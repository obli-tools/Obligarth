#!/bin/sh
set -e

REPO="https://raw.githubusercontent.com/obli-tools/Obligarth/main"
INSTALL_DIR="${OBLIGARTH_DIR:-./obligarth}"
ADMIN_PASSWORD=""

# Random alphanumeric string of $1 characters. No weak fallback: without a
# usable random source, the installation stops.
random_string() {
  value=$(LC_ALL=C tr -dc 'A-Za-z0-9' 2>/dev/null < /dev/urandom | head -c "$1") || value=""
  if [ "${#value}" -ne "$1" ] && command -v openssl > /dev/null 2>&1; then
    value=$(openssl rand -base64 $(($1 * 2)) | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$1") || value=""
  fi
  if [ "${#value}" -ne "$1" ]; then
    echo "✗ Cannot generate random secrets (neither /dev/urandom nor openssl is usable)." >&2
    return 1
  fi
  printf '%s' "$value"
}

# 32 random bytes, base64url without padding (43 characters): the token of
# apple-edge's internal API. No weak fallback either.
random_token() {
  if command -v openssl > /dev/null 2>&1; then
    token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\r\n') || token=""
  else
    token=$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\r\n') || token=""
  fi
  if [ "${#token}" -ne 43 ]; then
    echo "✗ Cannot generate a random token (neither openssl nor /dev/urandom + base64 is usable)." >&2
    return 1
  fi
  printf '%s\n' "$token"
}

# Public URL of the device surface (MDM_PUBLIC_BASE): https, a host name,
# an optional port, no path. Final for every enrolled device.
valid_mdm_base() {
  printf '%s' "$1" | grep -Eq '^https://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$'
}

# 32 random bytes, base64: a key file of secrets/. No weak fallback either.
random_key() {
  if command -v openssl > /dev/null 2>&1; then
    key=$(openssl rand -base64 32) || key=""
  else
    key=$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr -d '\n') || key=""
  fi
  if [ "${#key}" -ne 44 ]; then
    echo "✗ Cannot generate a random key (neither openssl nor /dev/urandom + base64 is usable)." >&2
    return 1
  fi
  printf '%s\n' "$key"
}

# Version of the images to run, written in .env: OBLIGARTH_VERSION when given
# (a tag such as 1.0.0 pins it), latest otherwise.
resolve_version() {
  version="${OBLIGARTH_VERSION:-latest}"
  if ! printf '%s' "$version" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; then
    echo "✗ Invalid version: $version" >&2
    return 1
  fi
  printf '%s' "$version"
}

# Public URL of the Apple devices, from MDM_PUBLIC_BASE: required at the
# first installation, no default (it is written into every enrolled device).
resolve_mdm_base() {
  base="${MDM_PUBLIC_BASE:-}"
  base="${base%/}"
  if [ -z "$base" ]; then
    echo "✗ No public URL for the Apple devices: run the installer again with" >&2
    echo "  MDM_PUBLIC_BASE=https://mdm.<your domain> (a host name dedicated to the devices," >&2
    echo "  FINAL for every enrolled device: choose it once; see the documentation)." >&2
    return 1
  fi
  if ! valid_mdm_base "$base"; then
    echo "✗ Invalid MDM_PUBLIC_BASE: $base (expected https://<host>[:port], without path)." >&2
    return 1
  fi
  printf '%s' "$base"
}

echo ""
echo "  ╔═══════════════════════════════╗"
echo "  ║     Obligarth — Installer     ║"
echo "  ╚═══════════════════════════════╝"
echo ""

# Check docker
if ! command -v docker > /dev/null 2>&1; then
  echo "✗ Docker is not installed. Please install Docker first."
  echo "  https://docs.docker.com/get-docker/"
  exit 1
fi

if ! docker compose version > /dev/null 2>&1; then
  echo "✗ Docker Compose v2 is required. Please update Docker."
  exit 1
fi

if ! command -v curl > /dev/null 2>&1; then
  echo "✗ curl is required to download the configuration files."
  exit 1
fi

# Create install directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "→ Installing in: $(pwd)"
echo ""

# Download compose + env example
echo "→ Downloading docker-compose.yml..."
curl -fsSL "$REPO/docker-compose.yml" -o docker-compose.yml

if [ ! -f ".env" ]; then
  echo "→ Downloading .env.example..."
  curl -fsSL "$REPO/.env.example" -o .env.example

  # Version to run and public URL of the devices, then random secrets: the
  # database's two accounts (the server's, without superuser rights, and the
  # administrator used by server-migrate only) and the initial administrator's
  # password
  VERSION=$(resolve_version) || exit 1
  MDM_BASE=$(resolve_mdm_base) || exit 1
  SESSION_SECRET=$(random_string 48) || exit 1
  DB_PASSWORD=$(random_string 24) || exit 1
  DB_ADMIN_PASSWORD=$(random_string 32) || exit 1
  ADMIN_PASSWORD=$(random_string 20) || exit 1

  # Generate .env with the secrets filled in, readable by this user only
  (umask 077 && sed \
    -e "s|^OBLIGARTH_VERSION=.*|OBLIGARTH_VERSION=$VERSION|" \
    -e "s|^MDM_PUBLIC_BASE=.*|MDM_PUBLIC_BASE=$MDM_BASE|" \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$SESSION_SECRET|" \
    -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PASSWORD|" \
    -e "s|^DB_ADMIN_PASSWORD=.*|DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD|" \
    -e "s|^DEFAULT_ADMIN_PASSWORD=.*|DEFAULT_ADMIN_PASSWORD=$ADMIN_PASSWORD|" \
    .env.example > .env)
  for key in OBLIGARTH_VERSION MDM_PUBLIC_BASE SESSION_SECRET DB_PASSWORD DB_ADMIN_PASSWORD DEFAULT_ADMIN_PASSWORD; do
    if ! grep -q "^$key=[A-Za-z0-9]" .env; then
      rm -f .env
      echo "✗ .env.example has no $key line: .env not created."
      exit 1
    fi
  done

  echo ""
  echo "  ✓ .env created with generated secrets (readable by you only), version $VERSION."
  echo "  → Review and adjust settings if needed: $(pwd)/.env"
  echo ""
else
  echo "  → .env already exists, skipping."
  # Required since the row level security (lot A1): the database
  # administrator's password (it only acts on a new database volume).
  for key in DB_ADMIN_PASSWORD; do
    if ! grep -q "^$key=[A-Za-z0-9]" .env; then
      echo "✗ .env has no $key value: add it (see .env.example) and run the installer again."
      exit 1
    fi
  done
  # Required since apple-edge (lot B0): the public URL of the devices, taken
  # from MDM_PUBLIC_BASE when .env has none yet, never changed once set.
  if ! grep -q "^MDM_PUBLIC_BASE=[A-Za-z0-9]" .env; then
    MDM_BASE=$(resolve_mdm_base) || exit 1
    if grep -q "^MDM_PUBLIC_BASE=" .env; then
      (umask 077 && sed "s|^MDM_PUBLIC_BASE=.*|MDM_PUBLIC_BASE=$MDM_BASE|" .env > .env.tmp) && cat .env.tmp > .env && rm -f .env.tmp
    else
      printf '\nMDM_PUBLIC_BASE=%s\n' "$MDM_BASE" >> .env
    fi
    echo "  ✓ MDM_PUBLIC_BASE=$MDM_BASE added to .env."
  fi
  MDM_BASE=$(sed -n 's/^MDM_PUBLIC_BASE=//p' .env | tail -n 1)
  if ! valid_mdm_base "$MDM_BASE"; then
    echo "✗ Invalid MDM_PUBLIC_BASE in .env: $MDM_BASE (expected https://<host>[:port], without path)."
    exit 1
  fi
fi

# Key of the signed database context (Docker secret rls_context_key, R12):
# never in .env, never overwritten once created.
mkdir -p secrets
chmod 700 secrets
if [ ! -s secrets/rls_context_key ]; then
  (umask 077 && random_key > secrets/rls_context_key) || { rm -f secrets/rls_context_key; exit 1; }
  echo "  ✓ secrets/rls_context_key created (readable by you only)."
fi

# Key-encryption key of the vault (Docker secret server_kek): one per service,
# never in .env, never in a backup of the database, NEVER overwritten (a
# database restored with another key is refused at start, as it should be).
# Without it, no backup of the database can be restored: escrow it.
NEW_KEKS=""
if [ ! -s secrets/server_kek ]; then
  (umask 077 && random_key > secrets/server_kek) || { rm -f secrets/server_kek; exit 1; }
  echo "  ✓ secrets/server_kek created (readable by you only): the vault's key."
  NEW_KEKS="$NEW_KEKS server_kek"
fi

# apple-edge's secrets (Docker secrets, never in .env, NEVER overwritten): its
# own key-encryption key (one per service, escrowed with server_kek), the
# token of its internal API and the HMAC key of the DDM relay (both shared
# with the server), the password of its database role apple_edge_app.
random_password() {
  value=$(random_string 32) || return 1
  printf '%s\n' "$value"
}
new_secret() {
  if [ ! -s "secrets/$1" ]; then
    (umask 077 && "$2" > "secrets/$1") || { rm -f "secrets/$1"; exit 1; }
    echo "  ✓ secrets/$1 created."
  fi
}
if [ ! -s secrets/edge_kek ]; then NEW_KEKS="$NEW_KEKS edge_kek"; fi
new_secret edge_kek random_key
new_secret apple_edge_api_token random_token
new_secret apple_edge_ddm_hmac random_key
new_secret apple_edge_db_password random_password
if [ -n "$NEW_KEKS" ]; then
  echo "  ⚠ New vault keys:$NEW_KEKS (in $(pwd)/secrets). Escrow them now (see the"
  echo "    documentation): without them, no backup of the database can be restored."
fi

# apple-edge runs as uid 65532: the one-shot service secrets-init gives each
# service its own copy of its secrets (secrets/<service>), owned by its user.

# TLS of the device host (MDM_PUBLIC_BASE): the edge-proxy creates its own
# self-signed certificate (named volume mdm_tls) unless MDM_TLS_DIR names a
# directory with yours. Behind a reverse proxy holding the public certificate,
# nothing to do: forward https://<host of MDM_PUBLIC_BASE> to this host's
# MDM_LISTEN_PORT (3443), scheme https.
MDM_PORT=$(sed -n 's/^MDM_LISTEN_PORT=\([0-9][0-9]*\).*/\1/p' .env | tail -n 1)
[ -n "$MDM_PORT" ] || MDM_PORT=3443

# Persistent custom directory (reports, software repository, phone-key cache)
mkdir -p custom

echo "→ Starting Obligarth..."
echo ""
docker compose pull
if ! docker compose up -d; then
  echo ""
  echo "  ⚠ Some services did not start: docker compose ps, then docker compose logs <service>"
fi

# Port published by the client container: LISTEN_PORT of .env (default 3005)
PORT=$(sed -n 's/^LISTEN_PORT=\([0-9][0-9]*\).*/\1/p' .env | tail -n 1)
[ -n "$PORT" ] || PORT=3005

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║        Obligarth is running!         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  → Open: http://localhost:$PORT"
echo "  → Devices: $MDM_BASE, served by the edge-proxy on port $MDM_PORT (https):"
echo "    point your reverse proxy there (public certificate of $MDM_BASE)."
echo "    Health: $MDM_BASE/healthz"
if [ -n "$ADMIN_PASSWORD" ]; then
  echo "  → Sign in: admin / $ADMIN_PASSWORD"
  echo "    Shown only this once (also in .env, used only to create this first account)."
  echo "  → Change this password and enable two-factor authentication at first sign-in!"
else
  echo "  → Sign in with your administrator account. On a new database without"
  echo "    DEFAULT_ADMIN_PASSWORD in .env, its generated password is printed once by:"
  echo "    docker compose -f $(pwd)/docker-compose.yml logs server"
fi
echo ""
echo "  Useful commands:"
echo "    docker compose -f $(pwd)/docker-compose.yml logs -f"
echo "    docker compose -f $(pwd)/docker-compose.yml down"
echo "  Update: back up the database (and set OBLIGARTH_VERSION in .env if pinned), then"
echo "    docker compose -f $(pwd)/docker-compose.yml pull && docker compose -f $(pwd)/docker-compose.yml up -d"
echo "    (server-migrate, then apple-edge-migrate, migrate the database first; the server and"
echo "    apple-edge start once they have succeeded)"
echo ""
