#!/bin/sh
set -e

REPO="https://raw.githubusercontent.com/MeeJay/Obligarth/main"
RELEASES_API="https://api.github.com/repos/MeeJay/Obligarth/releases/latest"
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

# Version of the images to run, written in .env: never "latest" (an image
# newer than its database's migrations must not start by surprise). From
# OBLIGARTH_VERSION when given, else the latest published release.
resolve_version() {
  version="${OBLIGARTH_VERSION:-}"
  if [ -z "$version" ]; then
    version=$(curl -fsSL "$RELEASES_API" 2>/dev/null \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1) || version=""
  fi
  case "$version" in
    "" | latest)
      echo "✗ No version to install: run the installer again with OBLIGARTH_VERSION=<version>" >&2
      echo "  (a published image tag, e.g. OBLIGARTH_VERSION=1.0.0 sh install.sh; never latest)." >&2
      return 1 ;;
  esac
  if ! printf '%s' "$version" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; then
    echo "✗ Invalid version: $version" >&2
    return 1
  fi
  printf '%s' "$version"
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

  # Version to run, then random secrets: the database's two accounts (the
  # server's, without superuser rights, and the administrator used by
  # server-migrate only) and the initial administrator's password
  VERSION=$(resolve_version) || exit 1
  SESSION_SECRET=$(random_string 48) || exit 1
  DB_PASSWORD=$(random_string 24) || exit 1
  DB_ADMIN_PASSWORD=$(random_string 32) || exit 1
  ADMIN_PASSWORD=$(random_string 20) || exit 1

  # Generate .env with the secrets filled in, readable by this user only
  (umask 077 && sed \
    -e "s|^OBLIGARTH_VERSION=.*|OBLIGARTH_VERSION=$VERSION|" \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$SESSION_SECRET|" \
    -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PASSWORD|" \
    -e "s|^DB_ADMIN_PASSWORD=.*|DB_ADMIN_PASSWORD=$DB_ADMIN_PASSWORD|" \
    -e "s|^DEFAULT_ADMIN_PASSWORD=.*|DEFAULT_ADMIN_PASSWORD=$ADMIN_PASSWORD|" \
    .env.example > .env)
  for key in OBLIGARTH_VERSION SESSION_SECRET DB_PASSWORD DB_ADMIN_PASSWORD DEFAULT_ADMIN_PASSWORD; do
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
  # Required since the row level security (lot A1): a pinned version and the
  # database administrator's password (it only acts on a new database volume).
  for key in OBLIGARTH_VERSION DB_ADMIN_PASSWORD; do
    if ! grep -q "^$key=[A-Za-z0-9]" .env; then
      echo "✗ .env has no $key value: add it (see .env.example) and run the installer again."
      exit 1
    fi
  done
  if grep -q "^OBLIGARTH_VERSION=latest[[:space:]]*$" .env; then
    echo "✗ OBLIGARTH_VERSION=latest in .env: set the version to run (never latest)."
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

# Persistent custom directory (reports, software repository, phone-key cache)
mkdir -p custom

echo "→ Starting Obligarth..."
echo ""
docker compose pull
docker compose up -d

# Port published by the client container: LISTEN_PORT of .env (default 3005)
PORT=$(sed -n 's/^LISTEN_PORT=\([0-9][0-9]*\).*/\1/p' .env | tail -n 1)
[ -n "$PORT" ] || PORT=3005

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║        Obligarth is running!         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  → Open: http://localhost:$PORT"
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
echo "  Update: back up the database, set the new OBLIGARTH_VERSION in .env, then"
echo "    docker compose -f $(pwd)/docker-compose.yml pull && docker compose -f $(pwd)/docker-compose.yml up -d"
echo "    (server-migrate migrates the database first; the server starts once it has succeeded)"
echo ""
