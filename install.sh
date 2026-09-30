#!/bin/sh
set -e

REPO="https://raw.githubusercontent.com/MeeJay/Obligarth/main"
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

  # Generate random secrets, including the initial administrator's password
  SESSION_SECRET=$(random_string 48) || exit 1
  DB_PASSWORD=$(random_string 24) || exit 1
  ADMIN_PASSWORD=$(random_string 20) || exit 1

  # Generate .env with the secrets filled in, readable by this user only
  (umask 077 && sed \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$SESSION_SECRET|" \
    -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PASSWORD|" \
    -e "s|^DEFAULT_ADMIN_PASSWORD=.*|DEFAULT_ADMIN_PASSWORD=$ADMIN_PASSWORD|" \
    .env.example > .env)
  for key in SESSION_SECRET DB_PASSWORD DEFAULT_ADMIN_PASSWORD; do
    if ! grep -q "^$key=[A-Za-z0-9]" .env; then
      rm -f .env
      echo "✗ .env.example has no $key line: .env not created."
      exit 1
    fi
  done

  echo ""
  echo "  ✓ .env created with generated secrets (readable by you only)."
  echo "  → Review and adjust settings if needed: $(pwd)/.env"
  echo ""
else
  echo "  → .env already exists, skipping."
fi

# Persistent custom directory (reports, software repository, phone-key cache)
mkdir -p custom

echo "→ Starting Obligarth..."
echo ""
docker compose pull
docker compose up -d

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║        Obligarth is running!         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  → Open: http://localhost:3005"
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
echo "    docker compose -f $(pwd)/docker-compose.yml pull && docker compose up -d  # update"
echo ""
