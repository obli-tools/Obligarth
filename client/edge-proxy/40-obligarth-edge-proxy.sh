#!/bin/sh
# Role edge-proxy of the console image (docker-compose.yml, service edge-proxy,
# OBLIGARTH_ROLE=edge-proxy): the TLS of the device surface (MDM_PUBLIC_BASE),
# with nothing to put in place by hand. Run by the entrypoint of the nginx
# image before nginx starts; does nothing for the console (no OBLIGARTH_ROLE).
#   1. The server block of the console is replaced by mdm.conf (built in).
#   2. Certificate of /etc/nginx/certs/mdm (a named volume, or MDM_TLS_DIR):
#      yours when fullchain.pem and privkey.pem are there (renewed by your ACME
#      client, never touched here); otherwise a self-signed one for the host of
#      MDM_PUBLIC_BASE, created once and kept, recreated when that host changes
#      or 30 days before it expires. Self-signed suits a reverse proxy in front
#      that holds the public certificate (Nginx Proxy Manager, Traefik...):
#      the devices only accept a certificate they trust (ATS).
#   3. Addresses of the devices: the X-Forwarded-For of a reverse proxy in
#      EDGE_TRUSTED_PROXIES (comma list of addresses or CIDR; default: private
#      and loopback ranges; empty: no proxy trusted) gives the device's address
#      instead of the proxy's (EDGE_FAIL_LIMIT_PER_IP, apple-edge).
set -eu

[ "${OBLIGARTH_ROLE:-}" = "edge-proxy" ] || exit 0

say() { echo "edge-proxy: $*"; }
fail() { echo "edge-proxy: $*" >&2; exit 1; }

base="${MDM_PUBLIC_BASE:-}"
host=$(printf '%s' "$base" | sed -n 's#^https://\([A-Za-z0-9][A-Za-z0-9.-]*\)\(:[0-9][0-9]*\)\{0,1\}/\{0,1\}$#\1#p')
[ -n "$host" ] || fail "MDM_PUBLIC_BASE must be https://<host>[:port], without path (got: '$base')."

# 1. Server block.
cp /etc/obligarth/edge-proxy/mdm.conf /etc/nginx/conf.d/default.conf

# 2. Certificate.
CERTS=/etc/nginx/certs/mdm
MARK="$CERTS/.self-signed-for"
mkdir -p "$CERTS"
if [ -f "$MARK" ] || { [ ! -e "$CERTS/fullchain.pem" ] && [ ! -e "$CERTS/privkey.pem" ]; }; then
  if [ "$(cat "$MARK" 2>/dev/null)" != "$host" ] || [ ! -s "$CERTS/fullchain.pem" ] || [ ! -s "$CERTS/privkey.pem" ] \
    || ! openssl x509 -checkend 2592000 -noout -in "$CERTS/fullchain.pem" >/dev/null 2>&1; then
    (
      umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
        -subj "/CN=$host" -addext "subjectAltName=DNS:$host" \
        -keyout "$CERTS/privkey.pem.new" -out "$CERTS/fullchain.pem.new" >/dev/null 2>&1
    ) || fail "could not create the self-signed certificate in $CERTS."
    mv -f "$CERTS/privkey.pem.new" "$CERTS/privkey.pem"
    mv -f "$CERTS/fullchain.pem.new" "$CERTS/fullchain.pem"
    printf '%s\n' "$host" > "$MARK"
    say "self-signed certificate created for $host."
  fi
  say "self-signed certificate for $host: the devices reach it through a reverse proxy holding the public certificate of $host (or put yours, fullchain.pem and privkey.pem, in MDM_TLS_DIR)."
else
  [ -s "$CERTS/fullchain.pem" ] && [ -s "$CERTS/privkey.pem" ] \
    || fail "$CERTS holds only one of fullchain.pem and privkey.pem: put both, or remove both to get a self-signed certificate."
  say "certificate of MDM_TLS_DIR in use."
fi

# 3. Trusted reverse proxies.
REALIP=/etc/nginx/mdm-realip.conf
trusted="${EDGE_TRUSTED_PROXIES-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,fc00::/7,::1/128}"
: > "$REALIP"
for c in $(printf '%s' "$trusted" | tr ',' ' '); do
  printf '%s' "$c" | grep -Eq '^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$' || fail "EDGE_TRUSTED_PROXIES: not an address or CIDR: '$c'."
  echo "set_real_ip_from $c;" >> "$REALIP"
done
if [ -s "$REALIP" ]; then
  printf 'real_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n' >> "$REALIP"
  say "X-Forwarded-For trusted from: $trusted."
fi
