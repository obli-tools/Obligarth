# ---- Build stage ----
FROM node:24-alpine AS builder
WORKDIR /app

# Dependencies come from package-lock.json only (npm ci): exact versions and
# integrity hashes, and @obligarth/shared is the link to the local workspace
# recorded in the lock, never a package fetched from the public registry (the
# @obligarth npm scope is not reserved). npm ci checks the lock against the
# package.json of every workspace, hence the three of them.
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY server/package.json ./server/
COPY client/package.json ./client/
RUN npm ci --workspace=client

# Shared sources: tsc and Vite read them directly (alias @obligarth/shared →
# ../shared/src), no build of the shared package needed.
COPY shared/ ./shared/
COPY client/ ./client/
RUN npm run build --workspace=client

# ---- Production stage ----
FROM nginx:alpine AS production

# curl is more reliable than busybox wget for healthchecks; openssl creates the
# self-signed certificate of the edge-proxy role
RUN apk add --no-cache curl openssl

COPY --from=builder /app/client/dist/ /usr/share/nginx/html/
# Main config (events/worker_connections — can't be set from conf.d) + the
# server block (upstream keepalive pool, proxy routes, SPA).
COPY client/nginx-main.conf /etc/nginx/nginx.conf
COPY client/nginx.conf /etc/nginx/conf.d/default.conf
# Role edge-proxy (OBLIGARTH_ROLE=edge-proxy, service edge-proxy of
# docker-compose.yml): TLS of the device surface, set up at start by the
# script below (run by the entrypoint of the nginx image; no-op for the console).
COPY client/edge-proxy/mdm.conf /etc/obligarth/edge-proxy/mdm.conf
COPY client/edge-proxy/40-obligarth-edge-proxy.sh /docker-entrypoint.d/40-obligarth-edge-proxy.sh
RUN chmod 755 /docker-entrypoint.d/40-obligarth-edge-proxy.sh

EXPOSE 80

# -s silent, -f fail on HTTP errors (4xx/5xx → exit 1), -o discard body
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD curl -sf http://localhost/ -o /dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
