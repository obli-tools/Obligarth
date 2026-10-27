# ---- Node.js build stage (server + shared) ----
FROM node:24-alpine AS builder
WORKDIR /app

# playwright-chromium's postinstall would download a glibc Chromium that can't
# run on Alpine (musl) — skip it everywhere. At runtime we use the system
# Chromium (apk add chromium) via executablePath (see utils/chromium.ts).
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Dependencies come from package-lock.json only (npm ci): exact versions and
# integrity hashes, and @obligarth/* are links to the local workspaces
# recorded in the lock, never packages fetched from the public registry (the
# @obligarth npm scope is not reserved). npm ci checks the lock against the
# package.json of every workspace, hence the three of them.
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY server/package.json ./server/
COPY client/package.json ./client/
RUN npm ci --workspace=shared --workspace=server

COPY shared/ ./shared/
RUN npm run build --workspace=shared

COPY server/tsconfig.json server/knexfile.ts ./server/
COPY server/src/ ./server/src/
RUN npm run build --workspace=server

# ---- Production stage ----
FROM node:24-alpine AS production
WORKDIR /app

# chromium + font/lib deps: server-side PDF rendering (reports, device
# exports) via playwright-chromium pointed at this system binary. Playwright's
# own bundled Chromium is glibc-only and won't run on Alpine.
RUN apk add --no-cache \
    chromium nss freetype harfbuzz ca-certificates ttf-freefont

# Skip the bundled-browser download (see builder stage) and tell our launcher
# where the apk-installed Chromium lives.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    CHROMIUM_PATH=/usr/bin/chromium-browser

# Runtime dependencies of the server only, from the lock as well (see the
# builder stage). client/package.json is also read at runtime: the client
# version reported by GET /api/system.
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY server/package.json ./server/
COPY client/package.json ./client/
RUN npm ci --omit=dev --workspace=server && npm cache clean --force

COPY --from=builder /app/shared/dist/ ./shared/dist/
COPY --from=builder /app/server/dist/ ./server/dist/

# Obli mobile app (Android): drop zone read by GET /api/mobile/android/
# {version,download} (manifest.json, optional RELEASE_NOTES.md and
# obligarth.apk). No release is part of the repository, so the folder is empty
# in the image: version answers 503, download 404, and the web client says the
# app is not published yet. A release is provided by mounting it here.
RUN mkdir -p ./mobile/release

EXPOSE 3001

# Start period: the server migrates the database before it listens; a long
# migration (an index built on a large table) must not mark it unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10m \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

WORKDIR /app/server
# The persistent bind mount is at /custom (see docker-compose). Without this,
# config.customDir defaults to ./custom = /app/server/custom (inside the
# container's ephemeral layer), so the software repo, uploaded packages and
# other custom assets are silently LOST on every image upgrade / recreate.
# Point the app at the mounted volume so uploads actually persist.
ENV CUSTOM_DIR=/custom
# A deployment even when NODE_ENV is not passed: the server then refuses its
# development fallbacks (session secret, database URL) and weak secrets
# (config.ts). Only an explicit NODE_ENV=development relaxes that.
ENV NODE_ENV=production
CMD ["node", "dist/src/index.js"]
