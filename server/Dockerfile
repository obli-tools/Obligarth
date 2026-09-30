# ---- Node.js build stage (server + shared) ----
FROM node:24-alpine AS builder
WORKDIR /app

# playwright-chromium's postinstall would download a glibc Chromium that can't
# run on Alpine (musl) — skip it everywhere. At runtime we use the system
# Chromium (apk add chromium) via executablePath (see utils/chromium.ts).
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

COPY package.json ./
COPY shared/ ./shared/
RUN cd shared && npm install && npm run build

COPY server/package.json ./server/
RUN cd server && npm install

COPY server/tsconfig.json server/knexfile.ts ./server/
COPY server/src/ ./server/src/
RUN cd server && npm run build

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

COPY --from=builder /app/shared/package.json ./shared/
COPY --from=builder /app/shared/dist/ ./shared/dist/

COPY --from=builder /app/server/package.json ./server/
COPY package.json ./
RUN cd server && npm install --omit=dev

COPY --from=builder /app/server/dist/ ./server/dist/

# Client package.json — version used by GET /api/system
COPY client/package.json ./client/

# Obli mobile app (Android) — served by GET /api/mobile/android/{version,download}
# (docs/obli-mobile.md §6). Drop zone written by the release script:
# manifest.json (committed placeholder: versionCode 0 → available:false),
# optional RELEASE_NOTES.md and obligarth.apk (gitignored; missing → 404).
# The Gradle project (mobile/android) is excluded by .dockerignore.
RUN mkdir -p ./mobile/release
COPY mobile/release/ ./mobile/release/

# Obli.tools VERSION file — obli.tools/ is a symlink to an external directory and cannot be
# followed by the Docker build context. The version is injected via --build-arg at build time;
# defaults to "0.0.0" so the build never fails when the arg is omitted.
ARG OBLITOOLS_VERSION=0.0.0
RUN mkdir -p ./obli.tools && printf '%s' "${OBLITOOLS_VERSION}" > ./obli.tools/VERSION

# Obli.tools release binaries (GET /downloads/:filename): obli.tools/ is not
# part of this repository, so none are copied here and /downloads answers 404.
RUN mkdir -p ./obli.tools/dist

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
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
