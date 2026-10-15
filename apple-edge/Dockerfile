# syntax=docker/dockerfile:1.7
# Build context: ./apple-edge. Pin the base images by digest at the first release.
ARG GO_VERSION=1.26.9

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -buildvcs=false"
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/apple-edge ./cmd/apple-edge \
 && go run ./tools/notices -o /out/THIRD_PARTY_NOTICES.txt ./cmd/apple-edge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/apple-edge /usr/local/bin/apple-edge
COPY --from=build /out/THIRD_PARTY_NOTICES.txt /usr/share/doc/apple-edge/THIRD_PARTY_NOTICES.txt
USER nonroot:nonroot
EXPOSE 9000 9100
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/apple-edge", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/apple-edge"]
CMD ["serve"]
