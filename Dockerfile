# Multi-stage → scratch. Static binary (CGO disabled for modernc.org/sqlite).
# The web UI is prebuilt into internal/web/dist (committed), so no Node here.
FROM golang:1.26-alpine AS build
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/opencontrol ./cmd/opencontrol
# The data dir must exist and be owned by the runtime user so a fresh named
# volume inherits that ownership.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM scratch
COPY --from=alpine:3.22 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/opencontrol /opencontrol
COPY --from=build --chown=65532:65532 /out/data /data

# Runs unprivileged, so it listens on high ports inside the container; compose
# maps the public ports (53, 853, 443) onto them.
USER 65532:65532
ENV OC_LISTEN=":5353" \
    OC_API_LISTEN=":8080" \
    OC_SQLITE_PATH="/data/opencontrol.db" \
    OC_DATA_DIR="/data"
EXPOSE 5353/udp 5353/tcp 8080/tcp

VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/opencontrol", "healthcheck"]
ENTRYPOINT ["/opencontrol"]
CMD ["serve"]
