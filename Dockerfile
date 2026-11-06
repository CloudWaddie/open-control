# Multi-stage → scratch. Static binary (CGO disabled for modernc.org/sqlite).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/opencontrol ./cmd/opencontrol

FROM scratch
COPY --from=alpine:3.20 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/opencontrol /opencontrol

ENV OC_LISTEN=":53" \
    OC_SQLITE_PATH="/data/opencontrol.db" \
    OC_DATA_DIR="/data"

VOLUME /data
ENTRYPOINT ["/opencontrol"]
CMD ["serve"]
