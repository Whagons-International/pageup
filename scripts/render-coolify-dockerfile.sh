#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:-dev}

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
(
  cd "$root"
  tar \
    --exclude=.git \
    --exclude=.credentials \
    --exclude=.deploy \
    --exclude=bin \
    --exclude='*.out' \
    -czf - . | base64 -w 60000
) > "$archive"

printf '%s\n' \
  '# syntax=docker/dockerfile:1' \
  'FROM golang:1.26.5-alpine AS build' \
  'WORKDIR /src'
# Docker rejects Dockerfile lines over 64 KiB, so the source archive is
# appended in bounded lines rather than passed as one RUN argument.
sed "s|.*|RUN printf '%s' '&' >> /tmp/source.b64|" "$archive"
printf '%s\n' \
  'RUN base64 -d /tmp/source.b64 | tar -xzf - -C /src && rm /tmp/source.b64' \
  'RUN mkdir -p /out/downloads \' \
  " && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-linux-amd64 ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-linux-arm64 ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-darwin-amd64 ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-darwin-arm64 ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-windows-amd64.exe ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/downloads/pageup-windows-arm64.exe ./cmd/pageup \\" \
  " && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$version' -o /out/pageup-server ./cmd/pageup-server" \
  'FROM alpine:3.21' \
  'RUN apk add --no-cache ca-certificates \' \
  ' && addgroup -S -g 10001 pageup \' \
  ' && adduser -S -D -H -u 10001 -G pageup pageup \' \
  ' && mkdir -p /app/downloads /data/pages \' \
  ' && chown -R pageup:pageup /app /data' \
  'COPY --from=build --chown=pageup:pageup /out/pageup-server /app/pageup-server' \
  'COPY --from=build --chown=pageup:pageup /out/downloads /app/downloads' \
  'USER pageup' \
  'VOLUME ["/data"]' \
  'EXPOSE 8080' \
  'HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1' \
  'ENTRYPOINT ["/app/pageup-server"]'
