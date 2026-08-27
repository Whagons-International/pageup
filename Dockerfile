# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.5
FROM golang:${GO_VERSION}-alpine AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN mkdir -p /out/downloads \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-linux-amd64 ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-linux-arm64 ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-darwin-amd64 ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-darwin-arm64 ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-windows-amd64.exe ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/downloads/pageup-windows-arm64.exe ./cmd/pageup \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/pageup-server ./cmd/pageup-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 pageup \
    && adduser -S -D -H -u 10001 -G pageup pageup \
    && mkdir -p /app/downloads /data/pages \
    && chown -R pageup:pageup /app /data

COPY --from=build --chown=pageup:pageup /out/pageup-server /app/pageup-server
COPY --from=build --chown=pageup:pageup /out/downloads /app/downloads

USER pageup
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/app/pageup-server"]
