# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.5

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY app/src/main/assets/linux-server/go.mod app/src/main/assets/linux-server/go.sum ./
RUN go mod download

COPY app/src/main/assets/linux-server/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath -ldflags="-s -w -checklinkname=0" -o /out/wdtt-server .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/wdtt-server /usr/local/bin/wdtt-server

VOLUME ["/etc/wdtt"]
EXPOSE 56000/udp 56001/udp

ENTRYPOINT ["/usr/local/bin/wdtt-server"]
