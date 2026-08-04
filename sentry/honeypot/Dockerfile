# SENTRY honeypot.
#
# Receives attacker traffic, so it runs unprivileged, on a distroless base, with
# no route to any estate system. Compromising it yields nothing.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY honeypot/go.mod honeypot/go.sum ./
RUN go mod download
COPY honeypot/ ./
ARG VERSION=dev
ARG TARGETARCH
RUN GOOS=linux GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -ldflags "-X main.version=${VERSION} -s -w" -o /sentry-honeypot ./cmd/sentry-honeypot

FROM gcr.io/distroless/static:nonroot
COPY --from=build /sentry-honeypot /usr/local/bin/sentry-honeypot
USER 65532:65532
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/sentry-honeypot"]
