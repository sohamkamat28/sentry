# SENTRY ingest.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY ingest/go.mod ingest/go.sum ./
RUN go mod download
COPY ingest/ ./
ARG VERSION=dev
ARG TARGETARCH
RUN GOOS=linux GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build -ldflags "-X main.version=${VERSION} -s -w" -o /sentry-ingest ./cmd/sentry-ingest

FROM gcr.io/distroless/static:nonroot
COPY --from=build /sentry-ingest /usr/local/bin/sentry-ingest
USER 65532:65532
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/sentry-ingest"]
