# Builds a static lastgasp-server and runs it in a minimal image as a non-root user.
# The build stage runs on the build machine and cross compiles, so multi-arch builds need no emulation.
ARG GO_VERSION=1.27

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X lastgasp/internal/version.Version=${VERSION}" -o /out/lastgasp-server ./cmd/lastgasp-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lastgasp-server /usr/local/bin/lastgasp-server
# Default SQLite location, used when no postgres:// URL is given.
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/lastgasp
VOLUME /var/lib/lastgasp
EXPOSE 5140/udp 8080/tcp
USER nonroot:nonroot
# The image has no curl, so the server checks itself. It expects the web UI on port 8080.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/lastgasp-server", "health"]
ENTRYPOINT ["/usr/local/bin/lastgasp-server"]
CMD ["-listen", ":5140", "-http", ":8080", "-db", "/var/lib/lastgasp/lastgasp.db", "-key-file", "/etc/lastgasp/keys"]
