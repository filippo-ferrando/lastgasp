# Builds static lastgasp binaries into minimal images. The default target is the server, running as a non-root user.
# The agent image is the "agent" target. The build stage cross compiles, so multi-arch builds need no emulation.
# Base images are pinned by digest, so a changed upstream tag cannot change a release. Update both together.
ARG GO_VERSION=1.27

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X lastgasp/internal/version.Version=${VERSION}" -o /out/ ./cmd/lastgasp-server ./cmd/lastgasp-agent \
 && mkdir -p /out/data

# The agent runs as root: it reads /dev/kmsg and locks its memory. Kubernetes runs it from deploy/helm.
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS agent
COPY --from=build /out/lastgasp-agent /usr/local/sbin/lastgasp-agent
ENTRYPOINT ["/usr/local/sbin/lastgasp-agent"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS server
COPY --from=build /out/lastgasp-server /usr/local/bin/lastgasp-server
# Default SQLite location, used when no postgres:// URL is given.
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/lastgasp
VOLUME /var/lib/lastgasp
EXPOSE 5140/udp 8080/tcp
USER nonroot:nonroot
# The image has no curl, so the server checks itself. It expects the web UI on port 8080.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/lastgasp-server", "health"]
ENTRYPOINT ["/usr/local/bin/lastgasp-server"]
# No key file by default: agents enroll with join tokens. Add -key-file to use one as well.
CMD ["-listen", ":5140", "-http", ":8080", "-db", "/var/lib/lastgasp/lastgasp.db"]
