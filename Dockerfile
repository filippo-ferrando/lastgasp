# Builds a static lastgasp-server and runs it in a minimal image as a non-root user.
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/lastgasp-server ./cmd/lastgasp-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lastgasp-server /usr/local/bin/lastgasp-server
# Default SQLite location, used when no postgres:// URL is given.
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/lastgasp
VOLUME /var/lib/lastgasp
EXPOSE 5140/udp 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/lastgasp-server"]
CMD ["-listen", ":5140", "-http", ":8080", "-db", "/var/lib/lastgasp/lastgasp.db", "-key-file", "/etc/lastgasp/keys"]
