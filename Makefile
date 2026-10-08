GOFLAGS := -trimpath
# A tagged commit gets its tag as version, other builds show "dev" plus the commit.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo dev)
LDFLAGS := -s -w -X lastgasp/internal/version.Version=$(VERSION)
ARCHES := amd64 arm64 arm

.PHONY: all agent server test test-deploy test-examples test-chart image image-agent dist clean

all: agent server

# Static binary with no libc, so it never loads anything from disk after start.
agent:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/lastgasp-agent ./cmd/lastgasp-agent

server:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/lastgasp-server ./cmd/lastgasp-server

test: test-deploy test-examples test-chart
	go test -race ./...

test-deploy:
	sh deploy/install-agent_test.sh
	sh deploy/upgrade-notes_test.sh

test-examples:
	sh examples/examples_test.sh

test-chart:
	sh deploy/helm/chart_test.sh

image:
	docker build --build-arg VERSION=$(VERSION) --target server -t lastgasp-server:$(VERSION) -t lastgasp-server:latest .

image-agent:
	docker build --build-arg VERSION=$(VERSION) --target agent -t lastgasp-agent:$(VERSION) -t lastgasp-agent:latest .

# Release files: agent and server for each architecture, the installer of this version, units, checksums.
dist:
	@case "$(VERSION)" in v[0-9]*) ;; *) echo "dist needs VERSION=vX.Y.Z, got $(VERSION)"; exit 1 ;; esac
	rm -rf dist && mkdir -p dist
	for arch in $(ARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOARM=7 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' \
			-o dist/lastgasp-agent-linux-$$arch ./cmd/lastgasp-agent || exit 1; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOARM=7 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' \
			-o dist/lastgasp-server-linux-$$arch ./cmd/lastgasp-server || exit 1; \
	done
	sed 's/^VERSION=@VERSION@$$/VERSION=$(VERSION)/' deploy/install-agent.sh > dist/install-agent.sh
	grep -q '^VERSION=$(VERSION)$$' dist/install-agent.sh
	cp deploy/lastgasp-agent.service deploy/lastgasp-server.service dist/
	cd dist && sha256sum * > SHA256SUMS

clean:
	rm -rf bin dist
