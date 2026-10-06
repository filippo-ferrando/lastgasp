GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all agent server test test-deploy image clean

all: agent server

# Static binary with no libc, so it never loads anything from disk after start.
agent:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/lastgasp-agent ./cmd/lastgasp-agent

server:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/lastgasp-server ./cmd/lastgasp-server

test: test-deploy
	go test -race ./...

test-deploy:
	sh deploy/install-agent_test.sh

image:
	docker build -t lastgasp-server:latest .

clean:
	rm -rf bin
