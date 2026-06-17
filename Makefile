IMAGE := debian:bookworm

.PHONY: build package shell test clean

GO ?= go
GOFLAGS ?= -trimpath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")

# Build binary into dist/
build:
	mkdir -p dist
	$(GO) build $(GOFLAGS) -ldflags "-X main.version=$(VERSION)" -o dist/mtban .

# Build .deb locally inside a Debian container (works on macOS via Docker/Colima)
package:
	mkdir -p dist
	docker run --rm -v "$$PWD/..:/work" -w "/work/$$(basename $$PWD)" $(IMAGE) bash -c '\
		apt-get update -qq && \
		apt-get install -y -qq build-essential debhelper devscripts golang-any && \
		dpkg-buildpackage -us -uc -b && \
		mv ../*.deb ../*.changes ../*.buildinfo dist/'

# gofmt check + tests
test:
	@test -z "$$(gofmt -l .)" || (echo "Run gofmt on changed files" && gofmt -l . && false)
	$(GO) test ./...
	@echo "OK"

clean:
	rm -rf dist/
	rm -rf debian/.debhelper debian/files
	rm -rf debian/mtban debian/mtban.substvars
	rm -f debian/debhelper-build-stamp
