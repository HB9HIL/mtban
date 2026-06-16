IMAGE := debian:bookworm

.PHONY: build package shell lint clean

GO ?= go
GOFLAGS ?= -trimpath

# Build binary into dist/
build:
	mkdir -p dist
	$(GO) build $(GOFLAGS) -o dist/mtban .

# Build .deb locally inside a Debian container (works on macOS via Docker/Colima)
package:
	mkdir -p dist
	docker run --rm -v "$$PWD/..:/work" -w "/work/$$(basename $$PWD)" $(IMAGE) bash -c '\
		apt-get update -qq && \
		apt-get install -y -qq build-essential debhelper devscripts golang-any && \
		dpkg-buildpackage -us -uc -b && \
		mv ../*.deb ../*.changes ../*.buildinfo dist/'

# Lint: gofmt check + tests
lint:
	@test -z "$$(gofmt -l .)" || (echo "Run gofmt on changed files" && gofmt -l . && false)
	$(GO) test ./...
	@echo "OK"

clean:
	rm -rf dist/
	rm -rf debian/.debhelper debian/files
	rm -rf debian/mtban debian/mtban.substvars
	rm -f debian/debhelper-build-stamp
