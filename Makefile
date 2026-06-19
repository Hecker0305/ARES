# Build variables
BINARY_NAME=ares
GO_BUILD=CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"
GO_BUILD_LINUX=CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w"
GO_BUILD_LINUX_ARM=CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w"
GO_BUILD_DARWIN_AMD=CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w"
GO_BUILD_DARWIN_ARM=CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w"
GO_BUILD_WINDOWS=CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: all build build-linux build-linux-arm build-darwin-amd build-darwin-arm build-windows build-all clean test lint vet sec tidy run run-linux fmt frontend frontend-install frontend-build frontend-dev test-e2e sbom proto proto-gen license-check

all: vet build test

build:
	$(GO_BUILD) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/ares

build-linux:
	$(GO_BUILD_LINUX) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-linux-amd64 ./cmd/ares

build-linux-arm:
	$(GO_BUILD_LINUX_ARM) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-linux-arm64 ./cmd/ares

build-darwin-amd:
	$(GO_BUILD_DARWIN_AMD) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/ares

build-darwin-arm:
	$(GO_BUILD_DARWIN_ARM) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/ares

build-windows:
	$(GO_BUILD_WINDOWS) -ldflags="$(LDFLAGS)" -o $(BINARY_NAME).exe ./cmd/ares

build-all: build-linux build-linux-arm build-darwin-amd build-darwin-arm build-windows
	@echo "All binaries built successfully"

clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux*
	rm -f $(BINARY_NAME)-darwin*
	rm -f $(BINARY_NAME).exe
	rm -rf ./evidence ./output ./coverage.out ./state ./data/*.json

test:
	go test ./... -v -count=1

test-race:
	go test -race ./... -count=1

test-cover:
	go test ./... -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

vet:
	go vet ./...

sec:
	gosec -quiet -confidence medium ./...

tidy:
	go mod tidy

run:
	go run ./cmd/ares -- "$(ARGS)"

run-linux:
	./$(BINARY_NAME)-linux-amd64 -- "$(ARGS)"

fmt:
	go fmt ./...

frontend: frontend-install frontend-build

frontend-install:
	cd frontend && npm install

frontend-build:
	cd frontend && npm run build

frontend-dev:
	cd frontend && npm run dev

test-e2e:
	go test -tags=e2e ./internal/integration/... -v -count=1 -timeout 300s

sbom:
	syft . -o spdx-json > sbom.spdx.json

proto-gen:
	@which protoc >/dev/null 2>&1 || (echo "protoc not found. Install: https://grpc.io/docs/protoc-installation/" && exit 1)
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto
	@echo "Proto files generated successfully"

license-check:
	go-licenses check ./...

deb: frontend-build
	# Copy frontend dist to embed location
	mkdir -p internal/webserver/frontend/dist
	cp -r frontend/dist/* internal/webserver/frontend/dist/
	# Build .deb package
	cd packaging && bash build-deb.sh
