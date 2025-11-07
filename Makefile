.PHONY: build clean install test version

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Binary output
BINARY_NAME := vmgrab
BIN_DIR := bin

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) .
	@echo "✅ Built: $(BIN_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	@echo "✅ Clean complete"

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BIN_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ Installed to /usr/local/bin/$(BINARY_NAME)"

test:
	@echo "Running tests..."
	go test ./... -v

version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Built:   $(BUILD_TIME)"

help:
	@echo "vmgrab build system"
	@echo ""
	@echo "Usage:"
	@echo "  make build    - Build binary with version info"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Install to /usr/local/bin"
	@echo "  make test     - Run tests"
	@echo "  make version  - Show version information"
