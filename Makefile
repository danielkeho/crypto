BINARY_NAME=crypto

build:
	@echo "Building Cli..."
	@go build -o bin/${BINARY_NAME} ./cmd/cli
	@echo "CLI built!"
  