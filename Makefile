# Define the binary name
BINARY_NAME=dnest

# Define Go build command
GOBUILD=go build

# All target - default when you run just `make`
all: test build

# Test target
test:
	go test -v ./...

# Build for Linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux-amd64 main.go

# Build for Windows
build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-windows-amd64.exe main.go

# Build for both Linux and Windows
build: build-linux build-windows

# Clean up
clean:
	go clean
	rm $(BINARY_NAME)-linux-amd64
	rm $(BINARY_NAME)-windows-amd64.exe
