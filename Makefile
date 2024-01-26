# Detect the operating system
ifeq ($(OS),Windows_NT)
	detected_OS := Windows
else
	detected_OS := $(shell uname -s)
endif

# Define the binary name
BINARY_NAME=dnest

# Define Go build command
GOBUILD=go build

# All target - default when you run just `make`
all: test build

# Test target
test:
	go test -v ./...

# Build from Linux
build:
ifeq ($(detected_OS),Linux)
	@echo "Building from Linux for Linux and Windows"
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux-amd64 main.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc $(GOBUILD) -o $(BINARY_NAME)-windows-amd64.exe main.go

# Build from Windows
else
	@echo "Building from Windows for Linux and Windows"
	set CGO_ENABLED=1
	set GOOS=linux
	set GOARCH=amd64
	$(GOBUILD) -o $(BINARY_NAME)-linux-amd64 main.go
	set GOOS=windows
    # set GOARCH=amd64
	$(GOBUILD) -o $(BINARY_NAME)-windows-amd64.exe main.go
endif

clean:
	go clean
	rm -f $(BINARY_NAME)-linux-amd64
	rm -f $(BINARY_NAME)-windows-amd64.exe
