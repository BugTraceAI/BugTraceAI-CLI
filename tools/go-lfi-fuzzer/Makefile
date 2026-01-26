.PHONY: build test clean install

BINARY_NAME=go-lfi-fuzzer
BUILD_DIR=../../bin

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME) .

test:
	go test -v ./...

clean:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)*

install: build
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
