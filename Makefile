PROJECT="Packet Sniffer"

default: install
	@GO111MODULE=on go build -o bin/packet_sniffer cmd/packet_sniffer/main.go

install:
	@go mod download

test: install
	@go test -v ./...

.PHONY: default install test
