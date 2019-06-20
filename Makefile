GOPATH := $(shell cd ../../../.. && pwd)
export GOPATH

init-dep:
	@dep init

dep:
	@dep ensure

status-dep:
	@dep status

update-dep:
	@dep ensure -update

run:
	@go run main.go

test:
	@cd ./session && go test -v -race
	@cd ./mid && go test -v -race
	@cd ./httpna && go test -v -race

build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stage/bin/httpna_service .

.PHONY: test
