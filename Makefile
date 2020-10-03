GO111MODULE := on
export GO111MODULE

clean:
	@go mod tidy

update:
	@go get -u

run:
	@go run main.go

test:
	@go test -race

build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stage/bin/service .

.PHONY: test
