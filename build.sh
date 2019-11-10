#!/bin/sh

export CGO_ENABLED=0
exec_name=$(basename "$(pwd)")
rm -f go.mod go.sum "$exec_name"
go generate
go mod init
go mod tidy
go get -u ./...
go build || exit 1
strip "$exec_name"
