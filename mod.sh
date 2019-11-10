#!/bin/sh

rm -f go.mod go.sum
go generate
go mod init
go mod tidy
go get -u ./...
