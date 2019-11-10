#!/bin/sh

go fmt ./...
git add -A
git commit -am cleanup
git push
git push --tags
