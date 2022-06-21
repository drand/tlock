SHELL := /bin/bash

# ==============================================================================
# Local support

run-throw:
	go run app/throwaway/main.go

run:
	go run app/tle/main.go

docker-build:
	docker build \
		-f zarf/docker/Dockerfile \
		-t local-drand \
		zarf/docker

docker-run:
	docker run --rm -p 5101:5101 local-drand

# ==============================================================================
# Modules support

tidy:
	go mod tidy
	go mod vendor

deps-upgrade:
	go get -u -v ./...
	go mod tidy
	go mod vendor