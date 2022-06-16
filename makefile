SHELL := /bin/bash

# ==============================================================================
# Local support

run-throw:
	go run app/throwaway/main.go

run:
	go run app/tle/main.go


# ==============================================================================
# Modules support

tidy:
	go mod tidy
	go mod vendor

deps-upgrade:
	go get -u -v ./...
	go mod tidy
	go mod vendor