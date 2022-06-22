SHELL := /bin/bash

# ==============================================================================
# Local support

run-encrypt:
	go run app/tle/main.go -e -n "http://localhost:5101/" -c "a6fc05c10f76feaff566f3c581d8a5307aefe13e9f6ce1b9eb92c7524860ed00" -D 30s -o encryptedFile.txt toencrypt.txt

run-decrypt:
	go run app/tle/main.go -d encryptedFile.txt

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