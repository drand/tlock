SHELL := /bin/bash

# ==============================================================================
# Local support

run-encrypt:
	go run app/tle/main.go -e -n "http://pl-us.testnet.drand.sh/" -c "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D 30s -o encryptedFile.txt makefile

run-decrypt:
	go run app/tle/main.go -n "http://pl-us.testnet.drand.sh/" -d encryptedFile.txt

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