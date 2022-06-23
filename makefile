SHELL := /bin/bash

# ==============================================================================
# Local support

run-encrypt:
	go run app/tle/main.go -e -n "http://pl-us.testnet.drand.sh/" -c "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D 30s -o encryptedFile.txt makefile

run-decrypt:
	go run app/tle/main.go -n "http://pl-us.testnet.drand.sh/" -o decryptedFile.txt -d encryptedFile.txt

run-encrypt-a:
	go run app/tle/main.go -e -n "http://pl-us.testnet.drand.sh/" -a -c "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D 30s -o encryptedArmor.pem makefile

run-decrypt-a:
	go run app/tle/main.go -n "http://pl-us.testnet.drand.sh/" -a -o decryptedArmor.pem -d encryptedArmor.pem

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