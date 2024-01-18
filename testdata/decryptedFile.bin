SHELL := /bin/bash

# ==============================================================================
# Local support

run-encrypt:
	go run app/tle/main.go -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D=30s -o=encryptedFile makefile

run-decrypt:
	go run app/tle/main.go -d -n="http://pl-us.testnet.drand.sh/" -o=decryptedFile encryptedFile

run-encrypt-a:
	go run app/tle/main.go -a -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D=30s -o=encryptedArmor.pem makefile

run-decrypt-a:
	go run app/tle/main.go -d -n="http://pl-us.testnet.drand.sh/" -o=decryptedArmor.pem encryptedArmor.pem


# ==============================================================================
# Modules support

tidy:
	go mod tidy
	go mod vendor

deps-upgrade:
	go get -u -v ./...
	go mod tidy
	go mod vendor