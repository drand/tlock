package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	dhttp "github.com/drand/drand/client/http"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/util/random"
)

// Unchained testnets
// var urls = []string{
// 	"https://testnet0-api.drand.cloudflare.com/",
// 	"http://pl-us.testnet.drand.sh/",
// }

var chainHash, _ = hex.DecodeString("7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf")

func main() {
	// We are not using the Drand library as suggested by Yolan.
	// It was not working with the unchained net.
	// Drand has its own HTTP implementation, which is helpful
	httpClient, err := dhttp.New("http://pl-us.testnet.drand.sh/", chainHash, http.DefaultTransport)
	if err != nil {
		fmt.Println("client error:", err)
		return
	}
	// fmt.Println("ROUND", http.RoundAt(time.Now()))

	// Here we get information from a round, in this case, round 0
	// We should probably work a timeout context instead of an empty one.
	r, err := httpClient.Get(context.Background(), 0)
	if err != nil {
		fmt.Println("client get error:", err)
		return
	}

	// Get the network info:
	// {
	// 	"public_key": "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
	// 	"period": 3,
	// 	"genesis_time": 1651677099,
	// 	"hash": "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
	// 	"groupHash": "65083634d852ae169e21b6ce5f0410be9ed4cc679b9970236f7875cff667e13d",
	// 	"schemeID": "pedersen-bls-unchained",
	// 	"metadata": {
	// 	  "beaconID": "testnet-unchained-3s"
	// 	}
	//   }
	if _, err := httpClient.Info(context.Background()); err != nil {
		fmt.Println("client info error:", err)
		return
	}
	fmt.Println(r.Round(), r.Randomness())

	// The folling is code to encrypt and decrypt using the kyber library and ibe package.
	// We also need kybe-bls12381@v0.2.2, which adds the BLS12381Suite function

	suite := bls.NewBLS12381Suite()

	// The following lines are mimiking drand right now
	// I still have to remove it and use real data from the network.
	P := suite.G1().Point().Base()
	s := suite.G1().Scalar().Pick(random.New())
	Ppub := suite.G1().Point().Mul(s, P)

	ID := []byte("random value from Drand")
	IDP := suite.G2().Point().(kyber.HashablePoint)
	Qid := IDP.Hash(ID)     // public key
	sQid := Qid.Mul(s, Qid) // secret key

	msg := []byte("Hello World\n")

	encryptedData, err := ibe.Encrypt(suite, Ppub, ID, msg)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("encryptedData", encryptedData)

	decryptedData, err := ibe.Decrypt(suite, Ppub, sQid, encryptedData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("---")
	fmt.Println("decryptedData", string(decryptedData))
}
