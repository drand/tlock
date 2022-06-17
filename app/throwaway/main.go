package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// Unchained testnets
// var urls = []string{
// 	"https://testnet0-api.drand.cloudflare.com/",
// 	"http://pl-us.testnet.drand.sh/",
// }

var chainHash, _ = hex.DecodeString("7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf")

func encrypt(httpClient client.Client, duration time.Duration, message []byte, suite pairing.Suite, publicKey kyber.Point) error {
	// We need to get the future round number based on the duration.
	// The following call will do the required calculations based on the network `period` property,
	// and return a uint64 representing the round number in the future.
	// This round number is used to encrypt the data and will also be used by the dectypt function.
	round := httpClient.RoundAt(time.Now().Add(duration))

	// I am printing it to the termin so we can test the decryption call by updating the round number.
	fmt.Println("Future round to use for decryption: ", round)

	futureID := GetFutureRound(round)

	// This call to Encryption will return a Ciphertext containing the data to store in the file.
	encryptedData, err := ibe.Encrypt(suite, publicKey, futureID, message)
	if err != nil {
		return fmt.Errorf("ibe.Encrypt error: %s", err)
	}

	// The Ciphertext.U is a kyber point, and we have to call MarshalBinary to get a []byte.
	pointdata, err := encryptedData.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary error: %s", err)
	}

	f, err := os.OpenFile("encryptedData", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file error: %s", err)
	}
	defer f.Close()

	// Base64 each Ciphertext property
	P := base64.StdEncoding.EncodeToString(pointdata)
	V := base64.StdEncoding.EncodeToString(encryptedData.V)
	W := base64.StdEncoding.EncodeToString(encryptedData.W)

	// Formating those properties like JWT with a dot separator, and writing them to the file.
	f.WriteString(fmt.Sprintf("%s.%s.%s", P, V, W))

	return nil
}

func decrypt(httpClient client.Client, futureRound uint64, suite pairing.Suite, publicKey kyber.Point) error {
	fileData, err := os.ReadFile("encryptedData")
	if err != nil {
		return fmt.Errorf("open file error: %s", err)
	}

	fdata := strings.Split(string(fileData), ".")

	// Decode the base64 sections
	// Ignoring errors now for simplicity; they will be added later
	fP, _ := base64.StdEncoding.DecodeString(fdata[0])
	fV, _ := base64.StdEncoding.DecodeString(fdata[1])
	fW, _ := base64.StdEncoding.DecodeString(fdata[2])

	// We have to re-create the kyber point, using Group1 (Ciphertext.U property)
	g1 := bls.KyberG1{}
	if err := g1.UnmarshalBinary(fP); err != nil {
		return fmt.Errorf("UnmarshalBinary KyberG1 error: %s", err)
	}

	// Re-create the Ciphertext with the data from the file
	newCipherText := ibe.Ciphertext{
		U: &g1,
		V: fV,
		W: fW,
	}

	// Get the future round number data.
	// If it does not exist yet, it will return an EOF error (HTTP 404)
	roundData, err := httpClient.Get(context.Background(), futureRound)
	if err != nil {
		return fmt.Errorf("client get error: %s", err)
	}

	// If we can get the data from the future round above,
	// we need to create another kyber point but this time, using Group2.
	g2 := bls.KyberG2{}
	if err := g2.UnmarshalBinary(roundData.Signature()); err != nil {
		return fmt.Errorf("UnmarshalBinary error: %s", err)
	}

	decryptedData, err := ibe.Decrypt(suite, publicKey, &g2, &newCipherText)
	if err != nil {
		return fmt.Errorf("ibe.Decrypt error: %s", err)
	}

	fmt.Println("Message:", string(decryptedData))

	return nil
}

func main() {
	// Using Drand http client implementation
	httpClient, err := dhttp.New("http://pl-us.testnet.drand.sh/", chainHash, http.DefaultTransport)
	if err != nil {
		fmt.Println("client error:", err)
		return
	}

	// Get the network info:
	// Example:
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
	i, err := httpClient.Info(context.Background())
	if err != nil {
		fmt.Println("client info error:", err)
		return
	}

	// ===========================================

	suite := bls.NewBLS12381Suite()

	// We have to manually comment/uncomment the code to test both functions below.

	// ENCRYPT ===========================================

	// Inform the duration manually.
	if err := encrypt(httpClient, 30*time.Second, []byte(`Here is the data`), suite, i.PublicKey); err != nil {
		fmt.Println(err)
		return
	}

	// DECRYPT ===========================================

	// // Inform the number of the future round manually
	// // It was generated and printed to the stdout when running encrypt
	// if err := decrypt(httpClient, 1273234, suite, i.PublicKey); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
}

// GetFutureRoudn will generate a sha256 representing the future round number.
// This value is used to encrypt data.
// The future round signature is captured when the round number becomes available.
func GetFutureRound(round uint64) []byte {
	h := sha256.New()
	_, _ = h.Write(chain.RoundToBytes(round))
	return h.Sum(nil)
}
