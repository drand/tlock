package tlock_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"testing"

	"github.com/drand/drand/chain"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/tlock"
)

var publicKeyPoint kyber.Point
var sigP2Point kyber.Point

const futureRound = uint64(5211482)

const publicKeyTxt = "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11"
const futureRoundSigTxt = "ae8889667f09c68c3a0c2368dbd95db5d43ef3522f585b7460ee43519a7d41bc9f80998f39b971207e6694ab69fb122c04b99b1c986eefc8ad9f06244c4b90ee7b2c040c61257140c423b5cec5c8c002d743baa24c4838a2adb8ca5c1de0a4f8"

func init() {
	buf, err := hex.DecodeString(publicKeyTxt)
	if err != nil {
		log.Fatalf("unable to decode")
	}
	publicKeyPoint = new(bls.KyberG1)
	err = publicKeyPoint.UnmarshalBinary(buf)
	if err != nil {
		log.Fatalf("unable to decode")
	}
	id, err := hex.DecodeString(futureRoundSigTxt)
	if err != nil {
		log.Fatalf("Unable to decode sig to bytes")
	}
	sigP2Point = new(bls.KyberG2)
	if err := sigP2Point.UnmarshalBinary(id); err != nil {
		log.Fatalf("unmarshal kyber G2: %v", err)
	}
}

func BenchmarkTLock(b *testing.B) {
	data := []byte("Hello world")
	for i := 0; i < b.N; i++ {
		_, err := tlock.TimeLock(publicKeyPoint, futureRound, data)
		if err != nil {
			log.Fatalf("timelock error %s", err)
		}
	}
}

func BenchmarkTUnlock(b *testing.B) {

	data := []byte("hello world")
	cipherText, err := tlock.TimeLock(publicKeyPoint, futureRound, data)
	if err != nil {
		b.Fatalf("timelock error %s", err)
	}
	id, err := hex.DecodeString(futureRoundSigTxt)
	if err != nil {
		b.Fatalf("Unable to decode sig to bytes")
	}
	beacon := chain.Beacon{
		Round:     futureRound,
		Signature: id,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt, err := tlock.TimeUnlock(publicKeyPoint, beacon, cipherText)
		if err != nil {
			b.Fatalf("timeunlock error %s", err)
		}

		if !bytes.Equal(data, pt) {
			b.Fatalf("unexpected bytes; expected len %d; got %d", len(data), len(pt))
		}
	}
}
func BenchmarkTUnlockRaw(b *testing.B) {

	data := []byte("hello world")
	cipherText, err := tlock.TimeLock(publicKeyPoint, futureRound, data)
	if err != nil {
		b.Fatalf("timelock error %s", err)
	}
	id, err := hex.DecodeString(futureRoundSigTxt)
	if err != nil {
		b.Fatalf("Unable to decode sig to bytes")
	}
	beacon := chain.Beacon{
		Round:     futureRound,
		Signature: id,
	}
	var pt []byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt, err = tlock.TimeUnlock(publicKeyPoint, beacon, cipherText)
		if err != nil {
			b.Fatalf("timeunlock error %s", err)
		}

	}
	if !bytes.Equal(data, pt) {
		b.Fatalf("unexpected bytes; expected len %d; got %d", len(data), len(pt))
	}
}

func BenchmarkPairing(b *testing.B) {
	suite := bls.NewBLS12381Suite()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.Pair(publicKeyPoint, sigP2Point)
	}
}
func BenchmarkPairingG1(b *testing.B) {
	suite := bls.NewBLS12381Suite()
	P1 := new(bls.KyberG1).Base()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.Pair(P1, sigP2Point)
	}
}
func BenchmarkPairingG2(b *testing.B) {
	suite := bls.NewBLS12381Suite()
	P2 := new(bls.KyberG2).Base()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.Pair(publicKeyPoint, P2)
	}
}

func BenchmarkIBEDecrypt(b *testing.B) {
	suite := bls.NewBLS12381Suite()

	data := []byte("hello world")
	ciphertext, err := tlock.TimeLock(publicKeyPoint, futureRound, data)
	if err != nil {
		b.Fatalf("timelock error %s", err)
	}
	var dat []byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dat, err = ibe.Decrypt(suite, sigP2Point, ciphertext)
		if err != nil {
			b.Fatalf("error: %v", err)
		}
	}
	if !bytes.Equal(data, dat) {
		b.Fatalf("error decrypt")
	}
}
func BenchmarkIBEEncrypt(b *testing.B) {
	suite := bls.NewBLS12381Suite()

	data := []byte("hello world")
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(futureRound)); err != nil {
		b.Fatalf("unable to hash")
	}
	id := h.Sum(nil)

	var ciphertext *ibe.Ciphertext
	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err = ibe.Encrypt(suite, publicKeyPoint, id, data)
		if err != nil {
			b.Fatalf("timelock error %s", err)
		}
	}
	b.StopTimer()
	//validate test
	dat, err := ibe.Decrypt(suite, sigP2Point, ciphertext)
	if err != nil {
		b.Fatalf("decrypt error %s", err)
	}
	if !bytes.Equal(data, dat) {
		b.Fatalf("error decrypt")
	}
}
