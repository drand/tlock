package ibe

import (
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/sign"
)

type BatchIBEScheme interface {
	AggregateCiphers(private kyber.Point, ciphers []Ciphertext) (*AggregateCiphertext, error)
	DecryptAggregateCiphers(private kyber.Point, a *AggregateCiphertext) ([]Plaintext, error)
}

type bibeScheme struct {
	s      pairing.Suite
	master kyber.Point
}

func NewBatchIBESuite(s pairing.Suite, sig sign.Scheme, master kyber.Point) BatchIBEScheme {
	return nil
}

type AggregateCiphertext struct {
	// all initial ciphertexts
	cs []Ciphertext
	// individual pairings output
	pairs []kyber.Point
}

func AggregateCiphers(s pairing.Suite, master, private kyber.Point, ciphers []Ciphertext) (*AggregateCiphertext, error) {
	// Compute aggregate randomized sum
	pairs := make([]kyber.Point, len(ciphers))
	for i, c := range ciphers {
		// e(tau*r*P, private)
		Gid := s.Pair(c.U, private)
		pairs[i] = Gid
	}
	return &AggregateCiphertext{
		cs:    ciphers,
		pairs: pairs,
	}, nil
}

type Plaintext = []byte

// DecryptAggregateCiphers returns the list of all plaintext. If one decryption
// fails, it returns an error without the correct plaintexts.
func DecryptAggregateCiphers(s pairing.Suite, master, private kyber.Point, a *AggregateCiphertext) ([]Plaintext, error) {
	if len(a.pairs) != len(a.cs) {
		return nil, fmt.Errorf("invalid aggregated ciphertext: %d pairs vs %d ciphers", len(a.pairs), len(a.cs))
	}
	var plains = make([]Plaintext, len(a.cs))
	var err error
	for i := 0; i < len(a.cs); i++ {
		plains[i], err = subdecrypt(s, master, &a.cs[i], a.pairs[i])
		if err != nil {
			return nil, fmt.Errorf("Invalid cipher at position %d", i)
		}
	}
	return plains, nil
}

/// This whole code is to be thought as an experiment as a different way of
// aggregating and batch decrypt ciphertexts.. Given it is strictly less
// efficient than the currently algorith, it is commented out.
/*type AggregateCiphertext struct {*/
//// all initial ciphertexts
//cs []Ciphertext
//// individual pairings output
//pairs []kyber.Point
//// aggregated scaled sum of the pairings by randomn linear combination
//s       kyber.Point
//skipSum bool
//}

//func aggregateTag() []byte {
//return []byte("IBE-Aggregate")
//}

//func AggregateEncrypt(s pairing.Suite, master, private kyber.Point, ciphers []Ciphertext) (*AggregateCiphertext, error) {
//// Fiat Shamir
//tau, err := deriveTau(s, master, private, ciphers)
//if err != nil {
//return nil, err
//}
//// Compute aggregate randomized sum
//sum := s.GT().Point().Null()
//powers := s.GT().Scalar().One() // running powers of tau
//pairs := make([]kyber.Point, len(ciphers))
//for i, c := range ciphers {
//// e(tau*r*P, private)
//scaled := s.G1().Point().Mul(powers, c.U)
//scaledGid := s.Pair(scaled, private)
//Gid := s.Pair(c.U, private)
//pairs[i] = Gid
//sum = sum.Add(sum, scaledGid)
//powers = powers.Mul(powers, tau)
//}
//return &AggregateCiphertext{
//cs:    ciphers,
//pairs: pairs,
//s:     sum,
//}, nil
//}

//func DecryptAggregate(s pairing.Suite, master, private kyber.Point, c *AggregateCiphertext) ([][]byte, error) {
//if !c.skipSum {
//// Fiat Shamir
//tau, err := deriveTau(s, master, private, c.cs)
//if err != nil {
//return nil, err
//}
//// Compute aggregated sums of the resulting pairs
//sum := s.GT().Point().Null()
//powers := s.GT().Scalar().One()
//for _, gt := range c.pairs {
//scaled := s.GT().Point().Mul(powers, gt)
//sum = sum.Add(sum, scaled)
//powers = powers.Mul(powers, tau)
//}
//if !sum.Equal(c.s) {
//return nil, errors.New("Invalid RC proof")
//}
//}

//decrypted := make([][]byte, len(c.cs))
//for i, cipher := range c.cs {
//plain, err := subdecrypt(s, master, &cipher, c.pairs[i])
//if err != nil {
//return nil, fmt.Errorf("error at %d cipher: %v", i, err)
//}
//decrypted[i] = plain
//}
//return decrypted, nil
//}

//func deriveTau(s pairing.Suite, master, private kyber.Point, ciphers []Ciphertext) (kyber.Scalar, error) {
//xof, err := blake2s.NewXOF(uint16(s.G1().ScalarLen()), nil)
//if err != nil {
//return nil, err
//}
//if _, err := master.MarshalTo(xof); err != nil {
//return nil, err
//}
//if _, err := private.MarshalTo(xof); err != nil {
//return nil, err
//}
//for _, c := range ciphers {
//// TODO serialize method for ciphertext
//if _, err := c.U.MarshalTo(xof); err != nil {
//return nil, err
//}
//if _, err := xof.Write(c.V); err != nil {
//return nil, err
//}
//if _, err := xof.Write(c.W); err != nil {
//return nil, err
//}
//}
//return s.G1().Scalar().Pick(random.New(xof)), nil
/*}*/
