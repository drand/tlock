package bls

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	bls12381 "github.com/kilic/bls12-381"
)

// Domain comes from the ciphersuite used by the RFC of this name compatible
// with the paired library > v18
var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

// KyberG2 is a kyber.Point holding a G2 point on BLS12-381 curve
type KyberG2 struct {
	p *bls12381.PointG2
}

func NullKyberG2() *KyberG2 {
	var p bls12381.PointG2
	return newKyberG2(&p)
}

func newKyberG2(p *bls12381.PointG2) *KyberG2 {
	return &KyberG2{p: p}
}

func (k *KyberG2) Equal(k2 kyber.Point) bool {
	return bls12381.NewG2().Equal(k.p, k2.(*KyberG2).p)
}

func (k *KyberG2) Null() kyber.Point {
	return newKyberG2(bls12381.NewG2().Zero())
}

func (k *KyberG2) Base() kyber.Point {
	return newKyberG2(bls12381.NewG2().One())
}

func (k *KyberG2) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *KyberG2) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*KyberG2).p)
	return k
}

func (k *KyberG2) Clone() kyber.Point {
	var p bls12381.PointG2
	p.Set(k.p)
	return newKyberG2(&p)
}

func (k *KyberG2) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bb := b.(*KyberG2)
	bls12381.NewG2().Add(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG2) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bb := b.(*KyberG2)
	bls12381.NewG2().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG2) Neg(a kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bls12381.NewG2().Neg(k.p, aa.p)
	return k
}

func (k *KyberG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullKyberG2().Base()
	}
	bls12381.NewG2().MulScalarBig(k.p, q.(*KyberG2).p, &s.(*mod.Int).V)
	return k
}

func (k *KyberG2) MarshalBinary() ([]byte, error) {
	return bls12381.NewG2().ToCompressed(k.p), nil
}

func (k *KyberG2) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG2().FromCompressed(buff)
	return err
}

func (k *KyberG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *KyberG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *KyberG2) MarshalSize() int {
	return 96
}

func (k *KyberG2) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *KyberG2) Hash(m []byte) kyber.Point {
	pg2, _ := bls12381.NewG2().HashToCurve(m, Domain)
	k.p = pg2
	return k
}

func sha256Hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func (k *KyberG2) IsInCorrectGroup() bool {
	return bls12381.NewG2().InCorrectSubgroup(k.p)
}
