package bls

import (
	"crypto/cipher"
	"encoding/hex"
	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	bls12381 "github.com/kilic/bls12-381"
)

type KyberGT struct {
	f *bls12381.E
}

func newEmptyGT() *KyberGT {
	return newKyberGT(bls12381.NewGT().New())
}
func newKyberGT(f *bls12381.E) *KyberGT {
	return &KyberGT{
		f: f,
	}
}

func (k *KyberGT) Equal(kk kyber.Point) bool {
	return k.f.Equal(kk.(*KyberGT).f)
}

const gtLength = 576

func (k *KyberGT) Null() kyber.Point {
	// One since we deal with Gt elements as a multiplicative group only
	// i.e. Add in kyber -> mul in kilic/, Neg in kyber -> inverse in kilic/ etc
	k.f = bls12381.NewGT().New()
	return k
}

func (k *KyberGT) Base() kyber.Point {
	panic("not yet available")
	/*var baseReader, _ = blake2b.NewXOF(0, []byte("Quand il y a à manger pour huit, il y en a bien pour dix."))*/
	//_, err := NewGT().rand(baseReader)
	//if err != nil {
	//panic(err)
	//}
	/*return k*/
}

func (k *KyberGT) Pick(rand cipher.Stream) kyber.Point {
	panic("TODO: bls12-381.GT.Pick()")
}

func (k *KyberGT) Set(q kyber.Point) kyber.Point {
	k.f.Set(q.(*KyberGT).f)
	return k
}

func (k *KyberGT) Clone() kyber.Point {
	kk := newEmptyGT()
	kk.Set(k)
	return kk
}

func (k *KyberGT) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberGT)
	bb := b.(*KyberGT)
	bls12381.NewGT().Mul(k.f, aa.f, bb.f)
	return k
}

func (k *KyberGT) Sub(a, b kyber.Point) kyber.Point {
	nb := newEmptyGT().Neg(b)
	return newEmptyGT().Add(a, nb)
}

func (k *KyberGT) Neg(q kyber.Point) kyber.Point {
	qq := q.(*KyberGT)
	bls12381.NewGT().Inverse(k.f, qq.f)
	return k
}

func (k *KyberGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	v := s.(*mod.Int).V
	qq := q.(*KyberGT)
	bls12381.NewGT().Exp(k.f, qq.f, &v)
	return k
}

func (k *KyberGT) MarshalBinary() ([]byte, error) {
	return bls12381.NewGT().ToBytes(k.f), nil
}

func (k *KyberGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *KyberGT) UnmarshalBinary(buf []byte) error {
	fe12, err := bls12381.NewGT().FromBytes(buf)
	k.f = fe12
	return err
}

func (k *KyberGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *KyberGT) MarshalSize() int {
	return 576
}

func (k *KyberGT) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.GT: " + hex.EncodeToString(b)
}

func (k *KyberGT) EmbedLen() int {
	panic("bls12-381.GT.EmbedLen(): unsupported operation")
}

func (k *KyberGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Embed(): unsupported operation")
}

func (k *KyberGT) Data() ([]byte, error) {
	panic("bls12-381.GT.Data(): unsupported operation")
}
