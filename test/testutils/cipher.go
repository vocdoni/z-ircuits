package testutils

import (
	"math/big"

	"github.com/vocdoni/davinci-node/crypto/ecc"
	"github.com/vocdoni/davinci-node/crypto/ecc/bls12377te"
	"github.com/vocdoni/davinci-node/crypto/ecc/curves"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
)

// GenerateKeyPair returns a private/public key pair using the davinci-node ElGamal implementation.
func GenerateKeyPair() (*big.Int, ecc.Point) {
	curve := curves.New(bls12377te.CurveType)
	pub, priv, err := elgamal.GenerateKey(curve)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

// AffineCoords returns affine coordinates of the point (defensive copies).
func AffineCoords(p ecc.Point) (xOut, yOut *big.Int) {
	if p == nil {
		return new(big.Int), new(big.Int)
	}
	x, y := p.Point()
	if x == nil {
		x = new(big.Int)
	}
	if y == nil {
		y = new(big.Int)
	}
	return new(big.Int).Set(x), new(big.Int).Set(y)
}

// Encrypt encrypts message with the provided public key and randomness k.
// It returns the two ciphertext points in affine coordinates.
func Encrypt(message *big.Int, pubKey ecc.Point, k *big.Int) ([2]big.Int, [2]big.Int) {
	var resC1, resC2 [2]big.Int

	c1, c2 := elgamal.EncryptWithK(pubKey, message, k)

	x1, y1 := c1.Point()
	if x1 != nil {
		resC1[0].Set(x1)
	}
	if y1 != nil {
		resC1[1].Set(y1)
	}
	x2, y2 := c2.Point()
	if x2 != nil {
		resC2[0].Set(x2)
	}
	if y2 != nil {
		resC2[1].Set(y2)
	}
	return resC1, resC2
}
