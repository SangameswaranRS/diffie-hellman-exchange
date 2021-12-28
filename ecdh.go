package diffie_hellman_exchange

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

// ECDH started & adopted from https://github.com/aead/ecdh/blob/master/ecdh.go

var (
	ErrInvalidPrivateKey           = errors.New("invalid private key")
	ErrInvalidPublicKey            = errors.New("invalid public key")
	ErrInvalidCurve                = errors.New("invalid elliptic curve")
	ErrPrivateKeyCurveIncompatible = errors.New("private key curve incompatible")
	ErrNotImplemented              = errors.New("not yet implemented")
)

// Point represents a generic elliptic curve Point with a
// X and a Y coordinate.
type Point struct {
	X, Y *big.Int
}

// NewEllipticCurveExchanger creates a new DHExchanger with
// generic elliptic.Curve implementations.
func NewEllipticCurveExchanger(c elliptic.Curve) (DHExchanger, error) {
	if c == nil {
		return nil, ErrInvalidCurve
	}
	return &EllipticCurve{curve: c}, nil
}

type EllipticCurve struct {
	curve elliptic.Curve
}

// NewRandomKeyPair generates a new key pair for use.
func (ec *EllipticCurve) NewRandomKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	private, x, y, err := elliptic.GenerateKey(ec.curve, rand.Reader)
	if err != nil {
		private = nil
		return nil, nil, err
	}
	public := Point{X: x, Y: y}
	return private, public, nil
}

// PublicKey is derived from the given private key.
func (ec *EllipticCurve) PublicKey(private crypto.PrivateKey) (crypto.PublicKey, error) {
	key, ok := checkPrivateKey(private)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	N := ec.curve.Params().N
	if new(big.Int).SetBytes(key).Cmp(N) >= 0 {
		return nil, ErrPrivateKeyCurveIncompatible
	}

	x, y := ec.curve.ScalarBaseMult(key)
	public := Point{X: x, Y: y}
	return public, nil
}

// Check checks whether the given public key is on the elliptic curve.
func (ec *EllipticCurve) Check(peersPublic crypto.PublicKey) (err error) {
	key, ok := checkPublicKey(peersPublic)
	if !ok {
		err = errors.New("unexpected type of peers public key")
	}
	if !ec.curve.IsOnCurve(key.X, key.Y) {
		err = errors.New("peer's public key is not on curve")
	}
	return
}

// AgreeOnSecret agrees on a common secret between the transacting parties.
func (ec *EllipticCurve) AgreeOnSecret(selfPrivate crypto.PrivateKey, otherPublic crypto.PublicKey) ([]byte, error) {
	priKey, ok := checkPrivateKey(selfPrivate)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}
	pubKey, ok := checkPublicKey(otherPublic)
	if !ok {
		return nil, ErrInvalidPublicKey
	}

	sX, _ := ec.curve.ScalarMult(pubKey.X, pubKey.Y, priKey)

	secret := sX.Bytes()
	return secret, nil
}

// MarshalPublic encodes the key to byte array suitable for transport.
func (ec *EllipticCurve) MarshalPublic(_ crypto.PublicKey) ([]byte, error) {
	return nil, ErrNotImplemented
}

// UnMarshalPublic just assembles back your Marshalled public key
func (ec *EllipticCurve) UnMarshalPublic([]byte) (crypto.PublicKey, error) {
	return nil, ErrNotImplemented
}

// GetEncrypter returns the SymmetricEncrypter which could be used for encrypting and decrypting
// custom application level messages.
func (ec *EllipticCurve) GetEncrypter() *SymmetricEncrypter {
	return nil
}

func checkPrivateKey(typeToCheck interface{}) (key []byte, ok bool) {
	switch t := typeToCheck.(type) {
	case []byte:
		key = t
		ok = true
	case *[]byte:
		key = *t
		ok = true
	}
	return
}

func checkPublicKey(typeToCheck interface{}) (key Point, ok bool) {
	switch t := typeToCheck.(type) {
	case Point:
		key = t
		ok = true
	case *Point:
		key = *t
		ok = true
	}
	return
}
