package diffie_hellman_exchange

import "crypto"

// SymmetricEncrypter is a type that should be implemented by all "Symmetric"
// curves and algorithms. Since the Decryption process is dependent on type
// of encryption, SymmetricEncrypter should return a SymmetricDecrypter on demand.
type SymmetricEncrypter interface {
	// Encrypt just encrypts the content.
	Encrypt(content []byte, key []byte) ([]byte, error)

	// GetDecrypter returns a SymmetricDecrypter pertinent to the
	// Encryption algorithm used.
	GetDecrypter() *SymmetricDecrypter
}

// SymmetricDecrypter is a type that should be implemented by all "Symmetric"
// curves and algorithms.
type SymmetricDecrypter interface {
	// Decrypt just decrypts the encrypted chunk
	Decrypt(encryptedContent []byte, key []byte) ([]byte, error)
}

// DHExchanger is a wrapper of sorts that gives us all the functionality required for
// a diffie-hellman key agreement.
type DHExchanger interface {

	// NewRandomKeyPair generates a new key pair for use.
	NewRandomKeyPair() (crypto.PrivateKey, crypto.PublicKey, error)

	// MarshalPublic encodes the key to byte array suitable for transport.
	MarshalPublic(key crypto.PublicKey) ([]byte, error)

	// UnMarshalPublic just assembles back your Marshalled public key
	UnMarshalPublic([]byte) (crypto.PublicKey, error)

	// AgreeOnSecret agrees on a common secret between the transacting parties.
	AgreeOnSecret(selfPrivate crypto.PrivateKey, otherPublic crypto.PublicKey) ([]byte, error)

	// GetEncrypter returns the SymmetricEncrypter which could be used for encrypting and decrypting
	// custom application level messages.
	GetEncrypter() *SymmetricEncrypter

	// PublicKey is derived from the given private key.
	PublicKey(private crypto.PrivateKey) (crypto.PublicKey, error)

	// Check checks whether the given public key is on the elliptic curve.
	Check(peersPublic crypto.PublicKey) (err error)
}
