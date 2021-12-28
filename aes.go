package diffie_hellman_exchange

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AES Encrypter and Decrypter Implementation

var (
	ErrMalformedCipherText = errors.New("malformed cipher text") // Error when cipher text is malformed
)

// AESEncrypter is a type that does AES GCM Encryption.
type AESEncrypter struct {
	SecretKey []byte
	Decrypter SymmetricDecrypter
}

// AESDecrypter is a type that does AES GCM Decryption.
type AESDecrypter struct {
	SecretKey []byte
}

// NewAESDecrypter returns a new AESDecrypter
func NewAESDecrypter(secret []byte) *AESDecrypter {
	return &AESDecrypter{SecretKey: handleKeyPadding(secret)}
}

func (ad *AESDecrypter) Decrypt(cipherText []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(ad.SecretKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < gcm.NonceSize() {
		return nil, ErrMalformedCipherText
	}

	return gcm.Open(nil,
		cipherText[:gcm.NonceSize()],
		cipherText[gcm.NonceSize():],
		nil,
	)
}

// NewAESEncrypter returns a new AESEncrypter
func NewAESEncrypter(secret []byte) *AESEncrypter {
	return &AESEncrypter{
		SecretKey: handleKeyPadding(secret),
		Decrypter: NewAESDecrypter(secret),
	}
}

// Encrypt just encrypts the content.
func (ae *AESEncrypter) Encrypt(content []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(ae.SecretKey)
	if err != nil {
		return nil, err
	}

	// AES GCM does NOT require any padding, so PS: Laziness
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, content, nil), nil
}

// GetDecrypter returns a SymmetricDecrypter pertinent to the
// Encryption algorithm used.
func (ae *AESEncrypter) GetDecrypter() SymmetricDecrypter {
	return ae.Decrypter
}

// handleKeyPadding just pads the key for AES 256 length
// If key is Long, it truncates and considers the first 32 bytes.
func handleKeyPadding(key []byte) []byte {
	// AES 256
	if len(key) > 32 {
		return key[:32]
	}
	for len(key) < 32 {
		key = append(key, 0)
	}
	return key
}
