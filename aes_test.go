package diffie_hellman_exchange

import (
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAESEncrypterAndDecrypter(t *testing.T) {
	key := make([]byte, 28)
	_, _ = rand.Read(key)
	encrypter := NewAESEncrypter(key)
	require.NotNil(t, encrypter)
	encrypted, err := encrypter.Encrypt([]byte("I have no idea what I'm doing now"))
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	fmt.Printf("Encrypted: %x Length: %d\n", encrypted, len(encrypted))

	// test decrypt.
	decrypted, err := encrypter.GetDecrypter().Decrypt(encrypted)
	require.NoError(t, err)
	require.NotNil(t, decrypted)

	fmt.Printf("%s\n", string(decrypted))
	require.Equal(t, "I have no idea what I'm doing now", string(decrypted))
}

func TestAESEncrypterAndDecrypterWithShortContents(t *testing.T) {
	key := make([]byte, 40)
	_, _ = rand.Read(key)
	encrypter := NewAESEncrypter(key)
	require.NotNil(t, encrypter)
	encrypted, err := encrypter.Encrypt([]byte("lol"))
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	fmt.Printf("Encrypted: %x Length: %d\n", encrypted, len(encrypted))

	// test decrypt.
	decrypted, err := encrypter.GetDecrypter().Decrypt(encrypted)
	require.NoError(t, err)
	require.NotNil(t, decrypted)

	fmt.Printf("%s\n", string(decrypted))
	require.Equal(t, "lol", string(decrypted))
}
