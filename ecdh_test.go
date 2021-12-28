package diffie_hellman_exchange

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEllipticCurve(t *testing.T) {
	dhExchanger, err := NewEllipticCurveExchanger(elliptic.P224())
	require.NoError(t, err)
	require.NotNil(t, dhExchanger)

	// Basic Key Exchange Agreement.
	alicePrivate, alicePublic, err := dhExchanger.NewRandomKeyPair()
	require.NoError(t, err)
	require.NotNil(t, alicePrivate)
	require.NotNil(t, alicePublic)

	// The second exchanger if any, should be on the same curve
	bobPrivate, bobPublic, err := dhExchanger.NewRandomKeyPair()
	require.NoError(t, err)
	require.NotNil(t, bobPrivate)
	require.NotNil(t, bobPublic)

	aliceCompute, err := dhExchanger.AgreeOnSecret(alicePrivate, bobPublic)
	require.NoError(t, err)

	bobCompute, err := dhExchanger.AgreeOnSecret(bobPrivate, alicePublic)
	require.NoError(t, err)

	// Both of the keys should be same
	require.True(t, bytes.Equal(aliceCompute, bobCompute))

	fmt.Printf("Alice shared key=%x len=%d\n", base64.StdEncoding.EncodeToString(aliceCompute), len(aliceCompute))
	fmt.Printf("Bob shared key = %x len=%d\n", base64.StdEncoding.EncodeToString(bobCompute), len(bobCompute))
}

func TestEncryptionAndDecryption(t *testing.T) {
	dhExchanger, err := NewEllipticCurveExchanger(elliptic.P224())
	require.NoError(t, err)
	require.NotNil(t, dhExchanger)

	// Basic Key Exchange Agreement.
	alicePrivate, alicePublic, err := dhExchanger.NewRandomKeyPair()
	require.NoError(t, err)
	require.NotNil(t, alicePrivate)
	require.NotNil(t, alicePublic)

	// The second exchanger if any, should be on the same curve
	bobExchanger, err := NewEllipticCurveExchanger(elliptic.P224())
	require.NoError(t, err)
	require.NotNil(t, bobExchanger)
	bobPrivate, bobPublic, err := bobExchanger.NewRandomKeyPair()
	require.NoError(t, err)
	require.NotNil(t, bobPrivate)
	require.NotNil(t, bobPublic)

	aliceCompute, err := dhExchanger.AgreeOnSecret(alicePrivate, bobPublic)
	require.NoError(t, err)

	bobCompute, err := bobExchanger.AgreeOnSecret(bobPrivate, alicePublic)
	require.NoError(t, err)

	// Both of the keys should be same
	require.True(t, bytes.Equal(aliceCompute, bobCompute))
	fmt.Printf("Alice shared key=%x len=%d\n", base64.StdEncoding.EncodeToString(aliceCompute), len(aliceCompute))
	fmt.Printf("Bob shared key = %x len=%d\n", base64.StdEncoding.EncodeToString(bobCompute), len(bobCompute))

	// Encrypter - Alice
	aliceEncrypter := dhExchanger.GetEncrypter(aliceCompute)
	encrypted, err := aliceEncrypter.Encrypt([]byte("harvey reginald specter"))
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	// Decrypter - Bob
	bobEncrypter := bobExchanger.GetEncrypter(bobCompute)
	require.NotNil(t, bobEncrypter)
	decrypted, err := bobEncrypter.GetDecrypter().Decrypt(encrypted)
	require.NoError(t, err)
	require.NotNil(t, decrypted)

	fmt.Printf("Bob Decrypted: %s\n", string(decrypted))
	require.Equal(t, string(decrypted), "harvey reginald specter")
}
