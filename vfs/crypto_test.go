package vfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/tmhash"
)

func TestVStoreCryptoEncryptDecrypt(t *testing.T) {
	// ----------------------------------------------
	// Success cases
	secrets := [][]byte{
		[]byte("secretofthirtytwobytesforaes===="),
		tmhash.Sum([]byte("anothersecretforaes==")),
		[]byte("anothersecretofthirtytwobytes==="),
		tmhash.Sum([]byte("123")),
		tmhash.Sum([]byte("456")),
	}

	for _, secret := range secrets {
		plainData := []byte("Hello, World!")

		ciphertext, err := Encrypt(secret, plainData)
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext)

		plaintext, err := Decrypt(secret, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plainData, plaintext)
	}

	// ----------------------------------------------
	// Secret size failure cases
	failSecrets := [][]byte{
		[]byte("01"),
		[]byte("asecretthatistooshort"),
		[]byte("asecretthatistoolongandcantbeusedwithoutbeinghashed"),
	}

	for _, failSecret := range failSecrets {
		plainData := []byte("Hello, World!")

		ciphertext, err := Encrypt(failSecret, plainData)
		assert.NotNil(t, err)
		assert.Empty(t, ciphertext)
	}

	// ----------------------------------------------
	// Secret manipulation failures
	for _, secret := range secrets {
		plainData := []byte("Hello, World!")

		ciphertext, err := Encrypt(secret, plainData)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		failSecret := secret[1:] // lose first byte
		plaintext, err := Decrypt(failSecret, ciphertext)
		assert.NotNil(t, err)
		assert.Empty(t, plaintext)

		failSecret = secret[:] // manipulate
		failSecret[0] = 0

		plaintext, err = Decrypt(failSecret, ciphertext)
		assert.NotNil(t, err)
		assert.Empty(t, plaintext)
	}
}

func TestVStoreCryptoGenerateSecret(t *testing.T) {
	// ----------------------------------------------
	// Success cases
	pws := [][]byte{
		[]byte("1"),
		[]byte("test"),
		[]byte("testpassword"),
		[]byte("^{&,fqG6[]<Pe(i7,ADptqeZt{?^DB%="),
		[]byte("ZhmSBMGoQK9FktNf4SZXE5US6MHUadoe"),
	}

	for _, pw := range pws {
		// test with empty salt
		secret, salt, err := GenerateSecret(pw, []byte{}) // empty salt uses random salt
		assert.NoError(t, err)
		assert.Len(t, secret, 32)
		assert.Len(t, salt, 8)

		// test with filled salt
		secret2, salt2, err2 := GenerateSecret(pw, salt) // provided salt
		assert.NoError(t, err2)
		assert.Len(t, secret2, 32)
		assert.Len(t, salt2, 8)
		assert.Equal(t, secret, secret2)
		assert.Equal(t, salt, salt2)
	}

	// ----------------------------------------------
	// Error cases
	pw := []byte("") // empty password not allowed
	_, _, err := GenerateSecret(pw, []byte{})
	assert.Error(t, err, "expected error for empty password")

	pw = []byte("any")
	salt := []byte("1234567") // missing 1 byte
	_, _, err = GenerateSecret(pw, salt)
	assert.Error(t, err, "expected error for invalid salt length")
}

func TestVStoreCryptoMustGenerateIdentity(t *testing.T) {
	// create a unique, concurrency-safe test directory under os.TempDir()
	rootDir, _ := os.MkdirTemp("", "test-vstore-crypto-must_generate_identity")
	defer os.RemoveAll(rootDir)

	// create a unique identity for this vfs node (for encrypting db)
	pw := []byte("testpassword")
	priv, pub := MustGenerateIdentity(filepath.Join(rootDir, "id"), pw)
	assert.NotEmpty(t, priv)
	assert.NotEmpty(t, pub)

	// check that files were correctly created
	_, err1 := os.Stat(priv)
	_, err2 := os.Stat(pub)
	assert.NoError(t, err1, "should create a private key file")
	assert.NoError(t, err2, "should create a public key file")

	// check that identity can be opened/unlocked
	id := NewIdentity(priv, pw)
	pbz, err3 := id.Open()
	pk, err4 := id.PubKey()
	assert.NoError(t, err3, "should be able to decrypt identity file")
	assert.NoError(t, err4, "should be able to read public key")
	assert.Len(t, pbz, 64) // ed25519 private key
	assert.Len(t, pk, 32)  // ed25519 public key

	// ed25519 private key contains compressed pubkey bytes (32)
	assert.Contains(t, string(pbz), string(pk.Bytes()))
}
