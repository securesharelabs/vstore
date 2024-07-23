package vfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
)

// SecretProvider describes a provider that returns an AES-256 secret which
// is used to encrypt a ed25519 private key.
type SecretProvider interface {
	// Bytes returns the raw bytes of a secret provider.
	Bytes() ([]byte, error)

	// Open returns the bytes of the private key (64-bytes).
	Open() ([]byte, error)

	// Secret returns the 32-bytes secret used for encryption (AES).
	Secret() ([]byte, error)

	// PrivKey returns a ed25519 private key instance.
	PrivKey() (ed25519.PrivKey, error)

	// PubKey returns a ed25519 public key from the private key.
	PubKey() (crypto.PubKey, error)
}

// identityFile is a private structure that describes a password-protected
// identity file. The identity file is expected to contain a base64-encoded
// AES-256 ciphertext prepended by an 8-bytes salt.
// The file must be accessible.
type identityFile struct {
	Path string
	pw   []byte
}

// Type assertion ensures identityFile can be opened to a ed25519 private key.
var _ SecretProvider = (*identityFile)(nil)

// NewIdentity creates a new identityFile instance
func NewIdentity(file string, pw []byte) *identityFile {
	if len(pw) == 0 {
		panic("password must not be empty")
	}

	if _, err := os.Stat(file); err != nil {
		panic(fmt.Sprintf("could not open id file: %v", err))
	}

	return &identityFile{
		Path: file,
		pw:   pw,
	}
}

// Bytes opens an identity file and expects it to contain a base64-encoded
// content which is decoded and returned. The file must be accessible.
// Bytes implements SecretProvider
func (id identityFile) Bytes() ([]byte, error) {
	// First assess access to identity file
	if _, err := os.Stat(id.Path); err != nil {
		return []byte{}, fmt.Errorf("could not open id file: %v", err)
	}

	// Read the base64-encoded file content
	ctbz, err := os.ReadFile(id.Path)
	if err != nil {
		return []byte{}, err
	}

	// Decode base64 encoded file content
	ctbz, err = base64.StdEncoding.DecodeString(string(ctbz))
	if err != nil {
		return []byte{}, err
	}

	return ctbz, nil
}

// Open reads an AES encrypted file (base64-encoded) and decrypts
// its content using a salted password hash. This function expects
// the random salt to be prepended to the ciphertext (8 bytes).
// Open implements SecretProvider
func (id identityFile) Open() ([]byte, error) {
	if len(id.pw) == 0 {
		return []byte{}, errors.New("password must not be empty")
	}

	// Read the AES ciphertext bytes from file
	// Note: the first 8-bytes contain the random salt
	ctbz, err := id.Bytes()
	if err != nil {
		return []byte{}, err
	}

	// Extract salt 8-bytes before ciphertext
	salt, ctbz := ctbz[:8], ctbz[8:]

	// Generate secret from password
	secret, _ := MustGenerateSecret(id.pw, salt)

	// Decrypt the ciphertext (private key bytes)
	pbz, err := Decrypt(secret, ctbz)
	if err != nil {
		return []byte{}, err
	}

	return pbz, nil
}

// Secret returns the 32-bytes secret generated as a SHA-256 hash using
// a salt (8 bytes) and a password. A salt is expected to be available as
// the first 8 bytes before the ciphertext returned with Bytes.
// Secret implement SecretProvider
func (id identityFile) Secret() ([]byte, error) {
	// Read content and base64-decode
	ctbz, err := id.Bytes()
	if err != nil {
		return []byte{}, err
	}

	// Salt consists of 8 bytes prepended to ciphertext
	salt := ctbz[:8]

	// Generate the AES-compatible 32-bytes secret from password and salt
	secret, _, err := GenerateSecret(id.pw, salt)
	if err != nil {
		return []byte{}, err
	}

	return secret, nil
}

// PrivKey opens an identity file and creates a private key instance. It is
// recommended to clear this private key instance after you have used it.
// This function always opens and decrypts the identity file to avoid saving
// the plaintext content - i.e. the private key - in memory (of the instance).
// PrivKey implements SecretProvider
func (id identityFile) PrivKey() (ed25519.PrivKey, error) {
	bz, err := id.Open()
	if err != nil {
		return ed25519.PrivKey{}, err
	}

	defer func() {
		bz = []byte{}
	}()

	return ed25519.PrivKey(bz[:]), nil
}

// PubKey implements SecretProvider
func (id identityFile) PubKey() (crypto.PubKey, error) {
	priv, err := id.PrivKey()
	if err != nil {
		return nil, err
	}

	return priv.PubKey(), nil
}

// --------------------------------------------------------------------------
// Helpers

// GenerateSecret generates a 32-bytes secret by creating a SHA-256
// hash of a salted password using a random salt of 8-bytes. If a non-empty
// salt is provided, it is expected to be of 8-bytes length.
// It returns the 32-bytes secret and an 8-bytes salt.
func GenerateSecret(pw, salt []byte) ([]byte, []byte, error) {
	if len(pw) == 0 {
		return []byte{}, []byte{}, errors.New("password must not be empty")
	}

	if len(salt) == 0 {
		// Generate random 8-bytes salt
		salt = make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return []byte{}, []byte{}, err
		}
	} else if len(salt) != 8 {
		return []byte{}, []byte{}, fmt.Errorf("invalid salt size, want: %d, got: %d", 8, len(salt))
	}

	// Secret is: SHA256(salt || password)
	var sbuf bytes.Buffer
	sbuf.Grow(8 + len(pw))
	sbuf.Write(salt) // 8-bytes salt
	sbuf.Write(pw)   // password
	secret := tmhash.Sum(sbuf.Bytes())

	return secret, salt, nil
}

// Encrypt encrypts a plaintext using the secret with the AES block cipher algo.
func Encrypt(secret []byte, data []byte) ([]byte, error) {
	// Prepare AES block cipher
	block, err := aes.NewCipher(secret)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	// Generate random salt
	salt := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return []byte{}, err
	}

	// Encrypt private key using AES and store base64
	ctbz := gcm.Seal(salt, salt, data, nil)
	return ctbz, nil
}

// Decrypt decrypts a ciphertext using the secret with the AES block cipher algo.
func Decrypt(secret []byte, ciphertext []byte) ([]byte, error) {
	// Prepare AES block cipher
	block, err := aes.NewCipher(secret)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	saltSize := gcm.NonceSize()
	salt, ct := ciphertext[:saltSize], ciphertext[saltSize:]

	bz, err := gcm.Open(nil, salt, ct, nil)
	if err != nil {
		return []byte{}, err
	}

	return bz, nil
}

// MustGenerateIdentity generates a new ed25519 private key and saves it to
// the provided idFile file. A password pw is used to encrypt the private key.
// 8 bytes are added in front of the ciphertext which consist of a random salt.
// The created identity file contains a base64-encoded AES ciphertext prefixed
// with a random salt of 8 bytes.
// This function will panic if any errors occur.
func MustGenerateIdentity(idFile string, pw []byte) (string, string) {
	if len(pw) == 0 {
		panic("password must not be empty")
	}

	idDir := filepath.Dir(idFile)
	if _, err := os.Stat(idDir); err != nil {
		os.MkdirAll(idDir, 0700)
	}

	// Generate ed25519 private key
	priv := ed25519.GenPrivKey()

	// Generate random salt and 32-bytes secret for AES
	secret, salt := MustGenerateSecret(pw, []byte{}) // random salt

	// Encrypt the private key using AES
	ctbz, err := Encrypt(secret, priv.Bytes())
	if err != nil {
		panic(err.Error())
	}

	// Salt is added in front of ciphertext (starting 8-bytes)
	// The salt must be in plaintext to decrypt with the password.
	ctbz = append(salt, ctbz...)

	// Write base64-encoded ciphertext to file
	b64 := base64.StdEncoding.EncodeToString(ctbz)
	err = os.WriteFile(idFile, []byte(b64), 0600)
	if err != nil {
		panic(err.Error())
	}

	// Also *always* create a (cleartext) co-located .pub file
	pubFile := idFile + ".pub"
	b64_pub := base64.StdEncoding.EncodeToString(priv.PubKey().Bytes())
	err = os.WriteFile(pubFile, []byte(b64_pub), 0644)
	if err != nil {
		panic(err.Error())
	}

	// Returns pair of co-located files
	return idFile, pubFile
}

// MustGenerateSecret generates a 32-bytes secret with salt or panics.
// This function will panic if any errors occur.
func MustGenerateSecret(pw, salt []byte) ([]byte, []byte) {
	// Secret is: SHA256(salt || password)
	secret, salt, err := GenerateSecret(pw, salt)
	if err != nil {
		panic(err.Error())
	}

	return secret, salt
}
