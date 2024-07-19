package vfs

import (
	"github.com/cometbft/cometbft/crypto/ed25519"
)

// Signable describes data that can be signed using a private key.
type Signable interface {
	Sign(ed25519.PrivKey) ([]byte, error)
	Bytes() []byte
}

// SignData signs a transaction using a private key.
func SignData(priv ed25519.PrivKey, tx Signable) []byte {
	sig, err := tx.Sign(priv)
	if err != nil {
		panic(err)
	}

	return sig
}

// TransactionBody represents *unsigned* data.
type TransactionBody []byte

var _ Signable = (*TransactionBody)(nil)

// Sign creates a digital signature of the bytes using the private
// key implementation for ed25519. Only ed25519 compatibility is added
// for now because of being able to batch verify ed25519 signatures.
// Sign implements Signable
func (p TransactionBody) Sign(priv ed25519.PrivKey) ([]byte, error) {
	// Sign data using the private key
	sig, err := priv.Sign(p)
	if err != nil {
		return []byte{}, err
	}

	return sig, nil
}

// Bytes returns a size-prefixed byte representation of unsigned data.
// Bytes implements Signable
func (p TransactionBody) Bytes() []byte {
	return []byte(p)
}
