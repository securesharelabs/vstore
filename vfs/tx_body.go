package vfs

import (
	"bytes"
	"encoding/binary"

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
// key and prepends the signer public key and signature to the unsigned
// data bytes to form a signed data payload.
// Sign implements Signable
func (p TransactionBody) Sign(priv ed25519.PrivKey) ([]byte, error) {
	bin := make([]byte, 0)

	// Sign data using the private key
	pubKey := priv.PubKey()
	sig, err := priv.Sign(p)
	if err != nil {
		return []byte{}, err
	}

	// A signed payload consists of the signer public key,
	// the signature, a varint size and the unsigned data.
	buffer := bytes.NewBuffer(bin)
	buffer.Write(pubKey.Bytes())
	buffer.Write(sig)
	buffer.Write(p.Bytes())

	return buffer.Bytes(), nil
}

// Bytes returns a size-prefixed byte representation of unsigned data.
// Bytes implements Signable
func (p TransactionBody) Bytes() []byte {
	bin := make([]byte, 0)

	// Each data set is prefixed by its size as a varint
	varSize := make([]byte, 8)
	binary.PutVarint(varSize, int64(len(p)))

	// Prepare staged data prefixing it by size
	buffer := bytes.NewBuffer(bin)
	buffer.Write(varSize)
	buffer.Write([]byte(p))

	return buffer.Bytes()
}
