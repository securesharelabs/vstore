package vfs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	vfsp2p "vstore/api/vstore/v1"

	cmtp2p "github.com/cometbft/cometbft/api/cometbft/crypto/v1"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
)

// SignedTransaction describes a signed data object that includes
// an owner public key, a SHA-256 hash, a size, a signature and a
// timestamp.
type SignedTransaction struct {
	Signer ed25519.PubKey
	Hash   []byte
	Sig    []byte
	Size   uint64
	Time   time.Time
	Data   TransactionBody
}

// NewSignedTransaction expects a signed data payload which contains
// an owner public key (32 bytes), a signature (64 bytes), and at least
// 1 byte of arbitrary data.
// TODO: TBI verification of timestamp (too far in future, etc.)
// TODO: TBI when to verify signatures (careful with CheckTx)
func NewSignedTransactionFromBytes(tx []byte, tz time.Time) (*SignedTransaction, error) {
	psize, ssize := ed25519.PubKeySize, ed25519.SignatureSize

	// Validate minLength, expects public key and signature
	if len(tx) < psize+ssize+1 {
		return nil, errors.New("missing signature information in transaction")
	}

	// Timestamp bytes attached to hashed message
	tzb, err := tz.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error attaching timestamp to data: %w", err)
	}

	// Extract pubkey, signature and data from bytes
	pubkey, sig, data := tx[:psize], tx[psize:psize+ssize], tx[psize+ssize:]
	dsize := len(data)

	// Tx hash is: sha256(owner || data || sigtime)
	hparts := make([]byte, psize+dsize+len(tzb))
	copy(hparts, pubkey)            // adding pubkey
	copy(hparts[psize:], data)      // adding data
	copy(hparts[psize+dsize:], tzb) // adding timestamp

	return &SignedTransaction{
		Signer: pubkey,
		Hash:   tmhash.Sum(hparts),
		Size:   uint64(len(data)),
		Data:   data,
		Time:   tz,
		Sig:    sig,
	}, nil
}

// PublicKey returns the uppercase hexadecimal representation
// of the signer public key.
func (p SignedTransaction) PublicKey() string {
	return strings.ToUpper(hex.EncodeToString(p.Signer))
}

// Bytes returns a byte slice built from the transaction hash,
// the unsigned data bytes and the signature.
func (p SignedTransaction) Bytes() []byte {
	// Transaction hash used as an index in storage
	proto := p.Hash[:]

	// Get the size-prefixed unsigned bytes of data
	proto = append(proto, p.Data.Bytes()...)

	// Each data set is suffixed by its signature (64 bytes)
	payload := append(proto, p.Sig...)
	return payload
}

// ToProto returns a protobuf transaction object.
func (p SignedTransaction) ToProto() *vfsp2p.Transaction {
	// Parse owner public key
	pk := new(cmtp2p.PublicKey)
	err := pk.Unmarshal(p.Signer.Bytes())
	if err != nil {
		panic(err)
	}

	tx := new(vfsp2p.Transaction)
	tx.Signer = *pk
	tx.Signature = p.Sig
	tx.Hash = p.Hash
	tx.Time = p.Time
	tx.Body = p.Data

	return tx
}
