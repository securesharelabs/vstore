package vfs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	vfsp2p "vstore/api/vstore/v1"

	cmtp2p "github.com/cometbft/cometbft/api/cometbft/crypto/v1"
	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
)

const (
	// timestamp uint64 (UTC always)
	timestampSize = 8
)

// SignedTransaction describes a signed data object that includes
// an owner public key, a SHA-256 hash, a size, a signature and a
// timestamp.
type SignedTransaction struct {
	Signer    ed25519.PubKey
	Hash      []byte
	Signature []byte
	Size      int
	Time      time.Time
	Data      TransactionBody
}

// NewSignedTransaction expects a signed data payload which contains
// an owner public key (32 bytes), a signature (64 bytes), a timestamp
// and at least 1 byte of arbitrary data.
// TODO: TBI verification of timestamp (too far in future, etc.)
// TODO: TBI when to verify signatures (careful with CheckTx)
func NewSignedTransactionFromBytes(tx []byte) (*SignedTransaction, error) {
	// Create the transaction from bytes
	stx, err := FromBytes(tx)
	if err != nil {
		return nil, err
	}

	// Compute SHA256 transaction hash
	stx.Hash = ComputeHash(stx)

	return stx, nil
}

// PublicKey returns the uppercase hexadecimal representation
// of the signer public key.
func (p SignedTransaction) PublicKey() string {
	return strings.ToUpper(hex.EncodeToString(p.Signer))
}

// Bytes returns a byte slice built from the size-prefixed
// data and the signature.
func (p SignedTransaction) Bytes() []byte {
	pb := p.ToProto()
	bz, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}

	return bz
}

// ToProto returns a protobuf transaction object.
func (p SignedTransaction) ToProto() *vfsp2p.Transaction {

	// Make public key transportable
	pk := cmtp2p.PublicKey{
		Sum: &cmtp2p.PublicKey_Ed25519{
			Ed25519: p.Signer.Bytes(),
		},
	}

	//XXX if hash is empty, must compute

	tx := new(vfsp2p.Transaction)
	tx.Signer = pk
	tx.Signature = p.Signature
	tx.Hash = p.Hash
	tx.Time = time.Unix(0, p.Time.Unix())
	tx.Len = uint32(len(p.Data))
	tx.Body = p.Data

	return tx
}

// --------------------------------------------------------------------------
// Helpers

// ComputeHash computes the SHA256 hash of a signed transaction
// The transaction hash consists of a SHA256 of the signer public key,
// followed by the data and the attached timestamp bytes.
func ComputeHash(p *SignedTransaction) []byte {
	psize := ed25519.PubKeySize

	// Timestamp bytes attached to hashed message
	tzb := make([]byte, 8)
	binary.BigEndian.PutUint64(tzb, uint64(p.Time.Unix()))

	// Tx hash is: sha256(owner || data || sigtime)
	var hbuf bytes.Buffer
	hbuf.Grow(psize + p.Size + timestampSize)
	hbuf.Write(p.Signer) // adding pubkey
	hbuf.Write(p.Data)   // adding data
	hbuf.Write(tzb)      // adding timestamp

	return tmhash.Sum(hbuf.Bytes())
}

// FromProto takes a transaction proto message and returns the SignedTransaction.
func FromProto(pb *vfsp2p.Transaction) (*SignedTransaction, error) {
	if pb == nil {
		return nil, errors.New("nil Transaction")
	}

	pkbz, err := pb.Signer.Marshal()
	if err != nil {
		return nil, err
	}

	tx := new(SignedTransaction)
	tx.Signer = ed25519.PubKey(pkbz)
	tx.Signature = pb.Signature
	tx.Size = int(pb.Len)
	tx.Time = pb.Time
	tx.Data = pb.Body

	if len(pb.Hash) != 0 {
		tx.Hash = pb.Hash
	}

	return tx, nil
}

// FromBytes takes a bytes slice and returns the SignedTransaction
func FromBytes(bz []byte) (*SignedTransaction, error) {
	tx := new(vfsp2p.Transaction)
	err := proto.Unmarshal(bz, tx)
	if err != nil {
		return nil, err
	}

	return FromProto(tx)
}
