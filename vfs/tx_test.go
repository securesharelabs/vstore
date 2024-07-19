package vfs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vfsp2p "vstore/api/vstore/v1"

	cmtp2p "github.com/cometbft/cometbft/api/cometbft/crypto/v1"
	"github.com/cometbft/cometbft/crypto"

	"github.com/cometbft/cometbft/crypto/ed25519"
)

func TestVStoreTxFromProto(t *testing.T) {
	_, cancel, ownerPrivs := ResetTestRoot(t, 1)
	defer cancel()

	pubKey := ed25519.PrivKey(ownerPrivs[0]).PubKey()

	pb := new(vfsp2p.Transaction)
	pb.Signer = getWirePublicKey(pubKey)
	pb.Hash = []byte("test hash")
	pb.Signature = []byte("test signature")
	pb.Len = uint32(len(testSimpleValue))
	pb.Body = []byte(testSimpleValue)
	pb.Time = time.Now()

	stx, err := FromProto(pb)
	require.NoError(t, err, "should build signed transaction from protobuf")
	assert.Equal(t, []byte("test hash"), stx.Hash)
	assert.Equal(t, []byte("test signature"), stx.Signature)
	assert.Len(t, stx.Data, int(pb.Len))
	assert.Equal(t, pubKey.Bytes(), stx.Signer.Bytes())
}

func TestVStoreTxFromBytes(t *testing.T) {
	_, cancel, ownerPrivs := ResetTestRoot(t, 1)
	defer cancel()

	pubKey := ed25519.PrivKey(ownerPrivs[0]).PubKey()

	data := []byte(testSimpleValue)
	pb := new(vfsp2p.Transaction)
	pb.Signer = getWirePublicKey(pubKey)
	pb.Hash = []byte("test hash")
	pb.Signature = []byte("test signature")
	pb.Len = uint32(len(data))
	pb.Body = data
	pb.Time = time.Now()

	pbb, err := pb.Marshal()
	require.NoError(t, err, "should marshal protobuf class instance")

	tx, err := FromBytes(pbb)
	assert.NoError(t, err, "should create transaction from protobuf bytes")
	assert.Equal(t, data, tx.Data.Bytes())
	assert.Equal(t, len(data), tx.Size)
	assert.Equal(t, pb.Hash, tx.Hash)
	assert.Equal(t, pb.Signature, tx.Signature)
}

// --------------------------------------------------------------------------

func makeSignature(t *testing.T, privKey, data []byte) ([]byte, error) {
	t.Helper()

	priv := ed25519.PrivKey(privKey)
	sig, err := priv.Sign([]byte(testSimpleValue))
	if err != nil {
		return []byte{}, err
	}

	// No data means no signature
	if len(data) == 0 {
		return sig, nil
	}

	verifiable := priv.PubKey().VerifySignature(data, sig)
	require.Equal(t, true, verifiable)

	return sig, nil
}

func makeTransaction(t *testing.T, privKey, data []byte) (*SignedTransaction, error) {
	t.Helper()

	priv := ed25519.PrivKey(privKey)
	sig, err := makeSignature(t, privKey, data)
	require.NoError(t, err, "should sign data with ed25519 private key")
	require.Len(t, sig, ed25519.SignatureSize)

	tx := new(vfsp2p.Transaction)
	tx.Signer = getWirePublicKey(priv.PubKey())
	tx.Signature = sig
	tx.Time = time.Now()
	tx.Len = uint32(len(data))
	tx.Body = data

	stx, err := FromProto(tx)
	require.NoError(t, err, "should create transaction from protobuf schema")
	return stx, err
}

func getWirePublicKey(pubKey crypto.PubKey) cmtp2p.PublicKey {
	return cmtp2p.PublicKey{
		Sum: &cmtp2p.PublicKey_Ed25519{
			Ed25519: pubKey.Bytes(),
		},
	}
}
