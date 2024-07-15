package vfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
)

const (
	testSimpleValue  = "simple"
	testComplexValue = `{"age": 35, "name": "securesharelabs"}`
)

func TestVStoreCommitAndQuery(t *testing.T) {
	ctx, cancel, ownerPrivs := ResetTestRoot(t, 1)
	defer cancel()

	vstore := NewInMemoryVStoreApplication()

	data := []byte(testSimpleValue)
	pub, sig, err := makeSignature(ownerPrivs[0], data)
	require.NoError(t, err, "should sign simple value with ed25519 private key")

	// signature information: pubkey || sig
	si := append(pub, sig...)

	// data input: siginfo || data
	tx := append(si, data...)

	// CheckTx, PrepareProposal, FinalizeBlock, Commit
	response := testVStoreCommitTx(ctx, t, vstore, tx)

	// Query
	// data output: size || data || sig
	testVStoreQuery(ctx, t, vstore, pub, testSimpleValue, sig, response.TxResults)
}

func TestVStoreSigners(t *testing.T) {
	numSigners := uint32(10)
	ctx, cancel, ownerPrivs := ResetTestRoot(t, numSigners)
	defer cancel()

	vstore := NewInMemoryVStoreApplication()

	data := []byte(testSimpleValue)
	for i := 0; i < int(numSigners); i++ {
		pub, sig, err := makeSignature(ownerPrivs[i], data)
		require.NoError(t, err, "should sign simple value with ed25519 private key")

		// signature information: pubkey || sig
		si := append(pub, sig...)

		// data input: siginfo || data
		tx := append(si, data...)

		response := testVStoreCommitTx(ctx, t, vstore, tx)
		testVStoreQuery(ctx, t, vstore, pub, testSimpleValue, sig, response.TxResults)
	}

	assert.NotEmpty(t, vstore.state.NumTransactions)
	assert.Equal(t, int64(numSigners), vstore.state.NumTransactions)
	assert.Len(t, vstore.state.MerkleRoots(), int(numSigners))
}

func TestVStoreEmptyTxs(t *testing.T) {
	numSigners := uint32(4)
	ctx, cancel, ownerPrivs := ResetTestRoot(t, numSigners)
	defer cancel()

	vstore := NewInMemoryVStoreApplication()

	// CheckTx
	tx := []byte("")
	reqCheck := abci.RequestCheckTx{Tx: tx}
	resCheck, err := vstore.CheckTx(ctx, &reqCheck)
	require.NoError(t, err, "should not produce a compilation error")
	assert.Equal(t, resCheck.Code, CodeTypeEmptyDataError)

	// Prepare a slice of signed transactions with one of these
	// being an empty transaction that must be dropped by PrepareProposal
	txs := make([][]byte, 4)
	for i := 0; i < int(numSigners); i++ {
		data := []byte(testSimpleValue)
		if i == 1 {
			data = []byte("") // second tx is empty
		}

		pub, sig, err := makeSignature(ownerPrivs[i], data)
		require.NoError(t, err, "should sign data with ed25519 private key")

		// signature information: pubkey || sig
		si := append(pub, sig...)

		// data input: siginfo || data
		tx := append(si, data...)
		txs[i] = tx
	}

	// PrepareProposal
	reqPrepare := abci.RequestPrepareProposal{Txs: txs, MaxTxBytes: 10 * 1024}
	resPrepare, err := vstore.PrepareProposal(ctx, &reqPrepare)
	require.NoError(t, err)
	require.Equal(t, len(reqPrepare.Txs)-1, len(resPrepare.Txs), "Empty transaction not properly removed")
}

func TestVStoreMissingSigInfo(t *testing.T) {
	_, cancel, ownerPrivs := ResetTestRoot(t, 1)
	defer cancel()

	data := []byte(testSimpleValue)
	pub, sig, err := makeSignature(ownerPrivs[0], data)
	require.NoError(t, err, "should sign simple value with ed25519 private key")

	// data input: siginfo || data
	tx_missingPub := append(sig, data...)
	tx_missingSig := append(pub, data...)
	tx_missingBoth := data[:]

	_, err = NewSignedTransactionFromBytes(tx_missingPub, time.Now())
	assert.NotNil(t, err, "error should be returned for missing signature info")

	_, err = NewSignedTransactionFromBytes(tx_missingSig, time.Now())
	assert.NotNil(t, err, "error should be returned for missing signature info")

	_, err = NewSignedTransactionFromBytes(tx_missingBoth, time.Now())
	assert.NotNil(t, err, "error should be returned for missing signature info")
}

// --------------------------------------------------------------------------
// Exported helpers

func ResetTestRoot(t *testing.T, numSigners uint32) (context.Context, func(), [][]byte) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	ownerPrivs := make([][]byte, numSigners)
	for i := 0; i < int(numSigners); i++ {
		ownerPrivs[i] = ed25519.GenPrivKey()
		require.Len(t, ownerPrivs[i], ed25519.PrivateKeySize)
	}

	return ctx, cancel, ownerPrivs
}

// --------------------------------------------------------------------------

func testVStoreCommitTx(
	ctx context.Context,
	t *testing.T,
	app abci.Application,
	tx []byte,
) *abci.ResponseFinalizeBlock {
	t.Helper()

	// CheckTx
	checkTxResp, err := app.CheckTx(ctx, &abci.RequestCheckTx{Tx: tx})
	require.NoError(t, err)
	assert.Equal(t, uint32(0), checkTxResp.Code)

	// PrepareProposal
	ppResp, err := app.PrepareProposal(ctx, &abci.RequestPrepareProposal{Txs: [][]byte{tx}})
	require.NoError(t, err)
	assert.Len(t, ppResp.Txs, 1)

	// FinalizeBlock, Commit
	responseFinalizeBlock := makeBlockCommit(ctx, t, app, 1, ppResp.Txs...)
	assert.NotEmpty(t, responseFinalizeBlock.AppHash)
	assert.NotEmpty(t, responseFinalizeBlock.TxResults)

	return responseFinalizeBlock
}

func testVStoreQuery(
	ctx context.Context,
	t *testing.T,
	app abci.Application,
	signerPub []byte,
	value string,
	sig []byte,
	txResults []*abci.ExecTxResult,
) {
	// Info
	info, err := app.Info(ctx, &abci.RequestInfo{})
	require.NoError(t, err)
	assert.NotZero(t, info.LastBlockHeight)
	assert.NotEmpty(t, info.Data)

	// Query
	txHash := txResults[0].Data
	resQuery, err := app.Query(ctx, &abci.RequestQuery{
		Path: "/store",
		Data: txHash,
	})
	require.NoError(t, err)
	assert.Equal(t, CodeTypeOK, resQuery.Code)
	assert.Equal(t, txHash, resQuery.Key)
	assert.EqualValues(t, info.LastBlockHeight, resQuery.Height)
	assert.Len(t, resQuery.Value, 8+len(value)+ed25519.SignatureSize)

	// extract varint size and signature
	actualValue := string(resQuery.Value[8 : 8+len(value)])
	actualSig := resQuery.Value[8+len(value):]
	assert.Equal(t, value, actualValue, "signed payload should contain value")
	assert.Equal(t, sig, actualSig, "signed payload should contain signature")

	// also check that the varint size is correct
	buf := bytes.NewBuffer(resQuery.Value[:8])
	varintSize, err := binary.ReadVarint(buf)
	require.NoError(t, err, "should be able to read size as varint")
	assert.Equal(t, int64(len(value)), varintSize)

	// TODO: Add test for RequestQuery.Prove option
}

func makeSignature(privKey, data []byte) ([]byte, []byte, error) {
	priv := ed25519.PrivKey(privKey)
	pub := priv.PubKey().Bytes()
	sig, err := priv.Sign([]byte(testSimpleValue))
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return pub, sig, nil
}

func makeBlockCommit(
	ctx context.Context,
	t *testing.T,
	app abci.Application,
	heightInt int,
	txs ...[]byte,
) *abci.ResponseFinalizeBlock {
	t.Helper()

	// FinalizeBlock
	respFinBlock, err := app.FinalizeBlock(ctx, &abci.RequestFinalizeBlock{
		Height: int64(heightInt),
		Txs:    txs,
	})
	require.NoError(t, err)
	require.Len(t, respFinBlock.TxResults, len(txs))

	// Commit
	_, err = app.Commit(ctx, &abci.RequestCommit{})
	require.NoError(t, err)

	// response contains TxResults and AppHash
	return respFinBlock
}
