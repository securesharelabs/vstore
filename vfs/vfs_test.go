package vfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vfsp2p "vstore/api/vstore/v1"

	"github.com/cosmos/gogoproto/proto"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
)

const (
	testSimpleValue  = "simple"
	testComplexValue = `{"age": 35, "name": "securesharelabs"}`
)

func TestVStoreCommitAndQuery(t *testing.T) {
	ctx, cancel, ownerPrivs, vfsDir := ResetTestRoot(t, "test-vstore-commit_and_query", 1)
	defer func() {
		cancel()
		os.RemoveAll(vfsDir)
	}()

	vstore := NewInMemoryVStoreApplication(filepath.Join(vfsDir, "id"), []byte("testpassword"))

	data := []byte(testSimpleValue)
	stx, err := makeTransaction(t, ownerPrivs[0], data)
	require.NoError(t, err, "should create a signed transaction")

	// CheckTx, PrepareProposal, FinalizeBlock, Commit
	response := testVStoreCommitTx(ctx, t, vstore, stx.Bytes())

	// Query
	// data output: size || data || sig
	testVStoreQuery(ctx, t, vstore, testSimpleValue, stx, response.TxResults, vstore.state.Height)
}

func TestVStoreSigners(t *testing.T) {
	numSigners := uint32(10)
	ctx, cancel, ownerPrivs, vfsDir := ResetTestRoot(t, "test-vstore-signers", numSigners)
	defer func() {
		cancel()
		os.RemoveAll(vfsDir)
	}()

	vstore := NewInMemoryVStoreApplication(filepath.Join(vfsDir, "id"), []byte("testpassword"))

	data := []byte(testSimpleValue)
	for i := 0; i < int(numSigners); i++ {
		stx, err := makeTransaction(t, ownerPrivs[i], data)
		require.NoError(t, err, "should create a signed transaction")

		response := testVStoreCommitTx(ctx, t, vstore, stx.Bytes())
		testVStoreQuery(ctx, t, vstore, testSimpleValue, stx, response.TxResults, vstore.state.Height)
	}

	assert.NotEmpty(t, vstore.state.NumTransactions)
	assert.Equal(t, int64(numSigners), vstore.state.NumTransactions)
	assert.Len(t, vstore.state.SortedMerkleRoots(), int(numSigners))
}

func TestVStoreEmptyTxs(t *testing.T) {
	numSigners := uint32(4)
	ctx, cancel, ownerPrivs, vfsDir := ResetTestRoot(t, "test-vstore-empty_txs", numSigners)
	defer func() {
		cancel()
		os.RemoveAll(vfsDir)
	}()

	vstore := NewInMemoryVStoreApplication(filepath.Join(vfsDir, "id"), []byte("testpassword"))

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

		stx, err := makeTransaction(t, ownerPrivs[i], data)
		require.NoError(t, err, "should create a signed transaction")

		txs[i] = stx.Bytes()
	}

	// PrepareProposal
	reqPrepare := abci.RequestPrepareProposal{Txs: txs, MaxTxBytes: 10 * 1024}
	resPrepare, err := vstore.PrepareProposal(ctx, &reqPrepare)
	require.NoError(t, err)
	require.Equal(t, len(reqPrepare.Txs)-1, len(resPrepare.Txs), "Empty transaction not properly removed")
}

func TestVStoreInvalidSignature(t *testing.T) {
	ctx, cancel, ownerPrivs, vfsDir := ResetTestRoot(t, "test-vstore-invalid_signature", 1)
	defer func() {
		cancel()
		os.RemoveAll(vfsDir)
	}()

	vstore := NewInMemoryVStoreApplication(filepath.Join(vfsDir, "id"), []byte("testpassword"))

	data := []byte(testSimpleValue)
	stx, err := makeTransaction(t, ownerPrivs[0], data)
	require.NoError(t, err, "should create a signed transaction")

	// Invalidate signature
	stx.Signature = append(stx.Signature, []byte("1")...)

	// CheckTx
	checkTxResp, err := vstore.CheckTx(ctx, &abci.RequestCheckTx{Tx: stx.Bytes()})
	require.NoError(t, err)
	assert.Equal(t, CodeTypeInvalidSignatureError, checkTxResp.Code)
}

// --------------------------------------------------------------------------
// Exported helpers

func ResetTestRoot(t *testing.T, testName string, numSigners uint32) (
	context.Context,
	func(),
	[][]byte,
	string,
) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	// create a unique, concurrency-safe test directory under os.TempDir()
	rootDir, err := os.MkdirTemp("", testName)
	if err != nil {
		panic(err)
	}

	// also create a unique identity for this vfs node (for encrypting db)
	MustGenerateIdentity(filepath.Join(rootDir, "id"), []byte("testpassword"))

	// and generate numSigners random ed25519 private keys (for signing data)
	ownerPrivs := make([][]byte, numSigners)
	for i := 0; i < int(numSigners); i++ {
		ownerPrivs[i] = ed25519.GenPrivKey()
		require.Len(t, ownerPrivs[i], ed25519.PrivateKeySize)
	}

	return ctx, cancel, ownerPrivs, rootDir
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
	assert.Equal(t, CodeTypeOK, checkTxResp.Code)

	// PrepareProposal
	ppResp, err := app.PrepareProposal(ctx, &abci.RequestPrepareProposal{Txs: [][]byte{tx}})
	require.NoError(t, err)
	assert.Len(t, ppResp.Txs, 1)

	// FinalizeBlock, Commit
	responseFinalizeBlock, _ := makeBlockCommit(ctx, t, app, 1, ppResp.Txs)
	assert.NotEmpty(t, responseFinalizeBlock.AppHash)
	assert.NotEmpty(t, responseFinalizeBlock.TxResults)

	return responseFinalizeBlock
}

func testVStoreQuery(
	ctx context.Context,
	t *testing.T,
	app abci.Application,
	value string,
	signedTx *SignedTransaction,
	txResults []*abci.ExecTxResult,
	blockHeight int64,
) {
	t.Helper()

	// We don't go further if we don't have results
	require.Greater(t, len(txResults), 0)

	// Info
	info, err := app.Info(ctx, &abci.RequestInfo{})
	require.NoError(t, err)
	assert.NotZero(t, info.LastBlockHeight)
	assert.NotEmpty(t, info.Data)

	// Query
	txHash := txResults[0].Data
	resQuery, err := app.Query(ctx, &abci.RequestQuery{
		Path: "/hash",
		Data: txHash,
	})
	require.NoError(t, err)
	assert.Equal(t, CodeTypeOK, resQuery.Code)
	assert.Equal(t, txHash, resQuery.Key)
	assert.EqualValues(t, info.LastBlockHeight, resQuery.Height)
	assert.NotEmpty(t, resQuery.Value)

	tx := new(vfsp2p.Transaction)
	err = proto.Unmarshal(resQuery.Value, tx)

	assert.NoError(t, err, "should unmarshal transaction from query result")
	assert.Equal(t, txHash, tx.Hash, "transaction hash must be correct")
	assert.Equal(t, signedTx.Signature, tx.Signature, "transaction signature must be correct")
	assert.Equal(t, []byte(value), tx.Body, "transaction body must be correct")
	assert.Equal(t, len(value), int(tx.Len), "body length must be correct")

	// TODO: add tests for /height and /signer transaction indexes
}

func makeBlockCommit(
	ctx context.Context,
	t *testing.T,
	app abci.Application,
	heightInt int,
	txs [][]byte,
) (*abci.ResponseFinalizeBlock, *abci.ResponseCommit) {
	t.Helper()

	// FinalizeBlock
	respFinBlock, err := app.FinalizeBlock(ctx, &abci.RequestFinalizeBlock{
		Height: int64(heightInt),
		Txs:    txs,
	})
	require.NoError(t, err)
	require.Len(t, respFinBlock.TxResults, len(txs))

	// Commit
	respCommit, err := app.Commit(ctx, &abci.RequestCommit{})
	require.NoError(t, err)

	// response contains TxResults and AppHash
	return respFinBlock, respCommit
}
