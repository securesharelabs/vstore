package vfs

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"

	cmtdb "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/version"
)

const (
	AppVersion        uint64 = 1
	QueryType_Default string = "hash"
	QueryType_Height  string = "height"
	QueryType_PubKey  string = "pubkey"
)

var _ abci.Application = (*VStoreApplication)(nil)

// VStoreApplication describes the vStore ABCI application.
type VStoreApplication struct {
	abci.BaseApplication

	state  State
	stage  []SignedTransaction
	logger cmtlog.Logger

	priv SecretProvider
}

// NewVStoreApplication creates a vfs application using a DB to load the State
// and an ed25519 identity to encrypt/decrypt database entities.
func NewVStoreApplication(
	db cmtdb.DB,
	id_file string,
	password []byte,
) *VStoreApplication {

	// Opens the identity file to read the public key.
	// This also makes sure that the provided identity is valid.
	provider := NewIdentity(id_file, password)
	pubkey, err := provider.Identity().PubKey()
	if err != nil {
		panic(err.Error())
	}

	log.Printf("using identity: %x", pubkey.Bytes())

	// TODO: verify integrity upon loadState

	return &VStoreApplication{
		logger: cmtlog.NewNopLogger(),
		state:  loadState(db),
		priv:   provider,
	}
}

// NewInMemoryApplication creates a new application from an in memory database.
// NOTE: the data will not be persisted.
func NewInMemoryVStoreApplication(
	id_file string,
	password []byte,
) *VStoreApplication {
	return NewVStoreApplication(cmtdb.NewMemDB(), id_file, password)
}

// validateTx validates that the bytes slice is not empty, and that the data
// contains at least the 32 bytes of the owner pubkey, 64 bytes of the signature
// and 1 byte of arbitrary data.
func (app *VStoreApplication) validateTx(tx []byte) uint32 {
	// Expects valid marshalled format for vfsp2p.Transaction
	stx, err := FromBytes(tx)
	if err != nil {
		return CodeTypeInvalidFormatError
	}

	if stx.Size == 0 || len(stx.Data) == 0 {
		return CodeTypeEmptyDataError
	}

	if !stx.Verify() {
		return CodeTypeInvalidSignatureError
	}

	return CodeTypeOK
}

// processFinalizeBlock processes a slice of transactions from the request,
// the creates signed data payloads and updates the Height and NumTransactions
// as specified in the request.
// An error code will be returned for invalid transactions.
func (app *VStoreApplication) processFinalizeBlock(
	_ context.Context,
	req *abci.RequestFinalizeBlock,
) []*abci.ExecTxResult {
	respTxs := make([]*abci.ExecTxResult, len(req.Txs))

	// Reset stages
	app.stage = make([]SignedTransaction, 0)

	// Stage the block data
	for i, tx := range req.Txs {
		// Extract pubkey (32b), signature (64b), timestamp (8b) and data
		payload, err := NewSignedTransactionFromBytes(tx)
		if err != nil {
			respTxs[i] = &abci.ExecTxResult{
				Code:   CodeTypeInvalidFormatError,
				Data:   payload.Hash,
				Events: []abci.Event{},
			}

			// This transaction won't be staged!
			continue
		}

		// Stage this transaction
		app.stage = append(app.stage, *payload)

		respTxs[i] = &abci.ExecTxResult{
			Code:   CodeTypeOK,
			Data:   payload.Hash,
			Events: []abci.Event{},
		}

		app.state.NumTransactions++
	}

	app.state.Height = req.Height
	return respTxs
}

// commitMerkleRoots computes merkle roots per owner public key
// and stores them in the merkleRoots property.
func (app *VStoreApplication) commitMerkleRoots() {
	if len(app.state.MerkleRoots) == 0 {
		app.state.MerkleRoots = make(map[string][]byte, 0)
	}

	for _, payload := range app.stage {
		pub := payload.PublicKey()
		txs := [][]byte{payload.Hash} // merkle root computed with transaction hash

		// Prepend merkle root if it exists
		if mr, ok := app.state.MerkleRoots[pub]; ok {
			txs = append([][]byte{mr}, txs...)
		}

		// Compute merkle root by owner public key
		merkleRoot := merkle.HashFromByteSlices(txs)
		app.state.MerkleRoots[pub] = merkleRoot
	}
}

// commitStateTransactions saves the State to database and
// resets the stage.
func (app *VStoreApplication) commitStateTransitions() {
	// TODO: verify integrity before saveState

	// Save State instance to database
	saveState(app.state)

	// Reset data stage
	app.stage = make([]SignedTransaction, 0)
}

// commitTransactionHashes indexes transaction hashes by
// block height and by signer public key.
func (app *VStoreApplication) commitTransactionHashes() {
	for _, payload := range app.stage {
		// Indexes transaction hashes by height
		app.addTransactionByHeight(payload)

		// Indexes transaction hashes by pubkey
		app.addTransactionByPubKey(payload)
	}
}

// addTransactionByHeight appends the transaction hash to
// the block height transaction index.
func (app *VStoreApplication) addTransactionByHeight(tx SignedTransaction) error {
	txes := [][]byte{}

	// Indexes hashes by height with prefix "vfs:height:block-X"
	heightStr := strconv.FormatInt(app.state.Height, 10) // base10
	dbKey_byHeight := prefixKeyWith([]byte(heightStr), vfsPrefixKeyByHeight)

	// Do we have hashes indexed by this height already?
	data, err := app.state.db.Get(dbKey_byHeight)
	if err != nil {
		return err
	}

	if len(data) > 0 {
		json.Unmarshal([]byte(data), &txes)
	}

	// Adds transaction hash by height
	txes = append(txes, tx.Hash)
	byHeight, _ := json.Marshal(txes)

	// Stores transaction hash to index
	err = app.state.db.Set(dbKey_byHeight, byHeight)
	return err
}

// addTransactionByPubKey appends the transaction hash to
// the signer pubkey transaction index.
func (app *VStoreApplication) addTransactionByPubKey(tx SignedTransaction) error {
	txes := [][]byte{}

	// Indexes hashes by pubkey with prefix "vfs:pubkey:X"
	dbKey_byPubKey := prefixKeyWith(tx.Signer.Bytes(), vfsPrefixKeyByPubKey)

	// Do we have hashes indexed by this pubkey already?
	data, err := app.state.db.Get(dbKey_byPubKey)
	if err != nil {
		return err
	}

	if len(data) > 0 {
		json.Unmarshal([]byte(data), &txes)
	}

	// Adds transaction hash by pubkey
	txes = append(txes, tx.Hash)
	byPubKey, _ := json.Marshal(txes)

	// Stores transaction hash to index
	err = app.state.db.Set(dbKey_byPubKey, byPubKey)
	return err
}

// readTransactionFromDB fetches a transaction from the database.
// Given a transaction hash, the transaction content will be decrypted,
// otherwise the index is read to retrieve the hash and a second query
// is executed to fetch the transaction content by hash.
func (app *VStoreApplication) readTransactionFromDB(
	queryType string,
	value []byte,
) ([]byte, error) {
	var (
		queryKey []byte = getQueryKey(queryType, value)
	)

	// Read from the database
	data, err := app.state.db.Get(queryKey)
	if len(data) == 0 || err != nil {
		return []byte{}, err
	}

	// TODO: Return array of transaction for height/pubkey indexes
	if queryType != QueryType_Default {
		return []byte{}, nil
	}

	// Unlock the decryption secret
	secret, err := app.priv.Identity().Secret()
	if err != nil {
		return []byte{}, nil
	}
	defer func() { secret = []byte{} }()

	// Decrypt the transaction data with the node's secret
	txData, err := Decrypt(secret, data)
	if err != nil {
		return []byte{}, nil
	}

	return txData, nil
}

// --------------------------------------------------------------------------
// VStoreApplication implements interface abcitypes.Application

// Info returns information about the State of the application. This is used
// everytime a CometBFT instance begins and forwards its version to the application.
// Based on this information, CometBFT will ensure synchronicity with the application
// by potentially replaying some blocks.
// If the application returns a 0 LastBlockHeight, CometBFT will call InitChain.
// Info implements abci.Application
func (app *VStoreApplication) Info(
	_ context.Context,
	info *abci.RequestInfo,
) (*abci.ResponseInfo, error) {
	// State contains num_transactions, height & merkle_roots
	appData, err := json.Marshal(app.state)
	if err != nil {
		panic(err)
	}

	return &abci.ResponseInfo{
		Data:             string(appData),
		Version:          version.ABCIVersion,
		AppVersion:       AppVersion,
		LastBlockHeight:  app.state.Height,
		LastBlockAppHash: app.state.Hash(),
	}, nil
}

// InitChain returns the application hash in case the application starts with
// values pre-populated. This method is called whenever a new instance of the
// application is started, i.e. when LastBlockHeight is 0.
// InitChain implements abci.Application
func (app *VStoreApplication) InitChain(
	_ context.Context,
	chain *abci.RequestInitChain,
) (*abci.ResponseInitChain, error) {
	// Creates an empty AppHash (32 bytes 0-filled)
	return &abci.ResponseInitChain{
		AppHash: app.state.Hash(),
	}, nil
}

// CheckTx handles inbound transactions or in the case of re-CheckTx assesses old
// transaction validity after a state transition happened.
// It is preferable to keep the checks as stateless and as quick as possible.
// For the vfs application, we check that each transaction has a valid tx format:
// - Must not be empty
// - Must contain at least the owner pubkey (32 bytes) and a signature (64 bytes)
// - Must contain at least 1 byte of arbitrary data
// CheckTx implements abci.Application
func (app *VStoreApplication) CheckTx(
	_ context.Context,
	check *abci.RequestCheckTx,
) (*abci.ResponseCheckTx, error) {
	code := app.validateTx(check.Tx)
	return &abci.ResponseCheckTx{Code: code}, nil
}

// PrepareProposal is called only when the node is a proposer. CometBFT stages
// a set of transactions for the application.
// NOTE: we assume that CometBFT won't provide too many transactions for 1 block.
// PrepareProposal implements abci.Application
func (app *VStoreApplication) PrepareProposal(
	ctx context.Context,
	proposal *abci.RequestPrepareProposal,
) (*abci.ResponsePrepareProposal, error) {
	// Validate transactions before creating proposal
	blockData := make([][]byte, 0, len(proposal.Txs))
	for _, tx := range proposal.Txs {
		resp, err := app.CheckTx(ctx, &abci.RequestCheckTx{Tx: tx})
		if resp.Code != CodeTypeOK || err != nil {
			continue
		}

		blockData = append(blockData, tx)
	}

	// Forwarded block data are all valid transactions
	return &abci.ResponsePrepareProposal{Txs: blockData}, nil
}

// ProcessProposal is called whenever a node receives a complete proposal and allows
// the application to validate the proposal.
// Only validators from the validator set will have this method called.
// ProcessProposal implements abci.Application
func (app *VStoreApplication) ProcessProposal(
	ctx context.Context,
	proposal *abci.RequestProcessProposal,
) (*abci.ResponseProcessProposal, error) {
	for _, tx := range proposal.Txs {
		// As CheckTx is a full validity check, we can reuse
		if resp, err := app.CheckTx(ctx, &abci.RequestCheckTx{Tx: tx}); err != nil || resp.Code != CodeTypeOK {
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
		}
	}
	return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
}

// FinalizeBlock executes the block against the application state. Transactions
// are processed one-by-one and are cached in memory. They will be persisted
// when Commit is called.
// ConsensusParams are never changed.
// FinalizeBlock implements abci.Application
func (app *VStoreApplication) FinalizeBlock(
	ctx context.Context,
	req *abci.RequestFinalizeBlock,
) (*abci.ResponseFinalizeBlock, error) {

	// Updates the Height and NumTransactions by processing transactions
	// and creates signed data payloads from bytes
	respTxs := app.processFinalizeBlock(ctx, req)

	// Update the merkle root including staged transaction hashes
	app.commitMerkleRoots()

	// Respond with transaction results and updated AppHash
	response := &abci.ResponseFinalizeBlock{
		TxResults: respTxs,
		AppHash:   app.state.Hash(),
	}

	return response, nil
}

// Commit is called after FinalizeBlock and after the CometBFT state updates.
// The vfs application persists the staged data (from FinalizeBlock) in database
// in a modified key-value store where the key is the tx hash, and where
// values describe marshalled protobuf instances of vfsp2p.Transaction.
// Commit implements abci.Application
func (app *VStoreApplication) Commit(
	_ context.Context,
	commit *abci.RequestCommit,
) (*abci.ResponseCommit, error) {
	// Read the encryption secret
	secret, err := app.priv.Identity().Secret()
	if err != nil {
		return nil, err
	}

	defer func() {
		secret = []byte{}
	}()

	// Persist all the staged data in vfs
	for _, payload := range app.stage {
		// Use transaction hash as the key (index by hash)
		dbKey := prefixKey(payload.Hash)

		// Transaction hash must not exist
		if resp, err := app.state.db.Has(dbKey); err != nil || resp {
			return nil, errors.New("transaction hash already exists")
		}

		// Encrypt the transaction using the node's secret
		encProto, err := Encrypt(secret, payload.Bytes())
		if err != nil {
			return nil, err
		}

		// Stores an encrypted vfsp2p.Transaction protobuf payload
		err = app.state.db.Set(dbKey, encProto)
		if err != nil {
			return nil, err
		}
	}

	// Indexes transaction hash by height and signer pubkey
	app.commitTransactionHashes()

	// Save the State in database with updated merkle roots
	app.commitStateTransitions()

	// Response OK
	return &abci.ResponseCommit{}, nil
}

// Query returns an associated value or nil if missing.
// Expects a transaction hash in the request's Data field.
// Query implements abci.Application
func (app *VStoreApplication) Query(
	_ context.Context,
	req *abci.RequestQuery,
) (*abci.ResponseQuery, error) {
	response := &abci.ResponseQuery{
		Key:    req.Data,
		Height: app.state.Height,
	}

	queryType := getQueryType(req.Path)
	plainData, err := app.readTransactionFromDB(queryType, req.Data)
	if err != nil {
		return response, err
	}

	response.Value = plainData
	response.Log = "exists"
	if req.Prove {
		response.Index = -1 // TODO make Proof return index
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Private helpers

// getQueryKey returns a prefixed database key depending of a queryType.
func getQueryKey(queryType string, value []byte) []byte {
	switch queryType {
	case QueryType_Height:
		return prefixKeyWith(value, vfsPrefixKeyByHeight)
	case QueryType_PubKey:
		return prefixKeyWith(value, vfsPrefixKeyByPubKey)
	default:
		break
	}

	return prefixKey(value)
}

// getQueryType returns the query type depending on a request path.
func getQueryType(path string) string {
	switch path {
	case "/height":
		return QueryType_Height
	case "/pubkey":
		return QueryType_PubKey
	default:
		break
	}

	return QueryType_Default
}
