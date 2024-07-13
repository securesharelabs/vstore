package vfs

import (
	"encoding/json"
	"sort"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/crypto/merkle"
)

var (
	stateKey     = []byte("vfsState")
	vfsPrefixKey = []byte("vfs:")
)

// State describes the vstore application state which consists of a latest
// blockchain height, a total number of transactions and cryptographic
// commitments about transaction data (merkle roots).
type State struct {
	db cmtdb.DB

	// NumTransactions is essentially the total number of transactions processed.
	// This is used for the appHash in combination with the merkle roots
	NumTransactions int64 `json:"num_transactions"`
	Height          int64 `json:"height"`

	// MerkleRoots contains the cryptographic commitments for transactions that
	// have previously been processed.
	// This is used for the appHash.
	merkleRoots map[string][]byte `json:"merkle_roots"`
}

// MerkleRoots returns a slice of merkle roots that is *deterministic* due to
// keys always being sorted lexicographically.
func (s State) MerkleRoots() [][]byte {
	// Sort keys first (deterministic)
	max := len(s.merkleRoots)
	keys := make([]string, max)
	roots := make([][]byte, max)

	i := 0
	for k := range s.merkleRoots {
		keys[i] = k
		i++
	}

	// Sort keys lexicographically
	sort.Strings(keys)

	// Iterate over *keys* for determinism
	for j, k := range keys {
		v := s.merkleRoots[k]
		roots[j] = v
	}

	return roots
}

// Hash returns the hash of the application state. This is computed as the merkle
// root of all the committed transaction hashes using a deterministic merkle root
// slices as produced with MerkleRoots().
// The produced hash can be used to verify the integrity of the State.
// This function is used as the "AppHash"
func (s State) Hash() []byte {
	// Compute merkle root of all committed transactions
	return merkle.HashFromByteSlices(s.MerkleRoots())
}

// --------------------------------------------------------------------------

// prefixKey adds the "vfs:" database key prefix
func prefixKey(key []byte) []byte {
	return append(vfsPrefixKey, key...)
}

// loadState reads the state key from the database and tries to unmarshal
// a State instance or panics in case it doesn't work.
func loadState(db cmtdb.DB) State {
	var state State
	state.db = db
	stateBytes, err := db.Get(stateKey)
	if err != nil {
		panic(err)
	}
	if len(stateBytes) == 0 {
		return state
	}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		panic(err)
	}
	return state
}

// saveState saves the application state in the database using the state key.
func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	err = state.db.Set(stateKey, stateBytes)
	if err != nil {
		panic(err)
	}
}
