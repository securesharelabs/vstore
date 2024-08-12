package cmd

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	vfsp2p "github.com/securesharelabs/vstore/api/vstore/v1"
	vfs "github.com/securesharelabs/vstore/vfs"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/client/http"

	"github.com/cosmos/gogoproto/proto"
	"github.com/spf13/cobra"
)

// Used for flags
var transactionHash string
var printDataAsText bool

func init() {
	// e.g.: vstore query --hash "3816D803...9E03"
	queryCmd.PersistentFlags().StringVar(
		&transactionHash,
		"hash",
		"",
		"Build a query by transaction hash.",
	)

	// e.g.: vstore query --hash "3816D803...9E03" --json
	queryCmd.PersistentFlags().BoolVarP(
		&printAsJSON,
		"json",
		"j",
		false,
		"Display the information in a JSON format.",
	)

	// e.g.: vstore query --hash "3816D803...9E03" --plain
	queryCmd.PersistentFlags().BoolVarP(
		&printDataAsText,
		"plain",
		"p",
		false,
		"Display the transaction body in UTF-8 format.",
	)

	vstoreCmd.AddCommand(queryCmd)
}

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query your vStore instance for transactions",
	Long: `Query your vStore instance for transactions using:

	- the transaction hash as returned by the factory subcommand ; or
	- the block height in which the transaction was included ; or
	- the signer public key attached to the transaction.`,

	Example: `  vstore query
  vstore query --hash "XXX"`,

	Run: func(cmd *cobra.Command, args []string) {

		// Prepare the local RPC client
		// Note: A node must be running in the background
		// TODO: Permit overwrite of RPC remote address
		logger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
		cli, err := rpc.New("http://localhost:26657", "/websocket")
		if err != nil {
			log.Fatalf("could not connect to RPC server: %v", err)
		}
		cli.SetLogger(logger)

		// Ask for hash if not provided with --hash
		// TODO: Permit using height or pubkey indexes
		if len(transactionHash) == 0 {
			fmt.Printf("Enter the transaction hash: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalf("could not read transaction hash: %v", err)
			}

			transactionHash = strings.TrimSuffix(input, "\n")
		}

		// Parse transaction hash (for query key)
		hbz, err := hex.DecodeString(transactionHash)
		if err != nil {
			log.Fatalf("could not use provided transaction hash: %v", err)
		}

		// Execute query using RPC client
		response, err := cli.ABCIQuery(cmd.Context(), "/hash", hbz)

		if err != nil || response.Response.Code != vfs.CodeTypeOK {
			log.Fatalf("error occured on query: (%d - %s) with error: %v", response.Response.Code, response.Response.Log, err)
		}

		if len(response.Response.Value) == 0 {
			log.Fatalf("could not find transaction with hash: %x", hbz)
		}

		tx := new(vfsp2p.Transaction)
		err = proto.Unmarshal(response.Response.Value, tx)
		if err != nil {
			log.Fatalf("could not parse Transaction bytes: %v", err)
		}

		txBody := string(tx.Body)
		if !printDataAsText {
			txBody = fmt.Sprintf("%x", tx.Body)
		}

		txInfo := struct {
			Signer    string
			Signature string
			Size      int64
			Data      string
		}{
			fmt.Sprintf("%x", tx.Signer.GetEd25519()),
			fmt.Sprintf("%x", tx.Signature),
			int64(tx.Len),
			txBody,
		}

		if printAsJSON {
			json, _ := json.MarshalIndent(txInfo, "", "  ")
			fmt.Print(string(json) + "\n")
			return // Job done.
		}

		fmt.Printf("vStore v1.0 (vfs v%d) - ABCI: \n", vfs.AppVersion)
		fmt.Printf("  Signer PubKey: %s\n", txInfo.Signer)
		fmt.Printf("      Signature: %s\n", txInfo.Signature)
		fmt.Printf("           Size: %d\n", txInfo.Size)
		fmt.Printf("           Data: %s\n", txInfo.Data)
	},
}
