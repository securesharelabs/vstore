package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	vfs "github.com/securesharelabs/vstore/vfs"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/client/http"

	"github.com/spf13/cobra"
)

// Used for flags
var printAsJSON bool

func init() {
	// e.g.: vstore info --json
	infoCmd.PersistentFlags().BoolVarP(
		&printAsJSON,
		"json",
		"j",
		false,
		"Display the information in a JSON format.",
	)

	vstoreCmd.AddCommand(infoCmd)
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print the current node's vStore information (State)",
	Long: `Print the current node's vStore information including:

  - The latest block height ; and
  - The total number of transactions stored ; and
  - The application merkle roots to create the state Hash.

  The information returned with this command is necessary to perform
  the verification of integrity on vStore state instances.
`,
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

		// Broadcast the transaction
		response, err := cli.ABCIInfo(cmd.Context())
		if err != nil {
			log.Fatalf("could not retrieve ABCI information: %v", err)
		}

		var state vfs.State
		err = json.Unmarshal([]byte(response.Response.Data), &state)
		if err != nil {
			log.Fatalf("could not parse State JSON from RPC: %v", err)
		}

		appInfo := struct {
			ABCIVersion  string
			AppVersion   uint64
			LastHeight   int64
			Transactions int64
			MerkleRoots  int64
			AppHash      string
		}{
			response.Response.Version,
			response.Response.AppVersion,
			state.Height,
			state.NumTransactions,
			int64(len(state.MerkleRoots)),
			fmt.Sprintf("%x", response.Response.LastBlockAppHash),
		}

		if printAsJSON {
			json, _ := json.MarshalIndent(appInfo, "", "  ")
			fmt.Print(string(json) + "\n")
			return // Job done.
		}

		fmt.Printf("vStore v1.0 (vfs v%d) - ABCI: \n", vfs.AppVersion)
		fmt.Printf("  ABCI Version: %s\n", appInfo.ABCIVersion)
		fmt.Printf("   App Version: %d\n", appInfo.AppVersion)
		fmt.Printf("   Last Height: %d\n", appInfo.LastHeight)
		fmt.Printf("  Transactions: %d\n", appInfo.Transactions)
		fmt.Printf("  Merkle Roots: %d\n", appInfo.MerkleRoots)
		fmt.Printf("      App Hash: %s\n", appInfo.AppHash)
	},
}
