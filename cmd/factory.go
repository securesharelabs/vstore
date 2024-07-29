package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vfsp2p "vstore/api/vstore/v1"
	vfs "vstore/vfs"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/client/http"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Used for flags
var transactionData string
var alsoBroadcastTx bool

// init registers the factory command in vstore
func init() {
	// e.g.: vstore factory --data "This is a message"
	factoryCmd.PersistentFlags().StringVar(
		&transactionData,
		"data",
		"",
		"The transaction body that you want to sign.",
	)

	// e.g.: vstore factory --data "This is a message" --commit
	factoryCmd.PersistentFlags().BoolVarP(
		&alsoBroadcastTx,
		"commit",
		"c",
		false,
		"Broadcast and commit the transaction",
	)

	// Add the factory subcommand to vstore
	vstoreCmd.AddCommand(factoryCmd)
}

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Use the vstore transaction factory",
	Long:  `Use the vstore transaction factory to create digitally signed datasets.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Read password to encrypt/decrypt identity file
		fmt.Printf("Enter your password: ")
		pw, err := term.ReadPassword(0)
		if err != nil {
			log.Fatalf("could not read password: %v", err)
		}
		fmt.Printf("\n")

		// Generate and encrypt identity if necessary
		if _, err := os.Stat(idFile); os.IsNotExist(err) {
			vfs.MustGenerateIdentity(idFile, pw)
		}

		id, err := openIdentity(idFile, pw)
		if err != nil {
			log.Fatalf("could not open identity: %v", err)
		}

		priv, err := id.Identity().PrivKey()
		if err != nil {
			log.Fatalf("could not use private key: %v", err)
		}

		// Ask for data if not provided with --data
		if len(transactionData) == 0 {
			fmt.Printf("Enter the data to sign: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalf("could not read transaction data: %v", err)
			}

			transactionData = strings.TrimSuffix(input, "\n")
		}

		// Sign data
		sig, err := priv.Sign([]byte(transactionData))
		if err != nil {
			log.Fatalf("could not sign transaction: %v", err)
		}

		tx := new(vfsp2p.Transaction)
		tx.Signer = vfs.PubKeyToProto(priv.PubKey())
		tx.Signature = sig
		tx.Time = time.Now()
		tx.Len = uint32(len(transactionData))
		tx.Body = []byte(transactionData)

		stx, err := vfs.FromProto(tx)
		if err != nil {
			log.Fatalf("could not create signed transaction: %v", err)
		}

		txbz := stx.Bytes()

		// In case we don't commit the transaction, print the bytes
		if !alsoBroadcastTx {
			fmt.Println("Signed transaction bytes: ")
			fmt.Printf("0x%x\n", txbz)
			return
		}

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
		response, err := cli.BroadcastTxCommit(cmd.Context(), txbz)
		if err != nil {
			log.Fatalf("could not broadcast transaction: %v", err)
		}

		if response.TxResult.Code == vfs.CodeTypeOK {
			fmt.Println("Transaction successfully broadcast!")
			fmt.Printf("Transaction Hash: %x\n", response.Hash)
			fmt.Printf("Committed Height: %d\n", response.Height)
		} else {
			fmt.Println("An error occurred trying to broadcast transaction.")

			resCheckTx, _ := json.MarshalIndent(response.CheckTx, "", "  ")
			resTxResult, _ := json.MarshalIndent(response.TxResult, "", "  ")

			fmt.Println("CheckTx: ")
			fmt.Print(string(resCheckTx))

			fmt.Println("TxResult: ")
			fmt.Print(string(resTxResult))
		}
	},
}

// openIdentity opens an encrypted identity file.
func openIdentity(file string, pw []byte) (vfs.SecretProvider, error) {
	priv := vfs.NewIdentity(file, pw)
	_, err := priv.Open()
	if err != nil {
		return nil, err
	}

	return priv, nil
}
