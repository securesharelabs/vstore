package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	vfs "github.com/securesharelabs/vstore/vfs"

	"github.com/spf13/cobra"

	abciserver "github.com/cometbft/cometbft/abci/server"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtlog "github.com/cometbft/cometbft/libs/log"

	"golang.org/x/term"
)

var (
	// Used for flags.
	homeDir    string
	socketAddr string
	idFile     string

	// e.g. vstore --home /tmp/.vfs-home
	vstoreCmd = &cobra.Command{
		Use:   "vstore [subcommand]",
		Short: "vStore is a verifiable store for CometBFT blockchain networks",

		Long: `vStore is a Go application built using Cosmos SDK. It focusses on providing:

  - data integrity: attaching timestamp and signature information to data ; and
  - data redundancy: running a vstore application on top of CometBFT nodes ; and
  - data availability: data is available from any supporting CometBFT nodes ; and
  - data security: the blockchain is *not* used to store your data!`,

		Example: `  vstore
  vstore version
  vstore --home /tmp/.vstore --socket unix://vfs.sock --id /tmp/.vstore/id`,

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

			// Open database connection
			db, dbPath, teardownDb, err := openDatabase("vfs", homeDir)
			if err != nil {
				log.Fatalf("could not open database: %v", err)
			}

			defer teardownDb()

			log.Printf("using database: %s", dbPath)

			// Prepare the vfs application
			app := vfs.NewVStoreApplication(db, idFile, pw)

			// Prepare the ABCI server
			logger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
			server := abciserver.NewSocketServer(socketAddr, app)
			server.SetLogger(logger)

			// Start the ABCI server
			if err := server.Start(); err != nil {
				log.Fatalf("error starting socket server: %v", err)
				os.Exit(1)
			}
			defer server.Stop()

			// Handle SIGTERM
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	// e.g.: vstore --home /tmp/.vfs-home
	vstoreCmd.PersistentFlags().StringVar(
		&homeDir,
		"home",
		"",
		"Path to the vfs directory (if empty, uses $HOME/.vstore)",
	)

	// e.g.: vstore --socket unix://vfs.sock
	vstoreCmd.PersistentFlags().StringVar(
		&socketAddr,
		"socket",
		"unix://vfs.sock",
		"Unix domain socket address (if empty, uses \"unix://vfs.sock\")",
	)

	// e.g.: vstore --id /tmp/my-ed25519.id
	vstoreCmd.PersistentFlags().StringVar(
		&idFile,
		"id",
		"",
		"Path to the identity file (if empty, uses $HOME/.vstore/id)",
	)
}

func initConfig() {
	// Empty home directory uses default
	if homeDir == "" {
		homeDir, _ = os.UserHomeDir()
		homeDir = filepath.Join(homeDir, ".vstore") // $HOME/.vstore
	}

	// Empty identity file path generates new
	if idFile == "" {
		// Create default identity file
		idFile = filepath.Join(homeDir, "id")
	}
}

func Execute() {
	// Stop execution on panic
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("error starting vfs node: %v", err)
		}
	}()

	// Handle error return codes
	if err := vstoreCmd.Execute(); err != nil {
		log.Fatalf("error starting vfs node: %v", err)
	}
}

// openDatabase creates a new leveldb database using goleveldb in the user's
// home directory as provided with homeDir. A teardown function is returned
// as the third return value, you can defer the call to safely close the db.
func openDatabase(name, homeDir string) (cmtdb.DB, string, func(), error) {
	dbPath := filepath.Join(homeDir, "leveldb")
	dbType := cmtdb.BackendType("goleveldb")

	db, err := cmtdb.NewDB(name, dbType, dbPath)
	if err != nil {
		return nil, dbPath, func() {}, err
	}

	return db, dbPath, func() {
		if err := db.Close(); err != nil {
			log.Fatalf("error trying to close database: %v", err)
		}
	}, nil
}
