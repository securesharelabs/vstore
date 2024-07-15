package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	vfs "vstore/vfs"

	abciserver "github.com/cometbft/cometbft/abci/server"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtlog "github.com/cometbft/cometbft/libs/log"
)

var homeDir string
var socketAddr string

func init() {
	flag.StringVar(&homeDir, "vfs-home", "", "Path to the vfs directory (if empty, uses $HOME/.vstore)")
	flag.StringVar(&socketAddr, "socket-addr", "unix://example.sock", "Unix domain socket address (if empty, uses \"unix://example.sock\"")
}

func main() {
	flag.Parse()
	if homeDir == "" {
		homeDir = os.ExpandEnv("$HOME/.vstore")
	}

	dbPath := filepath.Join(homeDir, "leveldb")
	dbType := cmtdb.BackendType("goleveldb")

	db, err := cmtdb.NewDB("vfs", dbType, dbPath)
	if err != nil {
		log.Fatalf("could not open database: %v", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("error trying to close database: %v", err)
		}
	}()

	// Prepare the vfs application
	app := vfs.NewVStoreApplication(db)

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
}
