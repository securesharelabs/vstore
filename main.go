package main

import (
	"vstore/cmd"
)

// vStore is built using cobra: github.com/spf13/cobra
// By default, this main function runs the vstoreCmd from cmd/vstore.go.
//
// Usage example:
// vstore --home=/tmp/.vfs-home --socket=unix://vfs.sock
//
// Subcommands:
// - `vstore factory`: Create digitally signed transactions for vfs nodes.
// - `vstore version`: Print the version number of your vStore instance.
func main() {
	cmd.Execute()
}
