/*
Package vstore implements a verifiable store for CometBFT nodes.

# Motivation

vStore is a Go application built using [CometBFT]. It focusses on providing:

  - data integrity: attaching timestamp and signature information to data ; and
  - data redundancy: running a vstore application on top of CometBFT nodes ; and
  - data availability: data is available from any supporting CometBFT nodes ; and
  - data security: the blockchain is *not* used to store your data!

vStore is built using the [cobra] command-line utility software.

By default, the main function runs the vstoreCmd from `cmd/vstore.go` which starts
a vStore instance and asks the user for a password to decrypt the node identity.

# Examples

	vstore --home=/tmp/.vfs-home --socket=unix://vfs.sock
	vstore version
	vstore info --home=/tmp/.vfs-home
	vstore factory --home /tmp/.vfs-home --data "Message here" --commit
	vstore query --home /tmp/.vfs-home --hash TRANSACTION_HASH_HEX

# Commands

  - `vstore`: Default vStore application startup (ABCI application server).
  - `vstore factory`: Create digitally signed transactions for vfs nodes.
  - `vstore version`: Print the version number of your vStore instance.
  - `vstore info`: Print the current node's vStore information (State).
  - `vstore query`: Query your vStore instance for transactions.

[cobra]: https://github.com/spf13/cobra
[CometBFT]: https://github.com/cometbft/cometbft
*/
package main
