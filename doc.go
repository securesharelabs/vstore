/*
Package vstore implements a verifiable store for CometBFT nodes.

vStore is a Go application built using Cosmos SDK. It focusses on providing:

  - data integrity: attaching timestamp and signature information to data ; and
  - data redundancy: running a vstore application on top of CometBFT nodes ; and
  - data availability: data is available from any supporting CometBFT nodes ; and
  - data security: the blockchain is *not* used to store your data!

vStore is built using cobra: github.com/spf13/cobra
By default, the main function runs the vstoreCmd from `cmd/vstore.go`.

# Examples

	vstore --home=/tmp/.vfs-home --socket=unix://vfs.sock
	vstore version
	vstore info --home=/tmp/.vfs-home
	vstore factory --home /tmp/.vfs-home --data "Message here" --commit
	vstore query --home /tmp/.vfs-home --hash TRANSACTION_HASH_HEX

# Subcommands

  - `vstore`: Default vStore application startup (ABCI server).
  - `vstore factory`: Create digitally signed transactions for vfs nodes.
  - `vstore version`: Print the version number of your vStore instance.
  - `vstore info`: Print the current node's vStore information (State).
  - `vstore query`: Query your vStore instance for transactions.

# Disclaimer

The authors of this package cannot be held responsible for any loss of money or
any malintentioned- or harmful- usage forms of this package. Please use this
package with caution.

# Licensing

Copyright vStore Authors
Copyright 2024 SecureShareLabs (https://vfs.zone)

vStore © 2024 by SecureShareLabs is licensed under CC BY-SA 4.0.
*/
package vstore
