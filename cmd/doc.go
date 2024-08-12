/*
Package cmd implements a command-line interface (CLI) for vStore/vfs.

This module defines commands to manage a vStore/vfs ABCI application server and
send (commit) transactions to the blockchain or query the verifiable store.

# Commands

  - `vstore`: Default vStore application startup (ABCI application server).
  - `vstore factory`: Create digitally signed transactions for vfs nodes.
  - `vstore version`: Print the version number of your vStore instance.
  - `vstore info`: Print the current node's vStore information (State).
  - `vstore query`: Query your vStore instance for transactions.
*/
package cmd
