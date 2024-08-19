/*
Package vfs implements a verifiable store for CometBFT nodes.

vfs defines key components for the establishment of a secure data communication
protocol which is based on digital signatures with ed25519 elliptic-curve.

# Structures

  - [IdentitySecretProvider]: Creates AES-256 secrets used to encrypt the database.
  - [SecretProvider]: Creates AES-256 secrets used to encrypt private keys.
  - [Signable]: Interfaces that describes data to be signed using an ed25519 private key.
  - [SignedTransaction]: Describes a signed data object that is timestamped.
  - [State]: Consists of a blockchain height, a number of transactions and merkle roots.
  - [VStoreApplication]: A CometBFT ABCI application to run on top of CometBFT nodes.

# Examples

	vstore --home=/tmp/.vfs-home --socket=unix://vfs.sock
	vstore version
	vstore info --home=/tmp/.vfs-home
	vstore factory --home /tmp/.vfs-home --data "Message here" --commit
	vstore query --home /tmp/.vfs-home --hash TRANSACTION_HASH_HEX
*/
package vfs
