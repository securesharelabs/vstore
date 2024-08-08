# vStore: verifiable store

**vStore** is a Go application built using Cosmos SDK. It focusses on providing:

- *data integrity*: attaching timestamp and signature information to data ; and
- *data redundancy*: running a vstore application on top of CometBFT nodes ; and
- *data availability*: data is available from any supporting CometBFT nodes ; and
- *data security*: the blockchain is *not* used to store your data!

The **vStore** is released as an ABCI application which commits cryptographic proof
alongside data sets to ensure that they are untouched and always verifiable.

This software implements a first draft of **vfs** as an integral part of the vstore
application, this may change in the future.

## Install

To start running an instance of `vstore`, execute the following command:

```bash
go install github.com/securesharelabs/vstore@latest
vstore --home /tmp/.vfs-home --socket unix://vfs.sock
```

You can interact with vfs using any ABCI client implementation or you can run
a CometBFT node from the same directory that connects with this ABCI application:

```bash
export COMETBFT="github.com/cometbft/cometbft/cmd/cometbft@v0.38.10"
go run ${COMETBFT} init --home /tmp/.cometbft-home
go run ${COMETBFT} node --home /tmp/.cometbft-home --proxy_app unix://vfs.sock
```

Your `vstore` instance is now available through the CometBFT RPC, and using the
different subcommands available with vstore, e.g.:

```bash
# Sending a transaction
vstore factory --home /tmp/.vfs-home --data "Data that will be signed" --commit

# Querying app info (includes AppHash)
vstore info --home /tmp/.vfs-home

# Querying a transaction hash (as returned by factory)
vstore query --home /tmp/.vfs-home --hash TRANSACTION_HASH_HEX
```

## Disclaimer

The authors of this package cannot be held responsible for any loss of money or
any malintentioned- or harmful- usage forms of this package. Please use this
package with caution.

## Licensing

Copyright vStore Authors
Copyright 2024 SecureShareLabs (https://vfs.zone)

[vStore][vfs] © 2024 by SecureShareLabs is licensed under [CC BY-SA 4.0][license-url].

[vfs]: https://vfs.zone
[spec]: ./docs/spec/README.md
[license-url]: https://creativecommons.org/licenses/by-sa/4.0/
