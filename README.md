# vStore: verifiable store

**vStore** is a Go application built using Cosmos SDK. It focusses on providing:

- *data integrity*: attaching timestamp and signature information to data ; and
- *data redundancy*: running a vstore application on top of CometBFT nodes ; and
- *data availability*: our Go application enables you to make data available ; and
- *data security*: the blockchain is *not* used to store your data!

The **vStore** is released as an ABCI application which commits cryptographic proof
alongside data sets to ensure that they are untouched and always verifiable.

This software implements a first draft of **vfs** as an integral part of the vstore
application, this may change in the future.

## Install

To start running an instance of `vstore`, execute the following command:

```bash
go install github.com/securesharelabs/vstore@latest
vstore -vfs-home /tmp/.vfs-home --socket-addr unix://vfs.sock
```

You can interact with vfs using any ABCI client implementation or you can run
a CometBFT node from the same directory that connects with this ABCI application:

```bash
export COMETBFT="github.com/cometbft/cometbft/cmd/cometbft@latest"
go run ${COMETBFT} init --home /tmp/.cometbft-home
go run ${COMETBFT} node --home /tmp/.cometbft-home --proxy_app=unix://vfs.sock
```

Your `vstore` instance is now available through the CometBFT RPC, e.g.:

```bash
# Sending a transaction
curl -s 'localhost:26657/broadcast_tx_commit?tx="DATA"'

# Querying the filesystem by tx hash
curl -s 'localhost:26657/abci_query?data="TX_HASH"'
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
