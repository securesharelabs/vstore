# vStore: verifiable store

![Version](https://img.shields.io/github/v/tag/securesharelabs/vstore?label=version)
![Go version](https://img.shields.io/github/go-mod/go-version/securesharelabs/vstore)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)][issues]
[![Website](https://img.shields.io/badge/https://-vfs.zone-blue)][vfs]

**vStore** is a Go application built using Cosmos SDK. It focusses on providing:

- *data integrity*: attaching timestamp and signature information to data ; and
- *data redundancy*: running a vstore application on top of CometBFT nodes ; and
- *data availability*: data is available from any supporting CometBFT nodes ; and
- *data security*: the blockchain is *not* used to store your data!

The **vStore** is released as an ABCI application which commits cryptographic proof
alongside data sets to ensure that they are untouched and always verifiable.

This software implements a first draft of **vfs** as an integral part of the vstore
application, this may change in the future.

## Usage

A reference documentation is deployed at [https://vfs.zone][vfs].

Usage documentation can be found in this document or in the `cmd` package documentation
which also lists some examples [here][usage].

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

## Developer notes

This package is released as `github.com/securesharelabs/vstore` and is composed
of two implementation subpackages:

- `github.com/securesharelabs/vstore/vfs`: A first draft implementation for `vfs`.
- `github.com/securesharelabs/vstore/cmd`: A CLI for storing data with vStore.

Note that it is probable that the `vfs` subpackage implementation gets extracted
in later iterations of the project.

You can install dependencies and run the unit test suite using:

```bash
go get
go build
go test github.com/securesharelabs/vstore/vfs -v -count=1
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
[usage]: https://vfs.zone/pkg/github.com/securesharelabs/vstore/cmd/
[issues]: https://github.com/securesharelabs/vstore/issues
[license-url]: https://creativecommons.org/licenses/by-sa/4.0/
