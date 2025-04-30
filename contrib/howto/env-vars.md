## VLS Environment Variables

### Main Environment Variables

#### `VLS_MODE` - Choose VLS integration mode for system tests

The `VLS_MODE` env variable is interpreted by the top-level `vls-hsmd` repo Makefile.

See [VLS Integration Modes](https://gitlab.com/lightning-signer/docs/-/blob/master/overview/README.md#vls-integration-modes)
for more information.

Possible values:
- `VLS_MODE=cln:inplace`
- `VLS_MODE=cln:socket`
- `VLS_MODE=cln:serial`

#### `VLS_AUTOAPPROVE` - Automatically approve payments

The `VLS_AUTOAPPROVE` env variable is interpreted by `vlsd` and `remote_hsmd_inplace`.

By default, if an invoice payment, keysend, or onchain payment is not allowlisted it requires
explicit approval.  When `VLS_AUTOAPPROVE=1` these payments will be automatically approved.
This is useful for integration testing.

#### `VLS_PERMISSIVE` - Warn on policy violation instead of failing

The `VLS_PERMISSIVE` env variable is interpreted by `vlsd` and `remote_hsmd_inplace`.

When `VLS_PERMISSIVE=1` any policy violations will generate a warning to the log and then succeed.
This is useful for testing and early system integration.

#### `VLS_ONCHAIN_VALIDATION_DISABLE` - Disable onchain validation

The `VLS_ONCHAIN_VALIDATION_DISABLE` env variable is interpreted by
`vlsd` and `remote_hsmd_inplace`.

Setting `VLS_ONCHAIN_VALIDATION_DISABLE=1` disables policy checking
involving onchain events.  For example ensuring that the funding
transaction is locked before allowing further channel operations.

#### `VLS_MAX_PROTOCOL_VERSION` - Override maximum wire protocol version

The `VLS_MAX_PROTOCOL_VERSION` env variable is interpreted by `vlsd` on startup.

Setting `VLS_MAX_PROTOCOL_VERSION=4` limits the maximum protocol
version which will be used by `vlsd` when communicating with
node.  This feature is useful for developers who need to control the
protocol version for testing or debugging.

This only sets the maximum protocol version; the node may negotiate a lower version.

#### `RUST_LOG` - Set the logging level

The `RUST_LOG` env variable is interpreted by all VLS rust programs.

The `RUST_LOG` environment variable can be set to `trace`, `debug`, `info` ...

#### `BITCOIND_CLIENT_TIMEOUT_SECS` - Set the bitcoind_client timeout

Setting `BITCOIND_CLIENT_TIMEOUT_SECS=60` will set the timeout used by
the frontend (in the proxy) when making requests to the bitcoind RPC
API to 60 seconds.

If not set the bitcoind_client uses the default `SimpleHttpTransport`
timeout (currently 15 seconds).

#### `RUST_BACKTRACE` - Enable backtraces

The `RUST_BACKTRACE` env variable is interpreted by all VLS rust programs.

Set `RUST_BACKTRACE=1` if you desire backtraces.

### Miscellaneous Frontend Environment Variables

These are interpreted by `remote_hsmd_socket`, `remote_hsmd_serial`, and `remote_hsmd_inplace`.

- `VLS_FRONTEND_DISABLE` - Disable the frontend services (chainfollower, heartbeats)
- `VLS_CHAINFOLLOWER_TEST_STREAMING` - cause all blocks to be considered false positives in the frontend, so that the entire block is streamed
