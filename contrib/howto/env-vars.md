## VLS Environment Variables

#### `VLS_MODE` - Choose VLS integration mode for system tests

The `VLS_MODE` env variable is interpreted by the top-level `vls-hsmd` repo Makefile.

See [VLS Integration Modes](https://gitlab.com/lightning-signer/docs/-/blob/master/overview/README.md#vls-integration-modes)
for more information.

Possible values:
- `VLS_MODE=cln:inplace`
- `VLS_MODE=cln:socket`
- `VLS_MODE=cln:serial`

#### `VLS_DISABLE_UPDATE_VERSION` - Disable rebuilding binaries with current version

The `VLS_DISABLE_UPDATE_VERSION` env variable is interpreted by the
`vls` build system, for example `cargo build` or `cargo test`.

Unfortunately, `cargo build` always rebuilds the binaries (even when they are up to date) to
ensure the git version string is current.  Setting `VLS_DISABLE_UPDATE_VERSION=1` disables
this behavior.  This is useful in development when building repeatedly.

#### `VLS_AUTOAPPROVE` - Automatically approve payments

The `VLS_AUTOAPPROVE` env variable is interpreted by `vlsd2` and `remote_hsmd_inplace`.

By default if an invoice payment, keysend, or onchain payment is not allowlisted it requires
explicit approval.  When `VLS_AUTOAPPROVE=1` these payments will be automatically approved.
This is useful for integration testing.

#### `VLS_PERMISSIVE` - Warn on policy violation instead of failing

The `VLS_PERMISSIVE` env variable is interpreted by `vlsd2` and `remote_hsmd_inplace`.

When `VLS_PERMISSIVE=1` any policy violations will generate a warning to the log and then succeed.
This is useful for testing and early system integration.

#### `VLS_ONCHAIN_VALIDATION` - Enable onchain validation

The `VLS_ONCHAIN_VALIDATION` env variable is interpreted by `vlsd2` and `remote_hsmd_inplace`.

Setting `VLS_ONCHAIN_VALIDATION=1` enables policy checking involving onchain events.  For
example ensuring that the funding transaction is locked before allowing further channel
operations.

#### `VLS_FRONTEND_DISABLE` - Disable the frontend services (chainfollower, heartbeats)

The `VLS_FRONTEND_DISABLE` env variable is interpreted by
`remote_hsmd_socket`, `remote_hsmd_serial`, and `remote_hsmd_inplace`.

#### `RUST_LOG` - Set the logging level

The `RUST_LOG` env variable is interpreted by all VLS rust programs.

The `RUST_LOG` environment variable can be set to `trace`, `debug`, `info` ...

#### `RUST_BACKTRACE` - Enable backtraces

The `RUST_BACKTRACE` env variable is interpreted by all VLS rust programs.

Set `RUST_BACKTRACE=1` if you desire backtraces.

