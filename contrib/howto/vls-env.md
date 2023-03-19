## VLS Environment Variables

#### `VLS_MODE` - Choose VLS integration mode

See [VLS Integration Modes](https://gitlab.com/lightning-signer/docs/-/blob/master/overview/README.md#vls-integration-modes)
for more information.

Possible values:
- `VLS_MODE=cln:inplace`
- `VLS_MODE=cln:socket`
- `VLS_MODE=cln:serial`

#### `VLS_AUTOAPPROVE` - Automatically approve payments

By default if an invoice payment, keysend, or onchain payment is not allowlisted it requires
explicit approval.  When `VLS_AUTOAPPROVE=1` these payments will be automatically approved.
This is useful for integration testing.

#### `VLS_PERMISSIVE` - Warn on policy violation instead of failing

When `VLS_PERMISSIVE=1` any policy violations will generate a warning to the log and then succeed.
This is useful for testing and early system integration.

#### `VLS_CHAINFOLLOWER_ENABLE` - Enable the chainfollower

**DEPRECATED** By default the chainfollower is not enabled.  Setting
`VLS_CHAINFOLLOWER_ENABLE=1` enables the chainfollower.  This variable will likely be
replaced with `VLS_FRONTEND_DISABLE` in the near future.

#### `VLS_DISABLE_UPDATE_VERSION` - Disable rebuilding binaries with current version

Unfortunately, `cargo build` always rebuilds the binaries (even when they are up to date) to
ensure the git version string is current.  Setting `VLS_DISABLE_UPDATE_VERSION=1` disables
this behavior.  This is useful in development when building repeatedly.
