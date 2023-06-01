# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.9.0] - 2023-05-29: "Beta 1"

In the 0.9.0 Beta 1 release, we've improved onchain funding
transaction validation for better security, integrated BOLT-12
invoices for enhanced flexibility, and introduced LSS external
persistence for superior system stability and resilience.

### Added

 - core: Validate funding TXO ([#208], [#220])
 - core: Track funding inputs for double-spend ([#299])
 - core: Check maximum L1 transaction size ([#288])
 - core: Allow missing input txs when not funding channel ([#224])
 - core: Ensure funding tx inputs are segwit ([#224])
 - core: Invoice expiry ([#287])
 - core: Integrate BOLT-12 invoices
 - core, lss: Introduce ExternalPersist and ExternalPersistHelper ([#268])
 - core: Limit fee velocity ([#122])
 - core: Handle allowlist L2 payees ([#266])
 - core: Add policy limits to prevent DoS ([#233])
 - core: Extend coverage by adding more unit tests ([#256])
 - core: Enforce policy-onchain-funding-non-malleable
 - core, frontend: Add checkpoint support ([#255])
 - proxy: Sweep L1 funds ([#276])
 - proxy: Wait for signer port to be ready (HsmdInit) before sending any frontend messages ([#212])
 - proxy: Persist in inplace / nodefront ([#252])
 - remote-hsmd: Add new CLN HSMD messages ([#286])
 - howto: Add `RUST_LOG` env variable to list
 - howto: Add `listpeers` helper `listpeers-scid-to-nodeid`
 - howto: Add config for policy-channel-safe-type-anchors:warn ([#244])
 - release: Add `harvest_changelog` to gather commit annotations

### Fixed

 - core: Jump tracker to checkoint ([#297])
 - core: Fix upgrade crash with default_fee_velocity_control ([#302])
 - proxy: Fix signer port not becoming ready ([#296])
 - proxy: Fix nodefront thread vs persistence context ([#252])
 - howto: Add gawk to one-time-setup ([#259])
 - howto: Fix initial installation of CLN+VLS service components
 - howto: Fix path in cln testnet service setup
 - vlsd2: Don't print error on `--help` or `--git-desc`

### Changed

 - core: Increase default `MAX_CHANNELS` to 1000 ([#305], [#306])
 - core: Replace VLS_ONCHAIN_VALIDATION with VLS_ONCHAIN_VALIDATION_DISABLE
 - core: Clean up satoshi vs millisatoshi ([#292])
 - core: Update LDK to 0.0.115
 - core: Use `info` log level by default ([#275])
 - frontend: Replace VLS_CHAINFOLLOWER_ENABLE with VLS_FRONTEND_DISABLE ([#294])
 - protocol: increase maximum message size to 128 KiB ([#288])
 - txoo: update txoo to 0.4 ([#260])
 - txoo: update txoo to 0.3 ([#250])
 - stm32: Improved STM32 README documentaion
 - howto: Install systemd services to /etc/systemd ([#293])
 - howto: Improved setup / operation procedures

## [0.2.1] - 2023-03-20: "Developer Preview Plus"

## [0.2.0] - 2023-03-14: "Developer Preview"

### Changed

- legacy and plain anchors commitment types are now disabled by policy
- however, for CLN compatibility, `policy-channel-safe-type-anchors` can be set to warning, and it is set so for integration tests
- once CLN implements zero-fee anchors and disables this channel type, this should be set to error (issue #236)
- minimum dust threshold is now 346 satoshi instead of 330

