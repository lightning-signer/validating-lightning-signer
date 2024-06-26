# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.12.0-rc.1] - 2024-06-25: "Benevolent Basilisk"

This release named by Provisional Pete

### Added

 - core: Added tests for validating trusted oracle public key.
 - core: Implement `sign_holder_htlc_transaction`.
 - core: Make `NativeKeyDerive` struct public usable.
 - core: Rename `TxIdDef` and `OutpointDef` to clarify the txid encoding used.
 - core: Validate blocks using trusted oracle pubkeys.
 - core: `channel_balance` now breaks channel counts into stub, unconfirmed, ready, and closing counts.
 - protocol: Added hsmd protocol version 6: `GetPerCommitmentPoint` no longer returns the old secret.
 - protocol: A new procedural macro `SerBoltTlvOptions` was added to streamline defining TLV option structures.
 - proxy: Set the default directory to ~/.
 - proxy: Set the only read permission on the seed.
 - serial-proxy: `HsmdDevPreinit2` sent from CLN is now merged with VLS use.
 - stm32: Added unknown onchain destination approver screen.  Fixes ([#488]).
 - stm32: Now displays prep, active, and closing channel counts.
 - stm32: To avoid accidentally deleting a node instance the blue button must be held down when deleting a node.
 - vls-cli: Added new rpc methods and cli commands.
 - logging: Added log support for core, persist.
 - logging: Added tracing-instrument macro for span generation.
 - logging: Opentelemetry Logging Protocol exporter with tracing subscriber.
 - logging: The channel balance summary is logged on heartbeats.
 - debug: A table of current channel information is logged on startup.
 - howto: vls-probe-testnet service added to monitor stm32

### Changed

 - policy: The testnet value of max_feerate_per_kw was increased because higher values were observed in testnet.  See ([#313])
 - core: Use standard serialize for rust-bitcoin and provide backward compatible deserializer visitors.
 - protocol: A new msg `HsmdDevPreinit2` replaces the old `HsmdDevPreinit` with all arguments represented by a TLV encoded options.
 - protocol: Handle deep reorgs for testnet.
 - protocol: Update `serde_bolt` to v0.3.5.
 - security: Updated `mio` to 0.8.11 to mitigate `RUSTSEC-2024-0019`.
 - security: Updated `whoami` to 1.5.0 to mitigate `RUSTSEC-2024-0020.`
 - handler: Development initialization (forced seed etc) now uses the TLV based `HsmdDevPreinit2` message.
 - proxy: Allow comments and whitespace in ALLOWLIST by calling a publically available line_filter in the allowlist_parser.
 - proxy: Implement `SimplePolicy` values logging at startup using `Debug` and add regex to logfilter.
 - proxy: Rename `GREENLIGHT_VERSION` env variable to `VLS_CLN_VERSION`.
 - proxy: Replaces fixed placeholder seed for `HsmdDevPreinit` if no testing seed is found on startup. Now sends `None` instead and generate a random seed on the signer.
 - signer: The `HsmdDevPreinit2` handler does not send a reply.
 - stm32: Master messages on behalf of a single channel are shown on the channels track.
 - stm32: The serial proxy and demo_signer are updated to use the `HsmdDevPreinit2` message for development initialization.
 - debug: Enabling the `log_pretty_print` feature enables it for dependencies as well.
 - debug: The feature `log-pretty-print` is no longer default for debug builds.
 - howto: The `max-locktime-blocks` setting was removed from the example testnet config because CLN v24.05 deprecated it.
 - howto: The cln-testnet service is streamlined by automatically dynamically setting `VLS_CLN_VERSION`.
 - howto: the update instructions for build and install were simplified.

### Fixed

 - core: A problem w/ handling historical revocations on reconnection which led to state corruption was fixed ([#502])
 - vlsd2: Reconnect to CLN if CLN crashes.
 - stm32: The crash in the stm32 invoice approver is fixed ([#429])

### Workaround

 - protocol: Until `HSMD PROTOCOL VERSION` 6 it is safer if `get_per_commitment` doesn't fail on invalid (secret) indexes ([#469])
 - stm32: policies that CLBOSS hits are downgraded to warnings. ([#313])
 - stm32: `policy-commitment-retry-same` is nerfed until ([491]) resolved

### Contributors

The following people contributed to this release:
- bit-aloo
- Devrandom
- Harsh1s
- Jack Ronaldi
- Ken Sedgwick
- Lakshya Singh
- Shourya Sharma
- sistemd
- Tarek
- Vincenzo Palazzo


## [0.11.1] - 2024-05-16: "Auspicious Anubis"

This release named by Jack Ronaldi

### Fixed

- core: Added a compilation fix for dependency `serde_bolt v0.3.5` which broke API compatibility.
- security: Minimum `rustls`, `h2`, and `mio` versions now specified to mitigate issues reported by`cargo audit`.

## [0.11.0] - 2024-02-29: "Auspicious Anubis"

This release named by Jack Ronaldi

### Added

 - policy: adding the a `policy_generic_error` error
 - policy: policy-routing-balanced specify L2 max fee as %
 - core: Channels are pruned promptly when we know the node has forgotten them. ([#435])
 - core: Channels are now never pruned until the node calls `ForgetChannel`
 - core: Added explicit activate_initial_commitment call since
   commitment 0 does not have a prior commitment to revoke.
 - signer: Add ValueFormat field to KVVPersister
 - signer: Added json rpc server for administrative purposes
 - proxy: replay protocol init message on signer reconnect
 - handler: A new message `HsmdDevPreinit` should be used to force developer test parameters.
 - handler: Handling for the new CLN `hsmd_sign_any_cannouncement` was added.
 - handler: Implement version negotiation for the protocol between node and signer
 - handler: Improved logging to show when a SignCommitmentTx is really a SignMutualCloseTx
 - frontend: The bitcoind_client timeout can now be set with the BITCOIND_CLIENT_TIMEOUT_SECS env variable.
 - build: Added `mold` linker sample config
 - howto: Added utility to summarize logs in integration test trees
 - howto: Added journactl configuration tips
 - howto: Added logcat and logfilter scripts to facilitate searching logging output
 - howto: The CLN+VLS setup instructions were updated to enable anchors
 - howto: Added VLS Docker instructions
 - vls-cli: Added an administrative command line interface
 - proxy: add UnixConnection::try_clone
 - ci: add expiry time for artifacts

### Changed

 - core, persist: optimize de/serialization of u8 sequences for binary formats
 - create `Message::SignerError`
 - prioritize serde::De/Serialize implementations for binary formats
 - split revocation from validate_holder_commitment
 - lss: switch to ciborium
 - ci: The nightly toolchain is no longer needed for coverage runs.
 - core: Updated serde_bolt to v0.3.4
 - Updated txoo to v0.6.4
 - Updated ahash to v0.8.4 to avoid yanked version at crates.io.

### Removed

 - Removed `remote_hsmd_inplace` support because not used.

### Fixed

 - The wire protocol was updated to use explicit commitment revocation to fix ([#207])
 - core: avoiding dividing by 0 when the invoice amount is Some(0)
 - implement sweep of our to-remote with anchors
 - persist: drop staged versions on RedbKVVStore::put_batch abort
 - persist: fix cargo test compilation for vls-persist crate
 - persist: remove version increments on subsequent intra-transaction calls to CloudKVVStore::put
 - remote_hamd_socket should now shutdown cleanly
 - remove unneeded channel persists
 - remove unneeded trailing zero entries from CounterpartyCommitmentSecrets
 - revert change to channel ID endianess
 - set frontend interval MissedTickBehavior to Skip
 - upgrade unsafe-libyaml to correct RUSTSEC-2023-0075 and h2 to correct RUSTSEC-2024-0003
 - use earliest checkpoint in frontend startup check ([#470])

## [0.11.0-rc.1] - 2023-06-15: "Beta 3"

This release is focused on stability and performance.

### Added

- CloudKVVStore for cloud storage backed by a local store
- proxy: Extend the preapproval cache to the socket proxy. ([#431])
- Added warning placeholders for the CheckOutpoint and LockOutpoint until they are fully implemented
- Added --feature vls-proxy/heapmon_requests to enable peak request heap monitoring.

### Changed

- LSS now uses redb instead of sled for the embedded DB option
- build: The `workspace.resolver` has been set to "2"
- don't store zero amount issued invoices, e.g. synthetic invoices for keysend receiving
- reduce MSRV to 1.66
- update to LDK 0.0.116
- write a last-writer record to cloud store for sync checking
- ready_channel is now setup_channel
- Channel stubs are allowed to get 2nd per-commitment point ([#245])
- Use llvm-cov instead of kcov for coverage reports [(#382)]
- better version.rs update logic, VLS_DISABLE_UPDATE_VERSION no longer needed
- default to stm32f413 for the demo signer
- improved memory handling in persistence
- logging: The console log will use color and the file log will be plain.
- reduce AddBlock memory use ([#415])

### Removed

- support for sled in vls-persist

### Fixed

- catch any LDK panics when building HTLC transactions
- core: Use block time instead of block height to wait for final htcl sweep because testnet blockstorms cause premature channel pruning ([#412])
- eliminate unnecessary signing of HTLC transactions

### Security

- Updated reqwest to mitigate RUSTSEC-2023-0052
- Updated rustls and rustls-webpki to mitigate RUSTSEC-2023-0053
- Updated txoo to mitigate RUSTSEC-2023-0052

## [0.10.0] - 2023-06-15: "Beta 2"

The main focus of this release is low-resource environments and CLN 23.08 support.

### Added

- introduce Redb database support and deprecate sled based storage
- core: Add KEYSEND_PRUNE_TIME to facilitate more expedient pruning of keysends ([#235])
- proxy: Cache approved keysend and invoice requests for 60 seconds.
- core: Added Persist::delete_channel to address ([#315])
- frontend block streaming for bounded memory consumption
- core: Can now sign P2TR outpoints
- core: Prune stubs from Failed channel opens after 6 blocks ([#315])
- monitor closing of channels
- spending anchors
- counterparty revocation secrets storage
- Added a `sign_tagged_message` method for raw signatures
- basic crypto benchmarks
- bench: individual operation for latency measure
- howto: Added Fedora specific dependencies and setup instructions
- stm32: Added BlockChunk display and tuned block chunk size

### Changed

- MSRV is now 1.63.0
- memory efficient protocol handling
- no-std support for ThreadMemoPersister
- reduce memory requirement for SignWithdrawal PSBT handling
- stm32: Change the default memory configuration to the STM32F413 ([#300])
- stm32: Display heap remaining instead of heap used.
- stm32: Oversized RTT (ST-LINK) messages are now trimmed instead of being dropped entirely
- stm32: Set HEAP_SIZE to 224KB ([#300])
- stm32: Stack size was changed to 32KB

### Fixed

- core: Associated tracker listeners are now removed when channel is pruned.
- core: Channels are pruned after they are marked is_done
- core: Prune RoutedPayment records when forwarding done ([235])
- incorrect signature on anchor holder HTLC 2nd level txs
- serialization fixes related to serial port configurations
- stm32: Disabled link-time-optimization because it was truncating stack backtraces when heap exhausted. ([#352])
- stm32: Fixed problem with large FATFS writes ([#187], [#280])
- stm32: Reduced heap usage when logging message names
- vls-frontend: authenticate ChainFollower to bitcoind
- persist: Fixed startup crash on channel tombstone in kvv ([#371])

### Workaround

- feature flag to decrease chaintracker MAX_REORG_SIZE to 16 for low-resource environments
- stm32: Use block header tstamps until proper clock is implemented ([#206], [#235], [#339])


## [0.9.1] - 2023-06-15: "Beta 1.1"

### Added

- Handler::with_persist for modifications to the node requiring persist to cloud
- MemoApprover
- Node::update_velocity_controls to sync node with updated control specs (#295)
- ability to update VelocityApprover control
- commands to generate and dump sample persist data, and unit test restore of data
- persister: BackupPersister - write to a main persister and sync to backup persister (#314)
- debug_node_state logging feature

### Changed

- serialization backwards compatibility with 0.2
- core: Remove policy.require_invoices flag, always enforce
- Decrease allowable testnet locktime on us (to_self_delay) to speed sweeps of force-closed  nodes
- core: Replace debug_vals!() with dbgvals!() which is heap friendly
- ci: don't require Changelog entries for merge commits
- core: Increase testnet max_routing_fee_msat to 50_000 to clear CLN integration test
- howto: Consolidate vlsd2 config files in ~/.lightning-signer/
- howto: Decrease allowable testnet to_self_delay to allow earlier sweeps of force-closed channels

### Removed

- howto: Remove deprecated VLS_CHAINFOLLOWER_ENABLE=1 ([#294])

### Fixed

- core: Add workaround for keysend expiration ([#329])
- handing of failed HTLCs in payment accounting
- restore invoices and issued_invoices
- restore payments state
- workaround unbalanced routed payment with LDK - see #331
- core: Don't clear pre-existing payments state on add_{invoice,keysend}


## [0.9.0] - 2023-05-29: "Beta 1"

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
 - core, frontend: Add chain follower checkpoint support ([#255])
 - proxy: Sweep L1 funds ([#276])
 - proxy: Wait for signer port to be ready (HsmdInit) before sending any frontend messages ([#212])
 - proxy: Persist in inplace / nodefront ([#252])
 - remote-hsmd: Add new CLN HSMD messages ([#286])
 - howto: Add `RUST_LOG` env variable to list
 - howto: Add `listpeers` helper `listpeers-scid-to-nodeid`
 - howto: Add config for policy-channel-safe-type-anchors:warn ([#244])
 - release: Add `harvest_changelog` to gather commit annotations

### Fixed

 - core: Jump tracker to checkpoint ([#297])
 - core: Fix upgrade crash with default_fee_velocity_control ([#302])
 - proxy: Fix signer port not becoming ready ([#296])
 - proxy: Fix nodefront thread vs persistence context ([#252])
 - howto: Add gawk to one-time-setup ([#259])
 - howto: Fix initial installation of CLN+VLS service components
 - howto: Fix path in cln testnet service setup
 - vlsd2: Don't print error on `--help` or `--git-desc`

### Changed

 - compatibility with CLN 23.05 ([#415])
 - core: Increase default `MAX_CHANNELS` to 1000 as workaround to lack of garbage collection ([#305], [#306])
 - core: Replace VLS_ONCHAIN_VALIDATION with VLS_ONCHAIN_VALIDATION_DISABLE
 - frontend: Replace VLS_CHAINFOLLOWER_ENABLE with VLS_FRONTEND_DISABLE ([#294])
 - core: Clean up satoshi vs millisatoshi ([#292])
 - core: Update LDK to 0.0.115
 - core: Use `info` log level by default ([#275])
 - protocol: increase maximum message size to 128 KiB ([#288])
 - txoo: update txoo to 0.4 ([#260])
 - txoo: update txoo to 0.3 ([#250])
 - stm32: Improved STM32 README documentation
 - howto: Install systemd services to /etc/systemd ([#293])
 - howto: Improved setup / operation procedures

## [0.2.1] - 2023-03-20: "Developer Preview Plus"

## [0.2.0] - 2023-03-14: "Developer Preview"

### Changed

- legacy and plain anchors commitment types are now disabled by policy
- however, for CLN compatibility, `policy-channel-safe-type-anchors` can be set to warning, and it is set so for integration tests
- once CLN implements zero-fee anchors and disables this channel type, this should be set to error (issue #236)
- minimum dust threshold is now 346 satoshi instead of 330

