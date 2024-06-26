## Release checklist

Here's a checklist for the release process.

### Leading Up To The Release

1. Talk to team about whether there are any changes which MUST go in
   this release which may cause delay.
1. Look through outstanding issues, to identify any problems that might
   be necessary to fix before the release. Good candidates are crashes.
   and security issues.
1. Identify a good lead for each outstanding issue, and ask them about
   a fix timeline.
1. Create a milestone for the *next* release, and go through
   open issues and PRs and mark accordingly.

### Preparing for -rc.1

1. Create a new CHANGELOG.md heading `<VERSION>-rc.1`
1. Use `scripts/harvest-changelog <PREVIOUS>..` to collect the changelog entries from pull
   request commit messages and merge them into the manually maintained
   `CHANGELOG.md`.
1. Check that `CHANGELOG.md` is well formatted, ordered in areas,
   covers all significant changes, and sub-ordered approximately by user impact
   & coolness.
1. Create a PR with the above.

### Releasing -rc.1

1. Merge the above PR.
1. Update `Cargo.toml` for each crate, and build with `./scripts/build-all`
1. Publish the crates with `cargo publish` (you can test first with `--dry-run`)
1. Tag it and push the tags:
     - `VERSION=<VERSION>-rc.1`
     - `git pull`
     - `git tag -a -s v${VERSION} -m v${VERSION}`
     - `git push --tags`
1. Confirm that the tag will show up for builds with `git describe`
1. Update the /topic on #vls-dev.
1. Prepare draft release notes, and share with team for editing.

### Releasing -rc.2, etc

1. Change rc.1 to rc.2 in CHANGELOG.md.
1. Create a PR with the rc.2 CHANGELOG changes.
1. Update `Cargo.toml` for each crate, and build with `./scripts/build-all`
1. Tag it and push the tags
1. Publish the crates with `cargo publish`
1. Update the /topic on #vls-dev.

### Tagging the Release

1. Update the CHANGELOG.md; remove -rc.N in both places, update the date and add title and name.
1. Update `Cargo.toml` for each crate
1. Add a PR with that release, merge it.
1. Tag it and push the tags:
   - `VERSION=...`
   - `git pull`
   - `git tag -a -s v${VERSION} -m v${VERSION}`
   - `git push --tags`
1. Publish the crates with `cargo publish`

### Announcing the Release

1. Update the /topic on #vls-dev.
1. Send a mail to lightning-dev mailing list, using the
   same wording as the Release Notes.

### Post-release

1. Look through PRs which were delayed for release and merge them.
1. Close out the Milestone for the now-shipped release.
1. Update this file with any missing or changed instructions.

## Notes

These have separate release cycles and should be published first if they changed:

- `cargo publish -p bolt-derive`
- `(cd lightning-storage-server && cargo publish)`

Cargo publishing should be done in this order with matching versions:

- `cargo publish -p vls-core`
- `cargo publish -p vls-persist`
- `cargo publish -p vls-protocol`
- `cargo publish -p vls-protocol-signer`
- `cargo publish -p vls-protocol-client`
- `cargo publish -p vls-frontend`
- `cargo publish -p vls-proxy`
- `cargo publish -p vls-cli`

You may also be interested in:

- `cargo install cargo-publish-workspace-v2`
- `cargo publish-workspace --target-version 0.10.0-rc.1 --crate-prefix vls --exclude vls-core-test --token XXX`

where XXX is the token from `~/.cargo/credentials`.

## Helpful Commands

```
# do bolt-derive and/or lightning-storage-server need publishing?
export PREV_VER=v0.11.1
export VER=v0.12.0-rc.2
export YM=$(date +%Y-%m)
git checkout main && git pull
git checkout -b $YM-$VER
scripts/harvest-changelog "$PREV_VER".. > /tmp/CHANGELOG_ENTRIES.md
# merge /tmp/CHANGELOG_ENTRIES.md into CHANGELOG.md
git log --pretty="%aN" "$PREV_VER".. | sort -fu > /tmp/AUTHORS.txt
# incorporate the authors into the CHANGELOG.md
# string replace the old release w/ the new
./scripts/build-all
cargo test
cargo build --release
cargo package
# commit changes
# push MR
# review MR
# merge MR
git tag -a -s $VER -m $VER
git push --follow-tags
cargo login <your_token>
./scripts/publish-all
```
