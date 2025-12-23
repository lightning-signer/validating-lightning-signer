# Making Releases

The general process: we create release branches for each new minor release. We
start with release candidates before each release which needs to pass some
manual QA it moves to a final release. The changelog should be updated and the
versions in the Cargo.tomls should be bumped in a merge request onto the release
branch, which should then be merged and tagged. Bug fixes should be cherry
picked from main where appropriate, otherwise committed as a merge request onto
the release branch.

Cargo versions > 1.90 are capable of publishing workspaces.

## Release checklist

### Leading up to the release

1. Talk to team about whether there are any changes which MUST go in this
   release which may cause delay.
1. Look through outstanding issues to identify any problems that might be
   necessary to fix before the release. Good candidates are crashes and security
   issues.
1. Identify a good lead for each outstanding issue and ask them about a fix
   timeline.
1. Create a milestone for the _next_ release, go through open issues and MRs and
   mark accordingly.

### If releasing a new major or minor version

1. Create a new branch off main called `release-<MAJOR>.<MINOR>`
1. Push the new branch to the repo (with no commits).

### If releasing the first release candidate in a series

1. Create a new CHANGELOG.md heading `<VERSION>`

### For all release candidates

1. Use `scripts/harvest-changelog <PREVIOUS>..` to collect the changelog entries
   from pull request commit messages and merge them into the manually maintained
   `CHANGELOG.md`.
1. Check that `CHANGELOG.md` is well formatted, ordered in areas, covers all
   significant changes, and sub-ordered approximately by user impact & coolness.

### For final releases

1. Merge the release candidate notes in the CHANGELOG.md if more than one, and
   update with a date, title, and name.

### For all releases

1. Update the version numbers in the respecitve Cargo.toml files.
1. Create a merge request _onto the release branch_ with the above.
1. After approval, merge the request.
1. Tag it and push the tags:
   - `VERSION=<VERSION>`
   - `git pull`
   - `git tag -a v${VERSION} -m v${VERSION}`
   - `git push --tags`
1. Confirm that the tag will show up for builds with `git describe`
1. Publish workspace with
   `cargo publish --workspace --exclude bolt-derive --exclude vls-policy-derive`
   -- you can test first with `--dry-run`
1. Update the /topic on #vls-dev.
1. Prepare draft release notes, and share with team for editing.
1. Update any VLS references in other repos such as VLS Containers or the CLN/VLS test suite.

### Post-final release

1. Send a mail to lightning-dev mailing list, using the same wording as the
   Release Notes.
1. Close out the Milestone for the now-shipped release.
1. Update this file with any missing or changed instructions.

## Notes

These have separate release cycles and should be published first if they
changed:

- `cargo publish -p bolt-derive`
- `cargo publish -p vls-policy-derive`
- `(cd lightning-storage-server && cargo publish)`

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
