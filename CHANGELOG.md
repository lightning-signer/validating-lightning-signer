# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## v0.2.0 - 2023-03-14 - "Developer Preview"

### Changed

- legacy and plain anchors commitment types are now disabled by policy
- however, for CLN compatibility, `policy-channel-safe-type-anchors` can be set to warning, and it is set so for integration tests
- once CLN implements zero-fee anchors and disables this channel type, this should be set to error (issue #236)
- minimum dust threshold is now 346 satoshi instead of 330

## [unreleased]
