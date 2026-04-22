# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-22

### Changed

- Optimize (de)serializations in `Bech32`, `Base58`, `Segwit`.
- **Breaking:** Add length assertions inside `Bech32.encode()`.
- Migrate code from `base` to `core`.

### Removed

- **Breaking:** Remove redundant `toBytes` function in `bitcoin/TxOutput.mo` (use class method instead).

### Fixed

- Taproot sighash now uses actual transaction values instead of hardcoded `locktime=0` and `version=2` ([#14](https://github.com/dfinity/motoko-bitcoin/issues/14)).
- **Breaking:** Lowercase character range in `Bech32.mo` was incorrect ([#13](https://github.com/dfinity/motoko-bitcoin/issues/13)).
- **Breaking:** Reject BIP32 paths with double-slashes in `Bip32.mo`.

## [0.1.1]

### Added

- Add `CODEOWNERS`.

### Changed

- Update dependencies: `base`.

### Fixed

- Fix tests and formatting.
