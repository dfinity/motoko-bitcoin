# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-14

### Changed

- Migrate code from `base` to `core`.
- **Breaking:** Add length assertions inside `Bech32.encode()`.

### Removed

- **Breaking:** Remove redundant `toBytes` function in `bitcoin/TxOutput.mo` (use class method instead).

### Fixed

- Lowercase character range in `Bech32.mo` was incorrect.

## [0.1.1]

### Added

- Add `CODEOWNERS`.

### Changed

- Update dependencies: `base`.

### Fixed

- Fix tests and formatting.
