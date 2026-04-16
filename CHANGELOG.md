# Motoko `bitcoin` changelog

## 1.0.0

* Bugfix: Taproot sighash now uses actual transaction values instead of hardcoded locktime=0 and version=2 (#14)
* Migrate code from `base` to `core`
* *Breaking:* Remove `toBytes` function in `bitcoin/TxOutput.mo` (use class method instead)
* *Breaking:* Add length assertions inside `Bech32.encode()`
* *Breaking*: Lowercase character range in `Bech32.mo` was incorrect (bugfix)
* *Breaking:* Reject BIP32 paths with double-slashes in `Bip32.mo` (bugfix)

## 0.1.1

* Fix tests and formatting.
* Add `CODEOWNERS`.
* Update dependencies: `base`.