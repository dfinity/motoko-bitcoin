# AGENTS.md

Motoko library (`mops` package `bitcoin`) providing algorithms for Bitcoin integration.

## Prerequisites

- Uses the [`mops`](https://docs.mops.one/quick-start) package manager for Motoko.
- Install dependencies before building or testing: `mops install`.
- The Motoko compiler is pinned to `moc` 1.11.0 in `mops.toml` (`[toolchain]`); minimum supported is 1.4.0. Install/select it with `mops toolchain use moc <version>`.

## Test

- Run tests: `mops test`.
- To run in the WASI interpreter: `mops test --mode wasi`.

## Benchmarks

- Run benchmarks: `mops bench`. Benchmark suites live in `bench/`.

## Format

- Formatting uses Prettier with `prettier-plugin-motoko` (config in `.prettierrc`).
- CI checks formatting and fails if it does not pass. Reproduce locally:
  ```sh
  npm install --save-dev prettier prettier-plugin-motoko
  npx prettier --check --plugin=prettier-plugin-motoko **/*.mo
  ```

## Layout

- `src/` — library modules; subdirectories `ec/` (elliptic curve), `ecdsa/`, and `bitcoin/`.
- `test/` — test files (`*.test.mo`) plus shared helpers (`TestUtils.mo`, `Hex.mo`).
- `bench/` — performance benchmarks (`*.bench.mo`).

## Conventions

- Test files are named `*.mo` and, for suites, `*.test.mo`; the format CI job matches `**/*.mo`.
- Do not hand-edit ignored/generated paths (see `.gitignore`), including `.mops/`, `test/.vessel/`, `test/_out/`, `mops.lock`, and `node_modules/`.
