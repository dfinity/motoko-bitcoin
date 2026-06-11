[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/bitcoin)](https://mops.one/bitcoin)
[![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/bitcoin)](https://mops.one/bitcoin/docs)

# mo:bitcoin — Bitcoin for Motoko

Motoko library for Bitcoin integration on the Internet Computer. Provides:

- **Bitcoin canister API bindings** — typed actor for `bitcoin_get_balance`, `bitcoin_get_utxos`, `bitcoin_send_transaction`, and more
- **Address generation** — P2PKH, P2TR (key-path and script-path), and P2WPKH (SegWit v0)
- **Transaction building and signing** — construct and sign Bitcoin transactions using ECDSA/Schnorr threshold keys
- **Cryptographic primitives** — ECDSA, BIP32, Base58, Bech32, RIPEMD160, HMAC, Segwit

Requires the [`mops`](https://docs.mops.one/quick-start) package manager.

```
mops add bitcoin
```

See the [Internet Computer Bitcoin integration docs](https://docs.internetcomputer.org/guides/chain-fusion/bitcoin) for background.

---

## Bitcoin Canister API

The `Canister` module provides a typed actor for the [official Bitcoin canister](https://github.com/dfinity/bitcoin-canister) and helpers for creating the right actor per network.

### Quick start

```motoko
import Canister "mo:bitcoin/bitcoin/Canister";
import Types "mo:bitcoin/bitcoin/Types";

// Get the Bitcoin canister actor for testnet
let btc = Canister.createActor(#testnet);

// Check the current fee schedule before making calls
let config = await btc.get_config();
let getBalanceFee = config.fees.get_balance;

// Query balance (update call — goes through consensus)
let balance : Types.Satoshi = await (with cycles = getBalanceFee) btc.bitcoin_get_balance({
  network = #testnet;
  address = "tb1q...";
  min_confirmations = null;
});

// Query balance (query call — faster, no consensus)
let balance2 : Types.Satoshi = await btc.bitcoin_get_balance_query({
  network = #testnet;
  address = "tb1q...";
  min_confirmations = null;
});
```

### Default canister IDs

| Network | Canister ID |
|---------|-------------|
| Mainnet | `ghsi2-tqaaa-aaaan-aaaca-cai` |
| Testnet | `g4xu7-jiaaa-aaaan-aaaaq-cai` |
| Regtest (local PocketIC) | `g4xu7-jiaaa-aaaan-aaaaq-cai` |

To target a custom deployment, construct the actor directly:
```motoko
let btc = actor("your-canister-id") : Canister.Bitcoin;
```

### Cycle costs

Cycle costs are **dynamically configurable** by the Bitcoin canister admins. Always call `get_config()` at runtime to get the current `Fees` record rather than relying on hardcoded values:

```motoko
let config = await btc.get_config();
// config.fees contains: get_balance, get_utxos_base, send_transaction_base, ...
```

### Available API methods

| Method | Type | Description |
|--------|------|-------------|
| `bitcoin_get_balance` | update | Balance for an address (consensus) |
| `bitcoin_get_balance_query` | query | Balance for an address (fast, no consensus) |
| `bitcoin_get_utxos` | update | UTXOs for an address (consensus) |
| `bitcoin_get_utxos_query` | query | UTXOs for an address (fast, no consensus) |
| `bitcoin_get_current_fee_percentiles` | update | Fee rate percentiles from recent txs |
| `bitcoin_get_block_headers` | update | Raw block headers for a height range |
| `bitcoin_send_transaction` | update | Submit a signed transaction |
| `get_config` | query | Current canister config (including `Fees`) |
| `get_blockchain_info` | query | Tip height, hash, timestamp, difficulty |

---

## Address Generation

```motoko
import P2pkh "mo:bitcoin/bitcoin/P2pkh";
import P2tr "mo:bitcoin/bitcoin/P2tr";
import Types "mo:bitcoin/bitcoin/Types";

// P2PKH address (Legacy)
let address : Text = switch (P2pkh.deriveAddress(Types.network_to_network_camel_case(#testnet), publicKey)) {
  case (#ok(addr)) addr;
  case (#err(e)) Runtime.trap(e);
};

// P2TR address (Taproot)
// See src/bitcoin/P2tr.mo for full API
```

---

## Low-level utilities

<details>
<summary>Base58, HMAC, RIPEMD160, EC, BIP32, Bech32, Segwit</summary>

**Base58:**
```motoko
import Base58 "mo:bitcoin/Base58";
let encoded : Text = Base58.encode([/* Nat8 data */]);
```

**Base58Check:**
```motoko
import Base58Check "mo:bitcoin/Base58Check";
let encoded : Text = Base58Check.encode([/* Nat8 data */]);
```

**HMAC:**
```motoko
import Hmac "mo:bitcoin/Hmac";
let hmac : Hmac.Hmac = Hmac.sha256(key);
hmac.write([/* data */]);
let result : [Nat8] = hmac.sum();
```

**RIPEMD160:**
```motoko
import Ripemd160 "mo:bitcoin/Ripemd160";
let digest : Ripemd160.Digest = Ripemd160.Digest();
digest.write([/* data */]);
let result : [Nat8] = digest.sum();
```

**EC (secp256k1):**
```motoko
import Jacobi "mo:bitcoin/ec/Jacobi";
import Curves "mo:bitcoin/ec/Curves";
let point = Jacobi.mulBase(1234, Curves.secp256k1);
```

**BIP32:**
```motoko
import Bip32 "mo:bitcoin/Bip32";
let rootKey = Bip32.parse("xpub...", null);
```

**Bech32:**
```motoko
import Bech32 "mo:bitcoin/Bech32";
Bech32.encode("bc", [/* data */], #BECH32);
```

**Segwit:**
```motoko
import Segwit "mo:bitcoin/Segwit";
Segwit.encode("bc", /* WitnessProgram */);
```

</details>

---

## Testing

```sh
mops test --mode wasi
```

## Benchmarks

```sh
mops bench
```

Benchmark files in `bench/` cover: Base58/Base58Check/Bech32, hashing and HMAC, BIP32, EC arithmetic, ECDSA verification, and Bitcoin transaction building.
