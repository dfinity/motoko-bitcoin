/// Bitcoin canister API bindings.
///
/// Provides the `Bitcoin` actor type matching the official Bitcoin canister
/// Candid interface, default canister IDs for each network, a `canister`
/// selector helper, and recommended cycle-cost constants.
///
/// Official Candid:
/// https://github.com/dfinity/bitcoin-canister/blob/master/canister/candid.did
///
/// ```motoko name=import
/// import Canister "mo:bitcoin/bitcoin/Canister";
/// ```

import Principal "mo:core/Principal";
import Types "Types";

module {

  // ─── Default canister IDs ─────────────────────────────────────────────────

  /// Textual canister ID of the Bitcoin integration canister on the **mainnet** ICP network.
  public let MAINNET_CANISTER_ID : Text = "ghsi2-tqaaa-aaaan-aaaca-cai";

  /// Textual canister ID of the Bitcoin integration canister used for **testnet** on the ICP network.
  public let TESTNET_CANISTER_ID : Text = "g4xu7-jiaaa-aaaan-aaaaq-cai";

  /// Textual canister ID used for **regtest** (same as testnet; used with PocketIC for local testing).
  public let REGTEST_CANISTER_ID : Text = "g4xu7-jiaaa-aaaan-aaaaq-cai";

  // ─── Actor type ───────────────────────────────────────────────────────────

  /// Actor type matching the full Bitcoin canister Candid service definition.
  ///
  /// Includes both update-call methods and query-call methods.
  /// The `network` field inside every request **must** use the lowercase
  /// variant tags (`#mainnet`, `#testnet`, `#regtest`) defined in `Types.Network`
  /// — these correspond to the lowercase Candid variant tags used by the canister.
  public type Bitcoin = actor {
    /// Returns the total balance (in satoshis) of the given Bitcoin address
    /// as an **update** call (goes through consensus).
    bitcoin_get_balance : Types.GetBalanceRequest -> async Types.Satoshi;

    /// Returns the total balance (in satoshis) of the given Bitcoin address
    /// as a **query** call (faster, does not go through consensus).
    bitcoin_get_balance_query : Types.GetBalanceRequest -> async Types.Satoshi;

    /// Returns the UTXOs of the given Bitcoin address as an **update** call.
    bitcoin_get_utxos : Types.GetUtxosRequest -> async Types.GetUtxosResponse;

    /// Returns the UTXOs of the given Bitcoin address as a **query** call.
    bitcoin_get_utxos_query : Types.GetUtxosRequest -> async Types.GetUtxosResponse;

    /// Returns the 100th-percentile fee rates (in millisatoshis per byte) seen
    /// in the last few thousand confirmed transactions.
    bitcoin_get_current_fee_percentiles : Types.GetCurrentFeePercentilesRequest -> async [Types.MillisatoshiPerByte];

    /// Returns raw 80-byte block headers for the requested height range.
    bitcoin_get_block_headers : Types.GetBlockHeadersRequest -> async Types.GetBlockHeadersResponse;

    /// Submits a signed Bitcoin transaction to the Bitcoin network.
    bitcoin_send_transaction : Types.SendTransactionRequest -> async ();

    /// Returns the current canister configuration as a **query** call.
    get_config : () -> async Types.Config;

    /// Updates canister configuration fields (admin only).
    set_config : Types.SetConfigRequest -> async ();

    /// Returns current blockchain state (tip height, tip hash, etc.) as a **query** call.
    get_blockchain_info : () -> async Types.BlockchainInfo;
  };

  // ─── Canister selector ────────────────────────────────────────────────────

  /// Returns the Bitcoin canister actor for the given `network`.
  ///
  /// Pass a `?Principal` override to target a custom deployment (e.g. a local
  /// PocketIC instance with a different canister ID) instead of the default.
  ///
  /// Example — get the mainnet canister:
  /// ```motoko
  /// let btc = Canister.canister(#mainnet, null);
  /// let balance = await btc.bitcoin_get_balance({ network = #mainnet; address = "bc1q..."; min_confirmations = null });
  /// ```
  ///
  /// Example — target a custom local deployment:
  /// ```motoko
  /// let customId = Principal.fromText("bkyz2-fmaaa-aaaaa-qaaaq-cai");
  /// let btc = Canister.canister(#regtest, ?customId);
  /// ```
  public func canister(network : Types.Network, override_id : ?Principal) : Bitcoin {
    let id : Text = switch (override_id) {
      case (?p) Principal.toText(p);
      case null switch network {
        case (#mainnet) MAINNET_CANISTER_ID;
        case (#testnet) TESTNET_CANISTER_ID;
        case (#regtest) REGTEST_CANISTER_ID;
      };
    };
    actor (id) : Bitcoin;
  };

  // ─── Cycle cost constants ─────────────────────────────────────────────────
  // Values are the *base* cycle costs charged by the canister on the
  // respective network.  Actual costs may vary; always check the current
  // canister fees via `get_config` for production code.
  //
  // Sources:
  //   https://internetcomputer.org/docs/build-on-btc
  //   https://github.com/dfinity/bitcoin-canister (fees record in candid.did)

  // Testnet / regtest costs ──────────────────────────────────────────────────

  /// Base cycle cost for `bitcoin_get_balance` on testnet/regtest.
  public let GET_BALANCE_COST_CYCLES : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_get_utxos` on testnet/regtest.
  public let GET_UTXOS_COST_CYCLES : Nat = 4_000_000_000;

  /// Base cycle cost for `bitcoin_get_current_fee_percentiles` on testnet/regtest.
  public let GET_CURRENT_FEE_PERCENTILES_COST_CYCLES : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_get_block_headers` on testnet/regtest.
  public let GET_BLOCK_HEADERS_COST_CYCLES : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_send_transaction` on testnet/regtest (excluding per-byte fee).
  public let SEND_TRANSACTION_BASE_COST_CYCLES : Nat = 5_000_000_000;

  /// Per-byte cycle cost for `bitcoin_send_transaction` on testnet/regtest.
  public let SEND_TRANSACTION_COST_CYCLES_PER_BYTE : Nat = 20_000_000;

  // Mainnet costs ────────────────────────────────────────────────────────────

  /// Base cycle cost for `bitcoin_get_balance` on mainnet.
  public let GET_BALANCE_COST_CYCLES_MAINNET : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_get_utxos` on mainnet.
  public let GET_UTXOS_COST_CYCLES_MAINNET : Nat = 10_000_000_000;

  /// Base cycle cost for `bitcoin_get_current_fee_percentiles` on mainnet.
  public let GET_CURRENT_FEE_PERCENTILES_COST_CYCLES_MAINNET : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_get_block_headers` on mainnet.
  public let GET_BLOCK_HEADERS_COST_CYCLES_MAINNET : Nat = 100_000_000;

  /// Base cycle cost for `bitcoin_send_transaction` on mainnet (excluding per-byte fee).
  public let SEND_TRANSACTION_BASE_COST_CYCLES_MAINNET : Nat = 5_000_000_000;

  /// Per-byte cycle cost for `bitcoin_send_transaction` on mainnet.
  public let SEND_TRANSACTION_COST_CYCLES_PER_BYTE_MAINNET : Nat = 20_000_000;

  // ─── Cycle cost helper ────────────────────────────────────────────────────

  /// Supported Bitcoin canister operations (for use with `cycleCost`).
  public type Operation = {
    #get_balance;
    #get_utxos;
    #get_current_fee_percentiles;
    #get_block_headers;
    /// `tx_size_bytes` is the serialised transaction size in bytes.
    #send_transaction : { tx_size_bytes : Nat };
  };

  /// Returns the recommended cycle amount to attach when calling the given
  /// `operation` on the given `network`.
  ///
  /// For `#send_transaction` the cost is `base + per_byte * tx_size_bytes`.
  ///
  /// Example:
  /// ```motoko
  /// let cycles = Canister.cycleCost(#mainnet, #get_utxos);
  /// // attach `cycles` when calling bitcoin_get_utxos
  /// ```
  public func cycleCost(network : Types.Network, operation : Operation) : Nat {
    switch network {
      case (#mainnet) switch operation {
        case (#get_balance) GET_BALANCE_COST_CYCLES_MAINNET;
        case (#get_utxos) GET_UTXOS_COST_CYCLES_MAINNET;
        case (#get_current_fee_percentiles) GET_CURRENT_FEE_PERCENTILES_COST_CYCLES_MAINNET;
        case (#get_block_headers) GET_BLOCK_HEADERS_COST_CYCLES_MAINNET;
        case (#send_transaction { tx_size_bytes }) {
          SEND_TRANSACTION_BASE_COST_CYCLES_MAINNET + SEND_TRANSACTION_COST_CYCLES_PER_BYTE_MAINNET * tx_size_bytes;
        };
      };
      case (#testnet or #regtest) switch operation {
        case (#get_balance) GET_BALANCE_COST_CYCLES;
        case (#get_utxos) GET_UTXOS_COST_CYCLES;
        case (#get_current_fee_percentiles) GET_CURRENT_FEE_PERCENTILES_COST_CYCLES;
        case (#get_block_headers) GET_BLOCK_HEADERS_COST_CYCLES;
        case (#send_transaction { tx_size_bytes }) {
          SEND_TRANSACTION_BASE_COST_CYCLES + SEND_TRANSACTION_COST_CYCLES_PER_BYTE * tx_size_bytes;
        };
      };
    };
  };

};
