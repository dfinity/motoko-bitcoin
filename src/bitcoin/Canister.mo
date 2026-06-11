/// Bitcoin canister API bindings.
///
/// Provides the `Bitcoin` actor type matching the official Bitcoin canister
/// Candid interface, default canister IDs for each network, and a `createActor`
/// helper to obtain the appropriate actor for a given network.
///
/// **Cycle fees** are dynamically configurable by the Bitcoin canister admins.
/// Always call `get_config()` at runtime to obtain the current `Fees` record
/// rather than relying on hardcoded values.
///
/// Official Candid:
/// https://github.com/dfinity/bitcoin-canister/blob/master/canister/candid.did
///
/// Documentation:
/// https://docs.internetcomputer.org/guides/chain-fusion/bitcoin
///
/// ```motoko name=import
/// import Canister "mo:bitcoin/bitcoin/Canister";
/// ```

import Types "Types";

module {

  // ─── Default canister IDs ─────────────────────────────────────────────────

  /// Canister ID of the Bitcoin integration canister on the **mainnet** ICP network.
  public let MAINNET_CANISTER_ID : Text = "ghsi2-tqaaa-aaaan-aaaca-cai";

  /// Canister ID of the Bitcoin integration canister for **testnet** on the ICP network.
  public let TESTNET_CANISTER_ID : Text = "g4xu7-jiaaa-aaaan-aaaaq-cai";

  /// Canister ID used for **regtest** (same as testnet; used with PocketIC for local testing).
  public let REGTEST_CANISTER_ID : Text = "g4xu7-jiaaa-aaaan-aaaaq-cai";

  // ─── Actor type ───────────────────────────────────────────────────────────

  /// Actor type matching the full Bitcoin canister Candid service definition.
  ///
  /// Includes both update-call methods and query-call methods.
  /// The `network` field inside every request must use the lowercase
  /// variant tags (`#mainnet`, `#testnet`, `#regtest`) from `Types.Network`.
  public type Bitcoin = actor {
    /// Returns the balance (in satoshis) for `address` as an **update** call (goes through consensus).
    bitcoin_get_balance : Types.GetBalanceRequest -> async Types.Satoshi;

    /// Returns the balance (in satoshis) for `address` as a **query** call (faster, no consensus).
    bitcoin_get_balance_query : Types.GetBalanceRequest -> async Types.Satoshi;

    /// Returns the UTXOs of `address` as an **update** call.
    bitcoin_get_utxos : Types.GetUtxosRequest -> async Types.GetUtxosResponse;

    /// Returns the UTXOs of `address` as a **query** call.
    bitcoin_get_utxos_query : Types.GetUtxosRequest -> async Types.GetUtxosResponse;

    /// Returns the 100 fee-rate percentiles (millisatoshis per byte) from recent confirmed transactions.
    bitcoin_get_current_fee_percentiles : Types.GetCurrentFeePercentilesRequest -> async [Types.MillisatoshiPerByte];

    /// Returns raw 80-byte block headers for the requested height range.
    bitcoin_get_block_headers : Types.GetBlockHeadersRequest -> async Types.GetBlockHeadersResponse;

    /// Submits a signed Bitcoin transaction to the Bitcoin network.
    bitcoin_send_transaction : Types.SendTransactionRequest -> async ();

    /// Returns the current canister configuration (including the `Fees` record) as a **query** call.
    /// Use this to obtain the current cycle costs for each operation.
    get_config : () -> async Types.Config;

    /// Updates canister configuration fields (admin only).
    set_config : Types.SetConfigRequest -> async ();

    /// Returns current blockchain state (tip height, tip hash, timestamp, difficulty) as a **query** call.
    get_blockchain_info : () -> async Types.BlockchainInfo;
  };

  // ─── Actor creation ───────────────────────────────────────────────────────

  /// Returns a `Bitcoin` actor for the given `network` using the well-known
  /// default canister IDs.
  ///
  /// To target a custom deployment (e.g. a locally deployed Bitcoin canister
  /// with a different principal), construct the actor directly:
  /// ```motoko
  /// let btc = actor("your-canister-id") : Canister.Bitcoin;
  /// ```
  ///
  /// Example — get the testnet actor and query fees:
  /// ```motoko
  /// let btc = Canister.createActor(#testnet);
  /// let config = await btc.get_config();
  /// let getBalanceFee = config.fees.get_balance;
  /// ```
  public func createActor(network : Types.Network) : Bitcoin {
    let id : Text = switch network {
      case (#mainnet) MAINNET_CANISTER_ID;
      case (#testnet) TESTNET_CANISTER_ID;
      case (#regtest) REGTEST_CANISTER_ID;
    };
    actor (id) : Bitcoin;
  };

};
