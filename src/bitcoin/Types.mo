/// Shared Bitcoin types and constants.
///
/// ```motoko name=import
/// import Types "mo:bitcoin/bitcoin/Types";
/// ```

module {
  // A single unit of Bitcoin.
  /// Bitcoin amount denominated in satoshis (`1 BTC = 100_000_000`).
  public type Satoshi = Nat64;

  /// Fee rate denominated in millisatoshis per byte.
  public type MillisatoshiPerByte = Nat64;

  /// A Bitcoin block hash (32 bytes).
  public type BlockHash = Blob;

  /// A raw serialised Bitcoin block header (80 bytes).
  public type BlockHeader = Blob;

  /// A Bitcoin block height (block number counted from the genesis block).
  public type BlockHeight = Nat32;

  /// A Bitcoin address string (e.g. a P2PKH, P2WPKH, or P2TR address).
  /// Distinct from the local `Address` variant which encodes the address type.
  public type BitcoinAddress = Text;

  // The type of Bitcoin network.
  /// Supported Bitcoin networks.
  public type Network = {
    #mainnet;
    #regtest;
    #testnet;
  };

  // A reference to a transaction output.
  /// Outpoint identifying a previous transaction output.
  ///
  /// `txid` is the 32-byte transaction hash in **serialization byte order**
  /// (the internal little-endian-ish order used inside transactions and
  /// block headers). This is the **reverse** of the byte order used in
  /// block explorers and JSON-RPC output — reverse the bytes before
  /// displaying or comparing against a user-supplied txid string.
  /// `vout` is the zero-based output index within that transaction.
  public type OutPoint = {
    txid : Blob;
    vout : Nat32;
  };

  // An unspent transaction output.
  /// Unspent transaction output (UTXO) data.
  ///
  /// `outpoint` references the funding transaction's output.
  /// `value` is the amount locked in the output, in satoshis.
  /// `height` is the block height at which the funding transaction was
  /// confirmed (`0` for unconfirmed UTXOs supplied by the caller).
  public type Utxo = {
    outpoint : OutPoint;
    value : Satoshi;
    height : Nat32;
  };

  /// Signature hash type bitfield.
  ///
  /// Combine the base mode (`SIGHASH_ALL`, `SIGHASH_NONE`,
  /// `SIGHASH_SINGLE`) with the optional `SIGHASH_ANYONECANPAY` flag
  /// using `or`. Encoded as the trailing byte appended to a DER signature.
  public type SighashType = Nat32;
  /// Sign all inputs and all outputs (the default).
  public let SIGHASH_ALL : SighashType = 0x01;
  /// Sign all inputs and no outputs.
  public let SIGHASH_NONE : SighashType = 0x02;
  /// Sign all inputs and only the output at the same index as the input.
  public let SIGHASH_SINGLE : SighashType = 0x03;
  /// OR-combine with one of the above to sign only the input being signed,
  /// allowing other inputs to be added or removed without invalidating it.
  public let SIGHASH_ANYONECANPAY : SighashType = 0x80;

  /// Decoded Bitcoin private key metadata.
  ///
  /// `network` is the network the WIF/key is for.
  /// `key` is the raw 256-bit secret scalar interpreted as a `Nat`
  ///   (must be in `[1, secp256k1_order)`).
  /// `compressedPublicKey` indicates whether the corresponding public key
  ///   should be encoded in SEC1 compressed form (33 bytes) rather than
  ///   uncompressed (65 bytes).
  public type BitcoinPrivateKey = {
    network : Network;
    key : Nat;
    compressedPublicKey : Bool;
  };

  /// Legacy Base58 P2PKH address string.
  public type P2PkhAddress = Text;
  /// SegWit v1 key-path (P2TR) address string.
  public type P2trKeyAddress = Text;
  /// SegWit v1 script-path (P2TR) address string.
  public type P2trScriptAddress = Text;

  /// Supported Bitcoin address variants.
  public type Address = {
    #p2pkh : P2PkhAddress;
    #p2tr_key : P2trKeyAddress;
    #p2tr_script : P2trScriptAddress;
  };

  // ─── Bitcoin Canister API types ───────────────────────────────────────────
  // These types mirror the official Bitcoin canister Candid exactly.
  // See: https://github.com/dfinity/bitcoin-canister/blob/master/canister/candid.did

  /// Filter used when requesting UTXOs.
  ///
  /// `#min_confirmations(n)` restricts results to UTXOs confirmed at least `n`
  /// times. `#page(token)` continues a paginated request using the opaque token
  /// returned in a previous `GetUtxosResponse`.
  public type UtxosFilter = {
    #min_confirmations : Nat32;
    #page : Blob;
  };

  /// Request type for `bitcoin_get_balance` / `bitcoin_get_balance_query`.
  public type GetBalanceRequest = {
    network : Network;
    address : BitcoinAddress;
    min_confirmations : ?Nat32;
  };

  /// Request type for `bitcoin_get_utxos` / `bitcoin_get_utxos_query`.
  public type GetUtxosRequest = {
    network : Network;
    address : BitcoinAddress;
    filter : ?UtxosFilter;
  };

  /// Response type for `bitcoin_get_utxos` / `bitcoin_get_utxos_query`.
  ///
  /// `next_page` is present when there are more UTXOs to retrieve; pass it back
  /// in a subsequent request as `filter = ?#page(token)`.
  public type GetUtxosResponse = {
    utxos : [Utxo];
    tip_block_hash : BlockHash;
    tip_height : BlockHeight;
    next_page : ?Blob;
  };

  /// Request type for `bitcoin_get_current_fee_percentiles`.
  public type GetCurrentFeePercentilesRequest = {
    network : Network;
  };

  /// Request type for `bitcoin_get_block_headers`.
  ///
  /// Retrieves raw 80-byte block headers for heights `[start_height, end_height]`.
  /// `end_height` defaults to the current chain tip when omitted.
  public type GetBlockHeadersRequest = {
    start_height : BlockHeight;
    end_height : ?BlockHeight;
    network : Network;
  };

  /// Response type for `bitcoin_get_block_headers`.
  public type GetBlockHeadersResponse = {
    tip_height : BlockHeight;
    block_headers : [BlockHeader];
  };

  /// Request type for `bitcoin_send_transaction`.
  public type SendTransactionRequest = {
    network : Network;
    transaction : Blob;
  };

  // ─── Admin / configuration types ──────────────────────────────────────────

  /// Simple enabled/disabled flag used in canister configuration.
  public type Flag = {
    #enabled;
    #disabled;
  };

  /// Fee schedule for Bitcoin canister operations (all values in cycles).
  public type Fees = {
    get_utxos_base : Nat;
    get_utxos_cycles_per_ten_instructions : Nat;
    get_utxos_maximum : Nat;
    get_balance : Nat;
    get_balance_maximum : Nat;
    get_current_fee_percentiles : Nat;
    get_current_fee_percentiles_maximum : Nat;
    send_transaction_base : Nat;
    send_transaction_per_byte : Nat;
    get_block_headers_base : Nat;
    get_block_headers_cycles_per_ten_instructions : Nat;
    get_block_headers_maximum : Nat;
  };

  /// Full configuration record returned by `get_config`.
  public type Config = {
    stability_threshold : Nat;
    network : Network;
    blocks_source : Principal;
    syncing : Flag;
    fees : Fees;
    api_access : Flag;
    disable_api_if_not_fully_synced : Flag;
    watchdog_canister : ?Principal;
    burn_cycles : Flag;
    lazily_evaluate_fee_percentiles : Flag;
  };

  /// Partial configuration record accepted by `set_config`.
  /// Only fields that are `?T` (not `null`) will be updated.
  public type SetConfigRequest = {
    stability_threshold : ?Nat;
    syncing : ?Flag;
    fees : ?Fees;
    api_access : ?Flag;
    disable_api_if_not_fully_synced : ?Flag;
    watchdog_canister : ??Principal;
    burn_cycles : ?Flag;
    lazily_evaluate_fee_percentiles : ?Flag;
  };

  /// Summary of the current blockchain state, returned by `get_blockchain_info`.
  public type BlockchainInfo = {
    height : BlockHeight;
    block_hash : BlockHash;
    timestamp : Nat32;
    difficulty : Nat;
    utxos_length : Nat64;
  };
};
