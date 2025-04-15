import Types "Types";
import Script "./Script";
import Segwit "../Segwit";
import EcdsaTypes "../ecdsa/Types";
import Result "mo:base/Result";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Hash "../Hash";

module {
  public type DecodedP2wpkhAddress = {
    hrp : Text;
    publicKeyHash : [Nat8];
  };

  /// Creates the scriptPubKey for a P2WPKH address (v0).
  /// The resulting script is: OP_0 PUSH_20 <20_byte_pubkey_hash>
  ///
  /// # Parameters:
  /// - `address`: The P2WPKH address in Bech32 format (e.g., "bc1q...")
  ///
  /// # Returns:
  /// `Result.Result<Script.Script, Text>` containing the Script (`#ok`) or an error message (`#err`).
  public func makeScript(address : Types.P2WPkhAddress) : Result.Result<Script.Script, Text> {
    switch (Segwit.decode(address)) {
      case (#ok((_hrp, witnessProgram))) {
        if (witnessProgram.version != 0) {
          return #err("P2WPKH.makeScript: Invalid witness version for P2WPKH (expected 0, got " # Nat8.toText(witnessProgram.version) # ")");
        };
        if (witnessProgram.program.size() != 20) {
          return #err("P2WPKH.makeScript: Invalid program size for P2WPKH (expected 20, got " # Nat.toText(witnessProgram.program.size()) # ")");
        };

        let script : Script.Script = [
          #opcode(#OP_0),
          #data(witnessProgram.program),
        ];
        #ok(script);
      };
      case (#err e) {
        #err("Internal error in P2WPKH.makeScript: Failed to re-decode valid P2WPKH address '" # address # "': " # e);
      };
    };
  };

  func getHrp(network : Types.Network) : Text {
    switch (network) {
      case (#Mainnet) { "bc" };
      case (#Testnet) { "tb" };
      case (#Regtest) { "bcrt" }; // Common HRP for Regtest Bech32
    };
  };

  /// Derives a P2WPKH (Bech32) address from an SEC1 public key.
  /// Requires the public key to be in compressed format (33 bytes).
  ///
  /// # Parameters:
  /// - `network`: The Bitcoin network (Mainnet, Testnet, Regtest).
  /// - `sec1PublicKey`: The public key in SEC1 format (pair: bytes, curve). Must be compressed.
  ///
  /// # Returns:
  /// `Result.Result<Types.P2wpkhAddress, Text>` containing the Bech32 address (`#ok`) or an error message (`#err`).
  public func deriveAddress(
    network : Types.Network,
    sec1PublicKey : EcdsaTypes.Sec1PublicKey,
  ) : Result.Result<Types.P2WPkhAddress, Text> {
    let (pkBytes, _curve) = sec1PublicKey;

    // P2WPKH REQUIRES a compressed public key
    // Assuming pkBytes.size() == 33 for compressed
    // (The library might have a helper function like PublicKey.isCompressed(pkBytes))
    if (pkBytes.size() != 33) {
      // Optional: We could try to compress it if it isn't, but requiring it is safer.
      return #err("P2WPKH requires a compressed public key (33 bytes)");
    };

    // 1. Calculate HASH160(pubkey)
    let pubKeyHash : [Nat8] = Hash.hash160(pkBytes);
    if (pubKeyHash.size() != 20) {
      return #err("Internal error: HASH160 result is not 20 bytes");
    };

    let hrp = getHrp(network);

    let witnessProgram : Segwit.WitnessProgram = {
      version = 0;
      program = pubKeyHash;
    };

    return Segwit.encode(hrp, witnessProgram);
  };

  public func decodeAddress(address : Types.P2WPkhAddress) : Result.Result<DecodedP2wpkhAddress, Text> {
    switch (Segwit.decode(address)) {
      case (#ok((hrp, witnessProgram))) {
        // P2WPKH specific validations
        if (witnessProgram.version != 0) {
          return #err("P2WPKH.decodeAddress: Invalid witness version (expected 0, got " # Nat8.toText(witnessProgram.version) # ")");
        };
        if (witnessProgram.program.size() != 20) {
          return #err("P2WPKH.decodeAddress: Invalid program size (expected 20, got " # Nat.toText(witnessProgram.program.size()) # ")");
        };
        // Validate HRP if necessary (e.g., hrp == getHrp(#Mainnet) or hrp == getHrp(#Testnet) ...)

        // Return the specific structure
        #ok({ hrp = hrp; publicKeyHash = witnessProgram.program });
      };
      case (#err e) {
        #err("P2WPKH.decodeAddress: Failed to decode Bech32 address: " # e);
      };
    };
  };

};