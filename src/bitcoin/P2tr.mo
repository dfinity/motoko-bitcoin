import Common "../Common";
import Curves "../ec/Curves";
import Fp "../ec/Fp";
import Hash "../Hash";
import Result "mo:base/Result";
import Array "mo:base/Array";
import Nat "mo:base/Nat";
import Script "./Script";
import Segwit "../Segwit";
import Types "./Types";
import Jacobi "../ec/Jacobi";

module {
  type PublicKey = {
    bip340_public_key : [Nat8];
    is_even : Bool;
  };
  type Script = Script.Script;

  public type P2trKeyAddress = Types.P2trKeyAddress;
  public type DecodedAddress = {
    network : Types.Network;
    publicKeyHash : [Nat8];
  };

  /// Create script for the given P2TR key spend address (see
  /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
  /// for more details).
  public func makeScriptFromP2trKeyAddress(address : P2trKeyAddress) : Result.Result<Script, Text> {
    return switch (Segwit.decode(address)) {
      case (#ok(_, { version = _; program })) {
        #ok([
          #opcode(#OP_1),
          // #opcode(#OP_PUSHBYTES_32) is implicit and added by the
          // #data below
          #data(program),
        ]);
      };
      case (#err msg) {
        #err msg;
      };
    };
  };

  // Create script for the given P2TR key spend address.
  public func leafScript(bip340_spender_public_key : [Nat8]) : Result.Result<Script, Text> {
    if (bip340_spender_public_key.size() != 32) {
      return #err("Invalid BIP-340 public key length: expected 32 but got " # Nat.toText(bip340_spender_public_key.size()));
    };
    #ok([
      // #opcode(#OP_PUSHBYTES_32) is implicit and added by the
      // #data below
      #data(bip340_spender_public_key),
      #opcode(#OP_CHECKSIG),
    ]);
  };

  public func leafHash(leaf_script : Script.Script) : [Nat8] {
    // BIP-342 tapscript
    let TAPROOT_LEAF_TAPSCRIPT : [Nat8] = [0xc0];
    let script_bytes = Script.toBytes(leaf_script);
    Hash.taggedHash(Array.flatten([TAPROOT_LEAF_TAPSCRIPT, script_bytes]), "TapLeaf");
  };

  /// Computes a tweak from the internal key and a hash. Corresponds to
  /// ```python
  ///     t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
  ///     if t >= SECP256K1_ORDER:
  ///         raise ValueError
  /// ```
  /// in `taproot_tweak_pubkey` function in
  /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
  public func tweakFromKeyAndHash(internal_key : [Nat8], hash : [Nat8]) : Result.Result<Fp.Fp, Text> {
    if (internal_key.size() != 32) {
      return #err("Failed to compute tweak, invalid internal key length: expected 32 but got " # Nat.toText(internal_key.size()));
    } else if (hash.size() != 32) {
      return #err("Failed to compute tweak, invalid hash length: expected 32 but got " # Nat.toText(hash.size()));
    };

    let tagged_hash = Hash.taggedHash(Array.flatten([internal_key, hash]), "TapTweak");

    let tweak = Common.readBE256(tagged_hash, 0);

    if (tweak >= Curves.secp256k1.p) {
      return #err("Failed to compute tweak, tweak is not smaller than the curve order");
    };

    #ok(Curves.secp256k1.Fp(tweak));
  };

  /// Corresponds to
  /// ```python
  ///     P = lift_x(int_from_bytes(pubkey))
  ///     if P is None:
  ///         raise ValueError
  ///     Q = point_add(P, point_mul(G, t))
  ///     return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))
  /// ```
  /// `taproot_tweak_pubkey` function in
  /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
  public func tweakPublicKey(public_key_bip340_bytes : [Nat8], tweak : Fp.Fp) : Result.Result<PublicKey, Text> {
    let even_point_flag : [Nat8] = [0x02];
    let public_key_sec1_bytes = Array.flatten([even_point_flag, public_key_bip340_bytes]);
    let public_key_point = switch (Jacobi.fromBytes(public_key_sec1_bytes, Curves.secp256k1)) {
      case (?point) {
        switch (point) {
          case (#infinity _) {
            return #err("Failed to tweak public key, invalid public key");
          };
          case (_) {};
        };
        point;
      };
      case (null) {
        return #err("Failed to tweak public key, invalid public key");
      };
    };

    let tweak_point = Jacobi.mulBase(tweak.value, Curves.secp256k1);

    let tweaked_public_key = Jacobi.add(public_key_point, tweak_point);

    if (not Jacobi.isOnCurve(tweaked_public_key) or Jacobi.isInfinity(tweaked_public_key)) {
      return #err("Tweaking produced an invalid public key");
    };

    let tweaked_public_key_sec1_bytes = Jacobi.toBytes(tweaked_public_key, true);
    #ok({
      bip340_public_key = Array.subArray(tweaked_public_key_sec1_bytes, 1, 32);
      is_even = tweaked_public_key_sec1_bytes[0] == 0x02;
    });
  };
};
