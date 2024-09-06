import Ecdsa "../ecdsa/Ecdsa";
import Hash "../Hash";
import Result "mo:base/Result";
import Array "mo:base/Array";
import Nat "mo:base/Nat";
import Script "./Script";
import Segwit "../Segwit";
import Types "./Types";

module {
    type PublicKey = Ecdsa.PublicKey;
    type Script = Script.Script;

    public type P2trKeyAddress = Types.P2trKeyAddress;
    public type DecodedAddress = {
        network : Types.Network;
        publicKeyHash : [Nat8];
    };

    // Create script for the given P2TR key spend address.
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
};
