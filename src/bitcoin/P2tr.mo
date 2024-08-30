import Types "./Types";
import Ecdsa "../ecdsa/Ecdsa";
import Script "./Script";
import Segwit "../Segwit";
import Result "mo:base/Result";

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
};
