import Types "Types";
import Script "./Script";
import Segwit "../Segwit";
import Common "../Common";
import Result "mo:base/Result";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Debug "mo:base/Debug";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Nat16 "mo:base/Nat16";
import Nat32 "mo:base/Nat32";
import Blob "mo:base/Blob";
import Sha256 "mo:sha2/Sha256";

module {

    let opPushData1Code : Nat8 = 0x4c;
    let opPushData1Threshold : Nat = 76;
    let maxNat8 : Nat = 0xff;
    let maxNat16 : Nat = 0xffff;

    public type DecodedP2wshAddress = {
        hrp : Text;
        scriptHash : [Nat8];
    };

    func encodeOpcode(opcode : Script.Opcode) : Nat8 {
        return switch (opcode) {
            case (#OP_0) { 0x00 }; // for makeScript
            case (#OP_PUSHDATA1) { opPushData1Code }; // for raw serialization
            case (#OP_PUSHDATA2) { 0x4d }; // for raw serialization
            case (#OP_PUSHDATA4) { 0x4e }; // for raw serialization
            case _ {
                Debug.trap("P2WSH internal: Unsupported opcode in encodeOpcode local replica");
            };
        };
    };

    func serializeScriptRaw(script : Script.Script) : [Nat8] {
        let buf = Buffer.Buffer<Nat8>(script.size());

        for (instruction in script.vals()) {
            switch (instruction) {
                case (#opcode(opcode)) {
                    buf.add(encodeOpcode(opcode));
                };
                case (#data data) {
                    let dataSize = data.size();
                    if (dataSize < opPushData1Threshold) {
                        buf.add(Nat8.fromNat(dataSize));
                    } else if (dataSize <= maxNat8) {
                        buf.add(encodeOpcode(#OP_PUSHDATA1));
                        buf.add(Nat8.fromNat(dataSize));
                    } else if (dataSize <= maxNat16) {
                        buf.add(encodeOpcode(#OP_PUSHDATA2));
                        let sizeData = Array.init<Nat8>(2, 0);
                        Common.writeLE16(sizeData, 0, Nat16.fromNat(dataSize));
                        for (byte in sizeData.vals()) { buf.add(byte) };
                    } else {
                        buf.add(encodeOpcode(#OP_PUSHDATA4));
                        let sizeData = Array.init<Nat8>(4, 0);
                        Common.writeLE32(sizeData, 0, Nat32.fromNat(dataSize));
                        for (byte in sizeData.vals()) { buf.add(byte) };
                    };
                    for (byte in data.vals()) {
                        buf.add(byte);
                    };
                };
            };
        };
        return Buffer.toArray(buf);
    };

    /// Creates the scriptPubKey for a P2WSH address (v0).
    /// The resulting script is:  OP_0 PUSH_32 <32_byte_script_hash>
    ///
    /// # Parameters:
    /// - `address`: The P2WSH address in Bech32 format (e.g., "bc1q...")
    ///
    /// # Returns:
    /// `Result.Result<Script.Script, Text>` containing the Script (`#ok`) or an error message (`#err`).
    public func makeScript(address : Types.P2WShAddress) : Result.Result<Script.Script, Text> {
        switch (Segwit.decode(address)) {
            case (#ok((_hrp, witnessProgram))) {
                if (witnessProgram.version != 0) {
                    return #err("P2WSH.makeScript: Invalid witness version for P2WSH (expected 0, got " # Nat8.toText(witnessProgram.version) # ")");
                };
                if (witnessProgram.program.size() != 32) {
                    return #err("P2WSH.makeScript: Invalid program size for P2WSH (expected 32, got " # Nat.toText(witnessProgram.program.size()) # ")");
                };

                let script : Script.Script = [
                    #opcode(#OP_0),
                    #data(witnessProgram.program),
                ];
                #ok(script);
            };
            case (#err e) {
                #err("Internal error in P2WSH.makeScript: Failed to re-decode valid P2WSH address '" # address # "': " # e);
            };
        };
    };

    func getHrp(network : Types.Network) : Text {
        switch (network) {
            case (#Mainnet) { "bc" };
            case (#Testnet) { "tb" };
            case (#Regtest) { "bcrt" };
        };
    };

    /// Derivate a P2WSH address (Bech32) from a witness script.
    ///
    /// # Parameters:
    /// - `network`: Bitcoin network (Mainnet, Testnet, Regtest).
    /// - `witnessScript`: the script (as `Script.Script`) wich hash SHA256 will be used.
    ///
    /// # Returns:
    /// `Result.Result<Types.P2wshAddress, Text>` contains the Bech32 address (`#ok`) or an error message (`#err`).
    public func deriveAddress(
        network : Types.Network,
        witnessScript : Script.Script
    ) : Result.Result<Types.P2WShAddress, Text> {

        let rawScriptBytes = serializeScriptRaw(witnessScript);

        let scriptHashBlob = Sha256.fromArray(#sha256, rawScriptBytes);
        let scriptHash = Blob.toArray(scriptHashBlob);

        if (scriptHash.size() != 32) {
            return #err("Internal error: SHA256 result is not 32 bytes");
        };

        let hrp = getHrp(network);

        let witnessProgram : Segwit.WitnessProgram = {
            version = 0;
            program = scriptHash;
        };

        return Segwit.encode(hrp, witnessProgram);
    };

    public func decodeAddress(address : Types.P2WShAddress) : Result.Result<DecodedP2wshAddress, Text> {
        switch (Segwit.decode(address)) {
            case (#ok((hrp, witnessProgram))) {
                if (witnessProgram.version != 0) {
                    return #err("P2WSH.decodeAddress: Invalid witness version (expected 0, got " # Nat8.toText(witnessProgram.version) # ")");
                };
                if (witnessProgram.program.size() != 32) {
                    return #err("P2WSH.decodeAddress: Invalid program size (expected 32, got " # Nat.toText(witnessProgram.program.size()) # ")");
                };

                #ok({ hrp = hrp; scriptHash = witnessProgram.program });
            };
            case (#err e) {
                #err("P2WSH.decodeAddress: Failed to decode Bech32 address: " # e);
            };
        };
    };

};
