import P2pkh "./P2pkh";
import P2WPKH "./P2wpkh";
import P2WSH "./P2wsh";
import P2tr "./P2tr";
import Script "./Script";
import Segwit "../Segwit";
import Types "./Types";
import Result "mo:base/Result";
import Nat8 "mo:base/Nat8";

module {
  public func addressFromText(address : Text) : Result.Result<Types.Address, Text> {
    switch (Segwit.decode(address)) {
      case (#ok((_hrp, witnessProgram))) {
        // Successfully decoded a Bech32/Bech32m address, now check version/size
        if (witnessProgram.version == 0) {
          if (witnessProgram.program.size() == 20) {
            // Version 0, 20-byte program -> P2WPKH
            return #ok(#p2wpkh(address));
          } else if (witnessProgram.program.size() == 32) {
            // Version 0, 32-byte program -> P2WSH (Add #p2wsh variant to Types.mo first)
            return #ok(#p2wsh(address)); // Enable if #p2wsh is added
          } else {
            return #err("Invalid program size for witness version 0");
          };
        } else if (witnessProgram.version == 1) {
          if (witnessProgram.program.size() == 32) {
            // Version 1, 32-byte program -> P2TR (Taproot)
            // For now, assume key path spend as default when parsing address text
            return #ok(#p2tr_key(address));
            // TODO: Decide how to differentiate between P2TR key/script from address text alone if needed
          } else {
            return #err("Invalid program size for witness version 1");
          };
        } else {
          // Other witness versions (>= 2) are currently unassigned by BIPs
          return #err("Unsupported witness version: " # Nat8.toText(witnessProgram.version));
        };
      };
      case (_) {};
    };

    switch (P2pkh.decodeAddress(address)) {
      case (#ok _) {
        return #ok(#p2pkh(address));
      };
      case (_) {};
    };

    #err("Failed to decode address " # address);
  };

  // Obtain scriptPubKey from given address.
  public func scriptPubKey(
    address : Types.Address
  ) : Result.Result<Script.Script, Text> {
    switch (address) {
      case (#p2pkh p2pkhAddr) {
        P2pkh.makeScript(p2pkhAddr);
      };
      case (#p2wpkh p2wpkhAddr) {
        P2WPKH.makeScript(p2wpkhAddr);
      };
      case (#p2wsh p2wshAddr) {
        P2WSH.makeScript(p2wshAddr);
      };
      case (#p2tr_key p2trKeyAddr) {
        P2tr.makeScriptFromP2trKeyAddress(p2trKeyAddr);
      };
      case (_) {
        return #err "Calling scriptPubKey on an unknown address type";
      };
    };
  };

  // Check if the given addresses are equal.
  public func isEqual(
    address1 : Types.Address,
    address2 : Types.Address,
  ) : Bool {
    return switch (address1, address2) {
      case (#p2pkh address1, #p2pkh address2) {
        address1 == address2;
      };
      case (#p2wpkh addr1, #p2wpkh addr2) {
        addr1 == addr2;
      };
      case (#p2wsh addr1, #p2wsh addr2) {
        addr1 == addr2;
      };
      case (#p2tr_key address1, #p2tr_key address2) {
        address1 == address2;
      };
      case (#p2tr_script address1, #p2tr_script address2) {
        address1 == address2;
      };
      case (_) {
        false;
      };
    };
  };
};
