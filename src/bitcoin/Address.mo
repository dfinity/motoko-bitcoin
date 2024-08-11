import P2pkh "./P2pkh";
import P2tr "./P2tr";
import Script "./Script";
import Segwit "../Segwit";
import Types "./Types";
import Result "mo:base/Result";

module {
  public func addressFromText(address : Text) : Result.Result<Types.Address, Text> {
    switch (Segwit.decode(address)) {
      case (#ok _) {
        return #ok(#p2tr_key(address));
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
    return switch (address) {
      case (#p2pkh p2pkhAddr) {
        return P2pkh.makeScript(p2pkhAddr);
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
