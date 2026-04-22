import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat8 "mo:core/Nat8";
import { type Result } "mo:core/Types";
import VarArray "mo:core/VarArray";

import Bech32 "Bech32";

module {

  public type WitnessProgram = {
    version : Nat8;
    program : [Nat8];
  };

  // Convert a Witness Program to a SegWit Address.
  public func encode(hrp : Text, { version; program } : WitnessProgram) : Result<Text, Text> {

    let converted = switch (convertBits(program, 0, 8, 5, true)) {
      case (#err(msg)) return #err(msg);
      case (#ok(c)) c;
    };

    let encoding : Bech32.Encoding = if (version > 0) {
      #BECH32M;
    } else {
      #BECH32;
    };

    let bech32Result : Text = Bech32.encode(
      hrp,
      [[version] : [Nat8], converted].flatten(),
      encoding,
    );

    return switch (decode(bech32Result)) {
      case (#ok((decodedHrp, _))) {
        // if the following fails, then there is a bug in decoding
        assert hrp == decodedHrp;
        #ok(bech32Result);
      };
      case (#err(msg)) {
        #err(msg);
      };
    };
  };

  // Convert a segwit address into a numan-readable part (HRP) and a Witness Program.
  // Decodes using Bech32.
  public func decode(address : Text) : Result<(Text, WitnessProgram), Text> {
    let (encoding, decodedHrp, data) = switch (Bech32.decode(address)) {
      case (#ok res) {
        res;
      };
      case (#err msg) {
        return #err(msg);
      };
    };

    if (data.size() == 0 or data.size() > 65) {
      return #err("Invalid data length.");
    };

    let version : Nat8 = data[0];

    if (version > 16) {
      return #err("Invalid witness version.");
    };

    let convertedData = switch (convertBits(data, 1, 5, 8, false)) {
      case (#err(msg)) return #err(msg);
      case (#ok(d)) d;
    };

    let convertedDataSize : Nat = convertedData.size();

    if (convertedDataSize < 2 or convertedDataSize > 40) {
      return #err("Wrong output size.");
    };

    if (
      version == 0 and convertedDataSize != 20 and convertedDataSize != 32
    ) {
      return #err("Program size does not match witness version.");
    };

    if (
      version == 0 and encoding != #BECH32 or
      version != 0 and encoding != #BECH32M
    ) {
      return #err("Encoding does not match witness version.");
    };

    #ok(decodedHrp, { version; program = convertedData });
  };

  // Convert between two bases that are power of 2.
  func convertBits(
    data : [Nat8],
    start : Nat,
    from : Nat32,
    to : Nat32,
    pad : Bool,
  ) : Result<[Nat8], Text> {

    var acc : Nat32 = 0;
    var bits : Nat32 = 0;
    let maxv : Nat32 = (1 << to) - 1;
    let dataSize = data.size();
    let output = VarArray.repeat<Nat8>(0, (dataSize - start) * from.toNat() / to.toNat() + 1);
    var outputLen : Nat = 0;

    var pos = start;
    while (pos < dataSize) {
      let v : Nat32 = data[pos].toNat16().toNat32();

      if ((v >> from) != 0) {
        return #err("Invalid input value: " # data[pos].toNat().toText());
      };

      acc := (acc << from) | v;
      bits += from;

      while (bits >= to) {
        bits -= to;
        output[outputLen] := ((acc >> bits) & maxv).toNat16().toNat8();
        outputLen += 1;
      };
      pos += 1;
    };

    if (pad) {
      if (bits > 0) {
        output[outputLen] := ((acc << (to - bits)) & maxv).toNat16().toNat8();
        outputLen += 1;
      };
    } else if (bits >= from or ((acc << (to - bits)) & maxv) != 0) {
      return #err("Invalid Padding");
    };

    #ok(Array.tabulate<Nat8>(outputLen, func(i) = output[i]));
  };
};
