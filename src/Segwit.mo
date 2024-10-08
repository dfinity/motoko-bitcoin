import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import P "mo:base/Prelude";
import Bech32 "../src/Bech32";

module {

  public type WitnessProgram = {
    version : Nat8;
    program : [Nat8];
  };

  // Convert a Witness Program to a SegWit Address.
  public func encode(hrp : Text, { version; program } : WitnessProgram) : Result.Result<Text, Text> {

    let bech32Input = Buffer.Buffer<Nat8>(program.size());
    bech32Input.add(version);

    switch (convertBits(program.vals(), bech32Input, 8, 5, true)) {
      case (#err(msg)) {
        return #err(msg);
      };
      case _ {};
    };

    let encoding : Bech32.Encoding = if (version > 0) {
      #BECH32M;
    } else {
      #BECH32;
    };

    let bech32Result : Text = Bech32.encode(
      hrp,
      Buffer.toArray(bech32Input),
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
  public func decode(address : Text) : Result.Result<(Text, WitnessProgram), Text> {
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

    // Split into version and program.
    let dataIter : Iter.Iter<Nat8> = data.vals();
    let version : Nat8 = switch (dataIter.next()) {
      case (?val) {
        val;
      };
      case _ {
        P.unreachable();
      };
    };

    let convertedData = Buffer.Buffer<Nat8>(0);
    switch (convertBits(dataIter, convertedData, 5, 8, false)) {
      case (#ok) {
        let convertedDataSize : Nat = convertedData.size();

        if (convertedDataSize < 2 or convertedDataSize > 40) {
          return #err("Wrong output size.");
        };

        if (data[0] > 16) {
          return #err("Invalid witness version.");
        };

        if (
          data[0] == 0 and convertedDataSize != 20 and convertedDataSize != 32
        ) {
          return #err("Program size does not match witness version.");
        };

        if (
          data[0] == 0 and encoding != #BECH32 or
          data[0] != 0 and encoding != #BECH32M
        ) {
          return #err("Encoding does not match witness version.");
        };

        return #ok(decodedHrp, { version; program = Buffer.toArray(convertedData) });
      };
      case _ {
        return #err("Convert bits failed.");
      };
    };
  };

  // Convert between two bases that are power of 2.
  func convertBits(
    data : Iter.Iter<Nat8>,
    output : Buffer.Buffer<Nat8>,
    from : Nat32,
    to : Nat32,
    pad : Bool,
  ) : Result.Result<(), Text> {

    var acc : Nat32 = 0;
    var bits : Nat32 = 0;
    var maxv : Nat32 = (1 << to) - 1;

    for (value in data) {
      let v : Nat32 = Nat32.fromIntWrap(Nat8.toNat(value));

      if ((v >> from) != 0) {
        return #err("Invalid input value: " # Nat.toText(Nat8.toNat(value)));
      };

      acc := (acc << from) | v;
      bits += from;

      while (bits >= to) {
        bits -= to;
        output.add(
          Nat8.fromIntWrap(
            Nat32.toNat((acc >> bits) & maxv)
          )
        );
      };
    };

    if (pad) {
      if (bits > 0) {
        output.add(
          Nat8.fromIntWrap(
            Nat32.toNat((acc << (to - bits)) & maxv)
          )
        );
      };
    } else if (bits >= from or ((acc << (to - bits)) & maxv) != 0) {
      return #err("Invalid Padding");
    };

    return #ok;
  };
};
