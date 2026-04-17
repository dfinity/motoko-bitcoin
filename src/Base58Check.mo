import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

import Base58 "Base58";

module {

  // Convert the given Base256 input to Base58 with checksum.
  public func encode(input : [Nat8]) : Text {
    // Add 4-byte hash check to the end.
    let hash : [Nat8] = Sha256.fromBlob(#sha256, Sha256.fromArray(#sha256, input)).toArray();
    let inputWithCheck : [var Nat8] = VarArray.repeat<Nat8>(0, input.size() + 4);

    for (i in Nat.range(0, input.size())) {
      inputWithCheck[i] := input[i];
    };

    inputWithCheck[input.size()] := hash[0];
    inputWithCheck[input.size() + 1] := hash[1];
    inputWithCheck[input.size() + 2] := hash[2];
    inputWithCheck[input.size() + 3] := hash[3];

    Base58.encode(inputWithCheck.toArray());
  };

  // Convert the given checked Base58 input to Base256. Returns null if the
  // checksum verification fails.
  public func decode(input : Text) : ?[Nat8] {
    let decoded : [Nat8] = Base58.decode(input);

    // Strip the last 4 bytes.
    let output = Array.tabulate<Nat8>(
      decoded.size() - 4,
      func(i) {
        decoded[i];
      },
    );

    // Re-calculate checksum, ensure it matches the included 4-byte checksum.
    let hash : [Nat8] = Sha256.fromBlob(#sha256, Sha256.fromArray(#sha256, output)).toArray();

    for (i in Nat.range(0, 4)) {
      if (hash[i] != decoded[decoded.size() - 4 + i]) {
        return null;
      };
    };

    return ?output;
  };
};
