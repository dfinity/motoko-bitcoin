import Array "mo:core/Array";
import List "mo:core/List";
import Nat "mo:core/Nat";
import { type Result; type Iter } "mo:core/Types";
import VarArray "mo:core/VarArray";

import ByteUtils "../ByteUtils";

module {
  // Witness consists of a sequence of byte arrays.
  public type Witness = [[Nat8]];

  public let EMPTY_WITNESS : Witness = [];

  /// A witness is serialized as
  /// `| num_elements | e_1_size | e_1 | ... | e_n_size | e_n |`. See
  /// [BIP144](https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki)
  /// for more details.
  public func toBytes(witness : Witness) : [Nat8] {
    let numElements = witness.size();
    let buffer = List.empty<[Nat8]>();
    buffer.add(ByteUtils.writeVarint(numElements));
    for (witness_element in witness.values()) {
      let size = ByteUtils.writeVarint(witness_element.size());
      buffer.add(size);
      buffer.add(witness_element);
    };
    buffer.toArray().flatten();

  };

  public func fromBytes(data : Iter<Nat8>) : Result<Witness, Text> {
    let numElements = switch (ByteUtils.readVarint(data)) {
      case (?numElements) { numElements };
      case (null) {
        return #err "Could not read number of elements in the witness";
      };
    };
    let witness : [var [Nat8]] = VarArray.repeat([], numElements);
    for (i in Nat.range(0, numElements)) {
      let size = switch (ByteUtils.readVarint(data)) {
        case (?size) { size };
        case (null) {
          return #err "Could not read witness element size";
        };
      };
      let witness_element = switch (ByteUtils.read(data, size, false)) {
        case (?witness_element) { witness_element };
        case (null) {
          return #err "Could not read witness element";
        };
      };
      witness[i] := witness_element;
    };
    let result = witness.toArray();
    #ok result;
  };
};
