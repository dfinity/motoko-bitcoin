import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import ByteUtils "../ByteUtils";
import Iter "mo:base/Iter";
import Result "mo:base/Result";

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
    let buffer = Buffer.Buffer<[Nat8]>(numElements * 2 + 1);
    buffer.add(ByteUtils.writeVarint(numElements));
    for (witness_element in Iter.fromArray(witness)) {
      let size = ByteUtils.writeVarint(witness_element.size());
      buffer.add(size);
      buffer.add(witness_element);
    };
    Array.flatten<Nat8>(Buffer.toArray(buffer));

  };

  public func fromBytes(data : Iter.Iter<Nat8>) : Result.Result<Witness, Text> {
    let numElements = switch (ByteUtils.readVarint(data)) {
      case (?numElements) { numElements };
      case (null) {
        return #err "Could not read number of elements in the witness";
      };
    };
    let witness : [var [Nat8]] = Array.init(numElements, []);
    for (i in Iter.range(0, numElements - 1)) {
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
    let result = Array.freeze(witness);
    #ok result;
  };
};
