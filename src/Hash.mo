import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Text "mo:core/Text";

import Sha256 "mo:sha2/Sha256";

import Ripemd160 "Ripemd160";

module {
  // Applies SHA256 followed by RIPEMD160 on the given data.
  public func hash160(data : [Nat8]) : [Nat8] {
    Ripemd160.hash(Sha256.fromArray(#sha256, data).toArray());
  };

  // Applies double SHA256 to input.
  public func doubleSHA256(data : [Nat8]) : [Nat8] {
    Sha256.fromBlob(#sha256, Sha256.fromArray(#sha256, data)).toArray();
  };

  public func taggedHash(data : [Nat8], tag : Text) : [Nat8] {
    let tag_hash = Sha256.fromBlob(#sha256, tag.encodeUtf8()).toArray();
    Sha256.fromArray(#sha256, [tag_hash, tag_hash, data].flatten()).toArray();
  };
};
