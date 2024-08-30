import Ripemd160 "./Ripemd160";
import Sha256 "mo:sha2/Sha256";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Array "mo:base/Array";

module {
  // Applies SHA256 followed by RIPEMD160 on the given data.
  public func hash160(data : [Nat8]) : [Nat8] {
    return Ripemd160.hash(Blob.toArray(Sha256.fromArray(#sha256, data)));
  };

  // Applies double SHA256 to input.
  public func doubleSHA256(data : [Nat8]) : [Nat8] {
    return Blob.toArray(Sha256.fromBlob(#sha256, Sha256.fromArray(#sha256, data)));
  };

  public func tagged_hash(data : [Nat8], tag : Text) : [Nat8] {
    let tag_hash = Blob.toArray(Sha256.fromBlob(#sha256, Text.encodeUtf8(tag)));
    Blob.toArray(Sha256.fromArray(#sha256, Array.flatten([tag_hash, tag_hash, data])));
  };
};
