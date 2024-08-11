import Ripemd160 "./Ripemd160";
import SHA256 "../motoko-sha/src/SHA256";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Array "mo:base/Array";

module {
  // Applies SHA256 followed by RIPEMD160 on the given data.
  public func hash160(data : [Nat8]) : [Nat8] {
    return Ripemd160.hash(SHA256.sha256(data));
  };

  // Applies double SHA256 to input.
  public func doubleSHA256(data : [Nat8]) : [Nat8] {
    return SHA256.sha256(SHA256.sha256(data));
  };

  public func tagged_hash(data : [Nat8], tag : Text) : [Nat8] {
    let tag_hash = SHA256.sha256(Blob.toArray(Text.encodeUtf8(tag)));
    SHA256.sha256(Array.flatten([tag_hash, tag_hash, data]));
  };
};
