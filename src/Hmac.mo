import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";

module {
  public type Digest = {
    writeArray : ([Nat8]) -> ();
    sum : () -> Blob;
  };

  public type DigestFactory = {
    blockSize : Nat;
    create : () -> Digest;
  };

  public type Hmac = {
    writeArray : ([Nat8]) -> ();
    sum : () -> Blob;
  };

  // Sha256 support.
  object sha256DigestFactory {
    public let blockSize : Nat = 64;
    public func create() : Digest = Sha256.Digest(#sha256);
  };
  public func sha256(key : [Nat8]) : Hmac = HmacImpl(key, sha256DigestFactory);

  // Sha512 support.
  object sha512DigestFactory {
    public let blockSize : Nat = 128;
    public func create() : Digest = Sha512.Digest(#sha512);
  };
  public func sha512(key : [Nat8]) : Hmac = HmacImpl(key, sha512DigestFactory);

  // Construct HMAC from an arbitrary digest function.
  public func new(key : [Nat8], digestFactory : DigestFactory) : Hmac {
    return HmacImpl(key, digestFactory);
  };

  // Construct HMAC from the given digest function:
  // HMAC(key, data) = H((key' ^ outerPad) || H((key' ^ innerPad) || data))
  // key' = H(key) if key larger than block size, otherwise equals key
  // H is a cryptographic hash function
  class HmacImpl(key : [Nat8], digestFactory : DigestFactory) : Hmac {
    let innerDigest : Digest = digestFactory.create();
    let outerDigest : Digest = digestFactory.create();
    let innerPad : Nat8 = 0x36;
    let outerPad : Nat8 = 0x5c;

    do {
      let blockSize = digestFactory.blockSize;
      let blockSizedKey : [Nat8] = if (key.size() <= blockSize) {
        // key' = key + [0x00] * (blockSize - key.size())
        Array.tabulate<Nat8>(
          blockSize,
          func(i) {
            if (i < key.size()) {
              key[i];
            } else {
              0;
            };
          },
        );
      } else {
        // key' = H(key) + [0x00] * (blockSize - key.size())
        let keyDigest : Digest = digestFactory.create();
        keyDigest.writeArray(key);
        let keyHash = Blob.toArray(keyDigest.sum());

        Array.tabulate<Nat8>(
          blockSize,
          func(i) {
            if (i < keyHash.size()) {
              keyHash[i];
            } else {
              0;
            };
          },
        );
      };

      // H(key' ^ outerPad)
      let outerPaddedKey = Array.map<Nat8, Nat8>(
        blockSizedKey,
        func(byte) {
          byte ^ outerPad;
        },
      );
      outerDigest.writeArray(outerPaddedKey);

      // H(key' ^ innerPad)
      let innerPaddedKey = Array.map<Nat8, Nat8>(
        blockSizedKey,
        func(byte) {
          byte ^ innerPad;
        },
      );
      innerDigest.writeArray(innerPaddedKey);
    };

    public func writeArray(data : [Nat8]) {
      innerDigest.writeArray(data);
    };

    public func sum() : Blob {
      let innerHash = Blob.toArray(innerDigest.sum());
      outerDigest.writeArray(innerHash);
      return outerDigest.sum();
    };
  };
};
