import Nat "mo:core/Nat";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";

module {
  // Read big endian 32-bit natural number starting at offset.
  public func readBE32(bytes : [Nat8], offset : Nat) : Nat32 {
    bytes[offset + 0].toNat16().toNat32() << 24 | bytes[offset + 1].toNat16().toNat32() << 16 | bytes[offset + 2].toNat16().toNat32() << 8 | bytes[offset + 3].toNat16().toNat32();
  };

  // Read big endian 64-bit natural number starting at offset.
  public func readBE64(bytes : [Nat8], offset : Nat) : Nat64 {
    let first : Nat32 = readBE32(bytes, offset);
    let second : Nat32 = readBE32(bytes, offset + 4);

    first.toNat64() << 32 | second.toNat64();
  };

  // Read big endian 128-bit natural number starting at offset.
  public func readBE128(bytes : [Nat8], offset : Nat) : Nat {
    let first : Nat64 = readBE64(bytes, offset);
    let second : Nat64 = readBE64(bytes, offset + 8);

    first.toNat() * 0x10000000000000000 + second.toNat();
  };

  // Read big endian 256-bit natural number starting at offset.
  public func readBE256(bytes : [Nat8], offset : Nat) : Nat {
    let first : Nat = readBE128(bytes, offset);
    let second : Nat = readBE128(bytes, offset + 16);

    first * 0x100000000000000000000000000000000 + second;
  };

  // Write given value as 32-bit big endian into array starting at offset.
  public func writeBE32(bytes : [var Nat8], offset : Nat, value : Nat32) {
    bytes[offset] := Nat8.fromNat(((value & 0xFF000000) >> 24).toNat());
    bytes[offset + 1] := Nat8.fromNat(((value & 0xFF0000) >> 16).toNat());
    bytes[offset + 2] := Nat8.fromNat(((value & 0xFF00) >> 8).toNat());
    bytes[offset + 3] := Nat8.fromNat((value & 0xFF).toNat());
  };

  // Write given value as 64-bit big endian into array starting at offset.
  public func writeBE64(bytes : [var Nat8], offset : Nat, value : Nat64) {
    let first : Nat32 = Nat32.fromIntWrap((value >> 32).toNat());
    let second : Nat32 = Nat32.fromIntWrap(value.toNat());

    writeBE32(bytes, offset, first);
    writeBE32(bytes, offset + 4, second);
  };

  // Write given value as 128-bit big endian into array starting at offset.
  public func writeBE128(bytes : [var Nat8], offset : Nat, value : Nat) {
    let first : Nat64 = Nat64.fromIntWrap(value / 0x10000000000000000);
    let second : Nat64 = Nat64.fromIntWrap(value);

    writeBE64(bytes, offset, first);
    writeBE64(bytes, offset + 8, second);
  };

  // Write given value as 256-bit big endian into array starting at offset.
  public func writeBE256(bytes : [var Nat8], offset : Nat, value : Nat) {
    let first : Nat = value / (2 ** 128);
    let second : Nat = value - (first * 0x100000000000000000000000000000000);

    writeBE128(bytes, offset, first);
    writeBE128(bytes, offset + 16, second);
  };

  // Read little endian 32-bit natural number starting at offset.
  public func readLE32(bytes : [Nat8], offset : Nat) : Nat32 {
    bytes[offset + 3].toNat16().toNat32() << 24 | bytes[offset + 2].toNat16().toNat32() << 16 | bytes[offset + 1].toNat16().toNat32() << 8 | bytes[offset + 0].toNat16().toNat32();
  };

  // Write given value as 16-bit little endian into array starting at offset.
  public func writeLE16(bytes : [var Nat8], offset : Nat, value : Nat16) {
    let first : Nat8 = Nat8.fromIntWrap(value.toNat());
    let second : Nat8 = Nat8.fromIntWrap((value >> 8).toNat());

    bytes[offset] := first;
    bytes[offset + 1] := second;
  };

  // Write given value as 32-bit little endian into array starting at offset.
  public func writeLE32(bytes : [var Nat8], offset : Nat, value : Nat32) {
    let first : Nat16 = Nat16.fromIntWrap(value.toNat());
    let second : Nat16 = Nat16.fromIntWrap((value >> 16).toNat());

    writeLE16(bytes, offset, first);
    writeLE16(bytes, offset + 2, second);
  };

  // Write given value as 64-bit little endian into array starting at offset.
  public func writeLE64(bytes : [var Nat8], offset : Nat, value : Nat64) {
    let first : Nat32 = Nat32.fromIntWrap(value.toNat());
    let second : Nat32 = Nat32.fromIntWrap((value >> 32).toNat());

    writeLE32(bytes, offset, first);
    writeLE32(bytes, offset + 4, second);
  };

  // Copy data from src into dest from/at the given offsets.
  public func copy(
    dest : [var Nat8],
    destOffset : Nat,
    src : [Nat8],
    srcOffset : Nat,
    count : Nat,
  ) {
    for (i in Nat.range(0, count)) {
      dest[destOffset + i] := src[srcOffset + i];
    };
  };
};
