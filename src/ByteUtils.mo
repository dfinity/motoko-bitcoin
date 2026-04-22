import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import { type Iter } "mo:core/Types";
import VarArray "mo:core/VarArray";

import Common "Common";

module {
  // Read a number of elements from the given iterator and return as array. If
  // reverse is true, will read return the elements in reverse order.
  // Returns null if the iterator does not produce enough data.
  public func read(
    data : Iter<Nat8>,
    count : Nat,
    reverse : Bool,
  ) : ?[Nat8] {
    do ? {
      if (count == 0) return ?[];

      let readData : [var Nat8] = VarArray.repeat<Nat8>(0, count);
      if (reverse) {
        var nextReadIndex : Nat = count - 1;

        label Loop loop {
          readData[nextReadIndex] := data.next()!;
          if (nextReadIndex == 0) {
            break Loop;
          };
          nextReadIndex -= 1;
        };
      } else {
        var nextReadIndex : Nat = 0;

        while (nextReadIndex < count) {
          readData[nextReadIndex] := data.next()!;
          nextReadIndex += 1;
        };
      };

      readData.toArray();
    };
  };

  // Read little endian 16-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE16(data : Iter<Nat8>) : ?Nat16 {
    do ? {
      let (a, b) = (data.next()!, data.next()!);
      b.toNat16() << 8 | a.toNat16();
    };
  };

  // Read little endian 32-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE32(data : Iter<Nat8>) : ?Nat32 {
    do ? {
      let (a, b, c, d) = (data.next()!, data.next()!, data.next()!, data.next()!);
      d.toNat16().toNat32() << 24 | c.toNat16().toNat32() << 16 | b.toNat16().toNat32() << 8 | a.toNat16().toNat32();
    };
  };

  // Read little endian 64-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE64(data : Iter<Nat8>) : ?Nat64 {
    do ? {
      let (a, b, c, d, e, f, g, h) = (
        data.next()!,
        data.next()!,
        data.next()!,
        data.next()!,
        data.next()!,
        data.next()!,
        data.next()!,
        data.next()!,
      );

      h.toNat16().toNat32().toNat64() << 56 | g.toNat16().toNat32().toNat64() << 48 | f.toNat16().toNat32().toNat64() << 40 | e.toNat16().toNat32().toNat64() << 32 | d.toNat16().toNat32().toNat64() << 24 | c.toNat16().toNat32().toNat64() << 16 | b.toNat16().toNat32().toNat64() << 8 | a.toNat16().toNat32().toNat64();
    };
  };

  // Read one element from the given iterator.
  // Returns null if the iterator does not produce enough data.
  public func readOne(data : Iter<Nat8>) : ?Nat8 {
    data.next();
  };

  // Read and return a varint encoded integer from data.
  // Returns null if the iterator does not produce enough data.
  public func readVarint(data : Iter<Nat8>) : ?Nat {
    do ? {
      switch (readOne(data)!) {
        case 0xfd {
          readLE16(data)!.toNat();
        };
        case 0xfe {
          readLE32(data)!.toNat();
        };
        case 0xff {
          readLE64(data)!.toNat();
        };
        case (length) {
          length.toNat();
        };
      };
    };
  };

  // Encode value as varint.
  public func writeVarint(value : Nat) : [Nat8] {
    assert (value < 0x10000000000000000);

    if (value < 0xfd) { [Nat8.fromIntWrap(value)] } else if (value < 0x10000) {
      let buf = VarArray.repeat<Nat8>(0xfd, 3);
      Common.writeLE16(buf, 1, Nat16.fromIntWrap(value));
      buf.toArray();
    } else if (value < 0x100000000) {
      let buf = VarArray.repeat<Nat8>(0xfe, 5);
      Common.writeLE32(buf, 1, Nat32.fromIntWrap(value));
      buf.toArray();
    } else {
      let buf = VarArray.repeat<Nat8>(0xff, 9);
      Common.writeLE64(buf, 1, Nat64.fromIntWrap(value));
      buf.toArray();
    };
  };
};
