import Array "mo:core/Array";
import List "mo:core/List";

module {
  // Extended Euclidean Algorithm.
  public func eea(a : Int, b : Int) : (Int, Int, Int) {
    if (b == 0) {
      return (a, 1, 0);
    };
    let (d, s, t) = eea(b, a % b);
    return (d, t, s - (a / b) * t);
  };

  // Convert given number to binary represented as an array of Bool in reverse
  // order.
  public func toBinaryReversed(a : Nat) : [Bool] {
    let bitsBuffer = List.empty<Bool>();
    var number : Nat = a;

    while (number != 0) {
      bitsBuffer.add(number % 2 == 1);
      number /= 2;
    };

    bitsBuffer.toArray();
  };

  // Convert given number to binary represented as an array of Bool.
  public func toBinary(a : Nat) : [Bool] {
    let reversedBinary = toBinaryReversed(a);
    Array.tabulate<Bool>(
      reversedBinary.size(),
      func(i) {
        reversedBinary[reversedBinary.size() - i - 1];
      },
    );
  };

  // Compute the Non-adjacent form representiation of the given integer.
  public func toNaf(n : Int) : [Int] {
    var input : Int = n;
    let output = List.empty<Int>();

    while (input != 0) {
      if (input % 2 != 0) {
        var nd : Int = input % 4;
        if (nd >= 2) {
          nd -= 4;
        };
        output.add(nd);
        input -= nd;
      } else {
        output.add(0);
      };
      input /= 2;
    };

    output.toArray();
  };
};
