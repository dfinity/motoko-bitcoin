// test/bitcoin/p2wpkhSighashTestVectors.mo

import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Int32 "mo:base/Int32";

module {
  public type P2wpkhSighashTestCase = {
    txHex : Text;
    scriptCodeHex : Text;
    inputIndex : Nat32;
    amount : Nat64;
    hashType : Int32;
    expectedSighashHex : Text;
    description : Text;
  };

  // Fuente: BIP143 Sección "Example" (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#examples)
  public let vectors : [P2wpkhSighashTestCase] = [
    {
      description = "BIP143 Example: Native P2WPKH SIGHASH_ALL (Input 1)";
      txHex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
      scriptCodeHex = "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac";
      inputIndex = 1;
      amount = 600000000;
      hashType = 1;
      expectedSighashHex = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
    }
  ];
};
