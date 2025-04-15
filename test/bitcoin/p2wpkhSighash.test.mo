// test/bitcoin/p2wpkhSighash.test.mo
// @testmode wasi

import Debug "mo:base/Debug";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Int32 "mo:base/Int32";
import TestVectors "./p2wpkhSighashVectors";
import TestUtils "../TestUtils";
import Hex "../Hex";
import Transaction "../../src/bitcoin/Transaction";
import Types "../../src/bitcoin/Types";

type TestCase = TestVectors.P2wpkhSighashTestCase;

let tests = TestVectors.vectors;

func testP2wpkhSighash(tcase : TestCase) {
  let hashTypeNat32 : Nat32 = Int32.toNat32(tcase.hashType);

  if (hashTypeNat32 != Types.SIGHASH_ALL) {
      Debug.print("Skipping test (" # tcase.description # "): Unsupported hashType " # Int32.toText(tcase.hashType));
      return;
  };

  let txData = switch (Hex.decode(tcase.txHex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad txHex hex: " # e);
  };
  let scriptCodeBytes = switch (Hex.decode(tcase.scriptCodeHex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad scriptCodeHex hex: " # e);
  };
  let expectedSighashBytes = switch (Hex.decode(tcase.expectedSighashHex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad expectedSighashHex hex: " # e);
  };

  let tx = switch (Transaction.fromBytes(txData.vals())) {
    case (#ok tx) { tx };
    case (#err msg) {
      Debug.trap("Could not deserialize transaction data: " # msg);
    };
  };

  let actualSighashResult = tx.createP2wpkhSignatureHash(
    tx,
    tcase.inputIndex,
    scriptCodeBytes,
    tcase.amount,
    hashTypeNat32
  );

  switch (actualSighashResult) {
    case (#ok actualSighashBytes) {
      if (not Array.equal(expectedSighashBytes, actualSighashBytes, Nat8.equal)) {
         Debug.print("--- TEST FAILED: " # tcase.description # " ---");
         Debug.print("Expected Sighash: " # debug_show(expectedSighashBytes));
         Debug.print("Actual Sighash:   " # debug_show(actualSighashBytes));
      };
      assert (
        Array.equal(
          expectedSighashBytes,
          actualSighashBytes,
          Nat8.equal
        ) == true
      );
    };
    case (#err msg) {
      Debug.trap("createP2wpkhSignatureHash failed for (" # tcase.description # "): " # msg);
    };
  };
};

// Ejecutar todos los tests
TestUtils.runTestWithDefaults({
  title = "P2WPKH Sighash (BIP143)";
  fn = testP2wpkhSighash;
  vectors = tests;
});