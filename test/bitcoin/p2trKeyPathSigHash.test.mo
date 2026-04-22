import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import VarArray "mo:core/VarArray";

import { expect; test } "mo:test";

import Transaction "../../src/bitcoin/Transaction";
import Witness "../../src/bitcoin/Witness";
import TestVectors "p2trTestVectors";

for (testCase in TestVectors.testCases().vals()) {
  test(
    Nat.toText(testCase.numInputs) # " inputs",
    func() {
      assert testCase.expectedKeySpendSigHashes.size() == testCase.numInputs;

      let computedSigHashes = testCase.keySpendSigHashes();
      assert computedSigHashes.size() == testCase.numInputs;

      for (inputIndex in computedSigHashes.keys()) {
        expect.blob(Blob.fromArray(computedSigHashes[inputIndex])).equal(Blob.fromArray(testCase.expectedKeySpendSigHashes[inputIndex]));
      };
    },
  );
};

test(
  "non-zero locktime changes sighash",
  func() {
    let testCase = TestVectors.testCases()[0];
    let txLocktime0 = testCase.transaction();
    let txLocktime42 = Transaction.Transaction(
      TestVectors.version,
      testCase.inputs(),
      testCase.outputs(),
      VarArray.repeat(Witness.EMPTY_WITNESS, testCase.numInputs),
      42,
    );

    let hash0 = txLocktime0.createTaprootKeySpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0,
    );
    let hash42 = txLocktime42.createTaprootKeySpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0,
    );

    expect.blob(Blob.fromArray(hash0)).notEqual(Blob.fromArray(hash42));
  },
);

test(
  "different version changes sighash",
  func() {
    let testCase = TestVectors.testCases()[0];
    let txVersion2 = testCase.transaction();
    let txVersion1 = Transaction.Transaction(
      1,
      testCase.inputs(),
      testCase.outputs(),
      VarArray.repeat(Witness.EMPTY_WITNESS, testCase.numInputs),
      0,
    );

    let hash2 = txVersion2.createTaprootKeySpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0,
    );
    let hash1 = txVersion1.createTaprootKeySpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0,
    );

    expect.blob(Blob.fromArray(hash2)).notEqual(Blob.fromArray(hash1));
  },
);
