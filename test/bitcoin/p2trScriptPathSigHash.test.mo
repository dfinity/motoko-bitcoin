import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import VarArray "mo:core/VarArray";

import { expect; test } "mo:test";

import P2tr "../../src/bitcoin/P2tr";
import Transaction "../../src/bitcoin/Transaction";
import Witness "../../src/bitcoin/Witness";
import TestVectors "p2trTestVectors";

for (testCase in TestVectors.testCases().vals()) {
  test(
    Nat.toText(testCase.numInputs) # " inputs",
    func() {
      assert testCase.expectedScriptSpendSigHashes.size() == testCase.numInputs;

      let computedSigHashes = testCase.scriptSpendSigHashes();
      assert computedSigHashes.size() == testCase.numInputs;

      for (inputIndex in computedSigHashes.keys()) {
        expect.blob(Blob.fromArray(computedSigHashes[inputIndex])).equal(Blob.fromArray(testCase.expectedScriptSpendSigHashes[inputIndex]));
      };
    },
  );
};

test(
  "non-zero locktime changes script spend sighash",
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

    let leafHash = P2tr.leafHash(testCase.leafScript());
    let hash0 = txLocktime0.createTaprootScriptSpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0, leafHash,
    );
    let hash42 = txLocktime42.createTaprootScriptSpendSignatureHash(
      testCase.amounts(), testCase.ownScript(), 0, leafHash,
    );

    expect.blob(Blob.fromArray(hash0)).notEqual(Blob.fromArray(hash42));
  },
);
