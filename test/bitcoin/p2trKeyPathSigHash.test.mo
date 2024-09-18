import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import TestVectors "p2trTestVectors";
import { expect; test } "mo:test";

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
