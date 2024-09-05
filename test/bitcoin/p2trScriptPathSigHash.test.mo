import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import TestVectors "p2trKeyPathTestVectors";
import { expect; test } "mo:test";

for (testCase in TestVectors.testCases().vals()) {
    test(
        Nat.toText(testCase.numInputs) # " inputs",
        func() {
            assert testCase.expectedSigHashes.size() == testCase.numInputs;

            let computedSigHashes = testCase.scriptSpendSigHashes();
            assert computedSigHashes.size() == testCase.numInputs;

            for (inputIndex in computedSigHashes.keys()) {
                expect.blob(Blob.fromArray(computedSigHashes[inputIndex])).equal(Blob.fromArray(testCase.expectedScriptSpendSigHashes[inputIndex]));
            };
        },
    );
};
