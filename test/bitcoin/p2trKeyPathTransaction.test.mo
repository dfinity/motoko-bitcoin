import Blob "mo:base/Blob";
import Nat "mo:base/Nat";
import TestVectors "p2trTestVectors";
import { expect; test } "mo:test";

for (testCase in TestVectors.testCases().vals()) {
    test(
        "serialized transaction with " # Nat.toText(testCase.numInputs) # " inputs",
        func() {
            let serializedTransaction = testCase.keySpendSignedTransaction().toBytes();

            expect.blob(Blob.fromArray(serializedTransaction)).equal(Blob.fromArray(testCase.expectedSerializedTransaction));
        },
    );
};

for (testCase in TestVectors.testCases().vals()) {
    test(
        "expected transaction id with " # Nat.toText(testCase.numInputs) # " inputs",
        func() {
            let computedTransactionId = testCase.keySpendSignedTransaction().id();

            expect.blob(Blob.fromArray(computedTransactionId)).equal(Blob.fromArray(testCase.expectedTransactionId));
        },
    );
};
