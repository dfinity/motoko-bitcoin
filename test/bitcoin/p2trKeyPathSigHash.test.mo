import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Array "mo:base/Array";
import Nat32 "mo:base/Nat32";
import P2tr "../../src/bitcoin/P2tr";
import TestVectors "p2trKeyPathSigHashTestVectors";
import Transaction "../../src/bitcoin/Transaction";
import TxInput "../../src/bitcoin/TxInput";
import TxOutput "../../src/bitcoin/TxOutput";
import Types "../../src/bitcoin/Types";
import Witness "../../src/bitcoin/Witness";
import { expect; test } "mo:test";
import P2pkh "../../src/bitcoin/P2pkh";

for (numInputs in Iter.range(1, TestVectors.testCases.size())) {
    test(
        Nat.toText(numInputs) # " inputs",
        func() {
            let testCase = TestVectors.testCases[numInputs - 1];
            let utxos = Array.subArray(TestVectors.utxos(), 0, numInputs);
            let inputs = Array.map<Types.Utxo, TxInput.TxInput>(
                utxos,
                func(utxo : Types.Utxo) {
                    TxInput.TxInput(utxo.outpoint, 0xffffffff);
                },
            );
            let amounts = Array.map<Types.Utxo, Types.Satoshi>(
                utxos,
                func(utxo : Types.Utxo) {
                    utxo.value;
                },
            );

            let ownScript = switch (P2tr.makeScriptFromP2trKeyAddress(TestVectors.ownAddress)) {
                case (#ok(script)) {
                    script;
                };
                case (#err(msg)) {
                    Debug.trap("Could not create script from address: " # msg);
                };
            };
            let dstScript = switch (P2pkh.makeScript(TestVectors.dstAddress)) {
                case (#ok(script)) {
                    script;
                };
                case (#err(msg)) {
                    Debug.trap("Could not create script from address: " # msg);
                };
            };
            let outputs = [
                TxOutput.TxOutput(
                    testCase.output_0,
                    dstScript,
                ),
                TxOutput.TxOutput(
                    testCase.output_1,
                    ownScript,
                ),
            ];

            assert utxos.size() == testCase.expectedSigHashes.size();

            assert utxos.size() > 0;
            for (inputIndex in Iter.range(0, utxos.size() - 1)) {
                let sighash = Transaction.Transaction(
                    TestVectors.version,
                    inputs,
                    outputs,
                    [var Witness.EMPTY_WITNESS],
                    0,
                ).createTaprootKeySpendSignatureHash(
                    amounts,
                    ownScript,
                    Nat32.fromNat(inputIndex),
                );

                expect.blob(Blob.fromArray(sighash)).equal(Blob.fromArray(testCase.expectedSigHashes[inputIndex]));
            };
        },
    );
};
