import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Nat32 "mo:base/Nat32";
import Types "../../src/bitcoin/Types";
import TxInput "../../src/bitcoin/TxInput";
import Script "../../src/bitcoin/Script";
import P2tr "../../src/bitcoin/P2tr";
import P2pkh "../../src/bitcoin/P2pkh";
import TxOutput "../../src/bitcoin/TxOutput";
import Transaction "../../src/bitcoin/Transaction";
import Witness "../../src/bitcoin/Witness";

// The expected sighashes in this test were generated using the Rust `bitcoin` crate.
module {
    // Own P2TR key spend address.
    public let ownAddress = "bcrt1p8q6d7qk3ugevrygyvr8kskfk9hh0afxp36klxt9dxgm6emdgax4qkpjz5s";

    // Destination P2PKH address.
    public let dstAddress = "mgDiqeKZEGSBTi5fhZvL4AwywHApYWYPxR";

    public let version : Nat32 = 2;

    public class TestCase(_output_0 : Types.Satoshi, _output_1 : Types.Satoshi, _expectedSigHashes : [[Nat8]], _expectedSerializedTransaction : [Nat8], _expectedTransactionId : [Nat8]) {
        public let output_0 : Types.Satoshi = _output_0;
        public let output_1 : Types.Satoshi = _output_1;
        public let expectedSigHashes : [[Nat8]] = _expectedSigHashes;

        public let numInputs : Nat = Array.size(expectedSigHashes);
        assert numInputs > 0;

        public let expectedSerializedTransaction : [Nat8] = _expectedSerializedTransaction;
        public let expectedTransactionId : [Nat8] = _expectedTransactionId;

        public func utxos() : [Types.Utxo] {
            let outpoints : [Types.OutPoint] = [
                {
                    txid = Blob.fromArray(
                        // prettier-ignore
                    [
                        156, 78, 51, 59, 95, 17, 99, 89, 181, 245, 87, 143, 228, 167, 76, 111, 88, 179,
                        186, 185, 210, 129, 73, 165, 131, 218, 134, 246, 191, 12, 226, 125,
                    ] : [Nat8]
                    );
                    vout = 1;
                },
                {
                    txid = Blob.fromArray(
                        // prettier-ignore
                    [
                        153, 221, 175, 109, 155, 117, 68, 125, 81, 39, 225, 115, 18, 246, 222, 246,
                        138, 203, 162, 212, 244, 100, 208, 226, 172, 147, 19, 123, 181, 202, 183, 215,
                    ] : [Nat8]
                    );
                    vout = 0;
                },
                {
                    txid = Blob.fromArray(
                        // prettier-ignore
                    [
                        66, 24, 164, 25, 84, 39, 87, 217, 96, 23, 68, 87, 220, 130, 224, 107, 54, 19,
                        172, 142, 210, 197, 40, 146, 104, 51, 67, 56, 131, 245, 225, 248,
                    ] : [Nat8]
                    );
                    vout = 85;
                },
            ];

            let utxos : [Types.Utxo] = [
                {
                    outpoint = outpoints[0];
                    value = 11_000;
                    height = 9;
                },
                {
                    outpoint = outpoints[1];
                    value = 10_000;
                    height = 0;
                },
                {
                    outpoint = outpoints[2];
                    value = 12_000;
                    height = 156;
                },
            ];

            Array.subArray(Array.reverse(utxos), 0, numInputs);
        };

        public func inputs() : [TxInput.TxInput] {
            Array.map<Types.Utxo, TxInput.TxInput>(
                utxos(),
                func(utxo : Types.Utxo) {
                    TxInput.TxInput(utxo.outpoint, 0xffffffff);
                },
            );
        };

        public func amounts() : [Types.Satoshi] {
            Array.map<Types.Utxo, Types.Satoshi>(
                utxos(),
                func(utxo : Types.Utxo) {
                    utxo.value;
                },
            );
        };

        public func ownScript() : Script.Script {
            switch (P2tr.makeScriptFromP2trKeyAddress(ownAddress)) {
                case (#ok(script)) {
                    script;
                };
                case (#err(msg)) {
                    Debug.trap("Could not create script from address: " # msg);
                };
            };
        };

        public func outputs() : [TxOutput.TxOutput] {
            let dstScript = switch (P2pkh.makeScript(dstAddress)) {
                case (#ok(script)) {
                    script;
                };
                case (#err(msg)) {
                    Debug.trap("Could not create script from address: " # msg);
                };
            };
            [
                TxOutput.TxOutput(
                    output_0,
                    dstScript,
                ),
                TxOutput.TxOutput(
                    output_1,
                    ownScript(),
                ),
            ];
        };

        public func transaction() : Transaction.Transaction {
            Transaction.Transaction(
                version,
                inputs(),
                outputs(),
                Array.init(numInputs, Witness.EMPTY_WITNESS),
                0,
            );
        };

        public func sigHashes() : [[Nat8]] {
            // `moc` doesn't let us use `transaction` as a name with [M0097] error.
            let _transaction : Transaction.Transaction = transaction();
            let sigHashes = Array.init<[Nat8]>(numInputs, []);
            for (inputIndex in sigHashes.keys()) {
                let sigHash = _transaction.createTaprootKeySpendSignatureHash(
                    amounts(),
                    ownScript(),
                    Nat32.fromNat(inputIndex),
                );
                sigHashes[inputIndex] := sigHash;
            };
            Array.freeze(sigHashes);
        };

        public func signedTransaction() : Transaction.Transaction {
            // `moc` doesn't let us use same names for functions and local vars with [M0097] error.
            let _sigHashes = Array.thaw<[Nat8]>(sigHashes());
            let _transaction : Transaction.Transaction = transaction();

            let signatureByteLength = 64;

            for (inputIndex in _sigHashes.keys()) {
                assert _sigHashes[inputIndex].size() <= signatureByteLength;
                let padding = Array.freeze(Array.init<Nat8>(signatureByteLength - _sigHashes[inputIndex].size(), 0));
                _sigHashes[inputIndex] := Array.append(_sigHashes[inputIndex], padding);
                // Store the signature in the transaction.
                //
                // The signature in the tests is construced by padding the hash
                // to-be-signed with zeroes to the length of a signature. This
                // is only to create a non-zero unique witness for each input.
                _transaction.witnesses[inputIndex] := [_sigHashes[inputIndex]];
            };

            _transaction;
        };
    };

    public func testCases() : [TestCase] {
        [
            TestCase(
                1,
                11_999,
                // prettier-ignore
                [
                    [
                        214, 43, 187, 97, 242, 24, 138, 96, 27, 13, 205, 123, 118, 58, 135, 142, 136, 208,
                        105, 74, 92, 92, 57, 45, 247, 118, 191, 181, 61, 112, 242, 58
                    ]
                ],
                // prettier-ignore
                [
                    2, 0, 0, 0, 0, 1, 1, 66, 24, 164, 25, 84, 39, 87, 217, 96, 23, 68, 87, 220, 130, 224,
                    107, 54, 19, 172, 142, 210, 197, 40, 146, 104, 51, 67, 56, 131, 245, 225, 248, 85, 0,
                    0, 0, 0, 255, 255, 255, 255, 2, 1, 0, 0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 7, 181, 210,
                    142, 23, 35, 95, 75, 209, 94, 84, 201, 23, 73, 111, 254, 52, 78, 48, 30, 136, 172, 223,
                    46, 0, 0, 0, 0, 0, 0, 34, 81, 32, 56, 52, 223, 2, 209, 226, 50, 193, 145, 4, 96, 207,
                    104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50, 55, 172, 237, 168,
                    233, 170, 1, 64, 214, 43, 187, 97, 242, 24, 138, 96, 27, 13, 205, 123, 118, 58, 135,
                    142, 136, 208, 105, 74, 92, 92, 57, 45, 247, 118, 191, 181, 61, 112, 242, 58, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0,
                ],
                [30, 150, 240, 251, 102, 248, 64, 131, 15, 166, 230, 172, 120, 211, 137, 109, 169, 86, 72, 54, 79, 131, 34, 191, 133, 83, 137, 138, 80, 162, 177, 32],
            ),
            TestCase(
                12_000,
                9_994,
                // prettier-ignore
                [
                    [
                        3, 235, 175, 217, 116, 63, 62, 97, 1, 28, 119, 160, 250, 43, 202, 59, 183, 235, 45,
                        249, 36, 142, 227, 137, 103, 239, 198, 28, 41, 14, 42, 88
                    ],
                    [
                        2, 224, 77, 119, 91, 254, 63, 23, 168, 126, 0, 88, 181, 250, 253, 26, 196, 41, 130,
                        89, 120, 92, 203, 32, 238, 33, 183, 235, 75, 52, 232, 185
                    ]
                ],
                // prettier-ignore
                [
                    2, 0, 0, 0, 0, 1, 2, 66, 24, 164, 25, 84, 39, 87, 217, 96, 23, 68, 87, 220, 130, 224,
                    107, 54, 19, 172, 142, 210, 197, 40, 146, 104, 51, 67, 56, 131, 245, 225, 248, 85, 0,
                    0, 0, 0, 255, 255, 255, 255, 153, 221, 175, 109, 155, 117, 68, 125, 81, 39, 225, 115,
                    18, 246, 222, 246, 138, 203, 162, 212, 244, 100, 208, 226, 172, 147, 19, 123, 181, 202,
                    183, 215, 0, 0, 0, 0, 0, 255, 255, 255, 255, 2, 224, 46, 0, 0, 0, 0, 0, 0, 25, 118,
                    169, 20, 7, 181, 210, 142, 23, 35, 95, 75, 209, 94, 84, 201, 23, 73, 111, 254, 52, 78,
                    48, 30, 136, 172, 10, 39, 0, 0, 0, 0, 0, 0, 34, 81, 32, 56, 52, 223, 2, 209, 226, 50,
                    193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50,
                    55, 172, 237, 168, 233, 170, 1, 64, 3, 235, 175, 217, 116, 63, 62, 97, 1, 28, 119, 160,
                    250, 43, 202, 59, 183, 235, 45, 249, 36, 142, 227, 137, 103, 239, 198, 28, 41, 14, 42,
                    88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 1, 64, 2, 224, 77, 119, 91, 254, 63, 23, 168, 126, 0, 88, 181, 250, 253,
                    26, 196, 41, 130, 89, 120, 92, 203, 32, 238, 33, 183, 235, 75, 52, 232, 185, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0,
                ],
                [170, 242, 50, 180, 119, 123, 177, 130, 160, 239, 4, 173, 97, 104, 155, 141, 39, 149, 208, 201, 170, 170, 217, 45, 120, 33, 45, 86, 74, 40, 238, 206],
            ),
            TestCase(
                25_000,
                7_987,
                // prettier-ignore
                [
                    [
                        248, 11, 147, 165, 172, 103, 145, 22, 148, 10, 19, 45, 195, 220, 155, 238, 172, 69, 59,
                        237, 198, 244, 144, 50, 123, 55, 52, 194, 186, 234, 171, 233
                    ],
                    [
                        233, 9, 25, 103, 95, 92, 77, 25, 210, 70, 57, 12, 183, 21, 129, 78, 105, 128, 95, 220, 88,
                        238, 51, 228, 20, 103, 221, 174, 138, 159, 33, 13
                    ],
                    [
                        243, 5, 80, 5, 44, 217, 13, 111, 23, 243, 255, 126, 78, 105, 156, 5, 102, 22, 214, 172,
                        211, 54, 21, 180, 162, 140, 49, 154, 252, 172, 197, 77
                    ]
                ],
                // prettier-ignore
                [
                    2, 0, 0, 0, 0, 1, 3, 66, 24, 164, 25, 84, 39, 87, 217, 96, 23, 68, 87, 220, 130, 224,
                    107, 54, 19, 172, 142, 210, 197, 40, 146, 104, 51, 67, 56, 131, 245, 225, 248, 85, 0,
                    0, 0, 0, 255, 255, 255, 255, 153, 221, 175, 109, 155, 117, 68, 125, 81, 39, 225, 115,
                    18, 246, 222, 246, 138, 203, 162, 212, 244, 100, 208, 226, 172, 147, 19, 123, 181, 202,
                    183, 215, 0, 0, 0, 0, 0, 255, 255, 255, 255, 156, 78, 51, 59, 95, 17, 99, 89, 181, 245,
                    87, 143, 228, 167, 76, 111, 88, 179, 186, 185, 210, 129, 73, 165, 131, 218, 134, 246,
                    191, 12, 226, 125, 1, 0, 0, 0, 0, 255, 255, 255, 255, 2, 168, 97, 0, 0, 0, 0, 0, 0, 25,
                    118, 169, 20, 7, 181, 210, 142, 23, 35, 95, 75, 209, 94, 84, 201, 23, 73, 111, 254, 52,
                    78, 48, 30, 136, 172, 51, 31, 0, 0, 0, 0, 0, 0, 34, 81, 32, 56, 52, 223, 2, 209, 226,
                    50, 193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173,
                    50, 55, 172, 237, 168, 233, 170, 1, 64, 248, 11, 147, 165, 172, 103, 145, 22, 148, 10,
                    19, 45, 195, 220, 155, 238, 172, 69, 59, 237, 198, 244, 144, 50, 123, 55, 52, 194, 186,
                    234, 171, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 233, 9, 25, 103, 95, 92, 77, 25, 210, 70, 57, 12, 183,
                    21, 129, 78, 105, 128, 95, 220, 88, 238, 51, 228, 20, 103, 221, 174, 138, 159, 33, 13,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 1, 64, 243, 5, 80, 5, 44, 217, 13, 111, 23, 243, 255, 126, 78, 105, 156, 5,
                    102, 22, 214, 172, 211, 54, 21, 180, 162, 140, 49, 154, 252, 172, 197, 77, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
                [219, 2, 52, 19, 45, 157, 255, 223, 6, 5, 101, 232, 236, 68, 95, 85, 168, 210, 42, 37, 113, 125, 154, 187, 238, 182, 164, 202, 118, 43, 151, 237],
            ),
        ];
    };
};
