import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Types "../../src/bitcoin/Types";

module {
    public let ownAddress = "bcrt1p8q6d7qk3ugevrygyvr8kskfk9hh0afxp36klxt9dxgm6emdgax4qkpjz5s";

    public let dstAddress = "mgDiqeKZEGSBTi5fhZvL4AwywHApYWYPxR";

    public let version: Nat32 = 2;

    type TestCase = {
        output_0 : Types.Satoshi;
        output_1 : Types.Satoshi;
        expectedSigHashes : [[Nat8]];
    };

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

        Array.reverse(utxos);
    };

    public let testCases : [TestCase] = [
        {
            output_0 = 1;
            output_1 = 11_999;
            // prettier-ignore
            expectedSigHashes = [
                [
                    214, 43, 187, 97, 242, 24, 138, 96, 27, 13, 205, 123, 118, 58, 135, 142, 136, 208,
                    105, 74, 92, 92, 57, 45, 247, 118, 191, 181, 61, 112, 242, 58
                ]
            ];
        },
        {
            output_0 = 12_000;
            output_1 = 9_994;
            // prettier-ignore
            expectedSigHashes = [
                [
                    3, 235, 175, 217, 116, 63, 62, 97, 1, 28, 119, 160, 250, 43, 202, 59, 183, 235, 45,
                    249, 36, 142, 227, 137, 103, 239, 198, 28, 41, 14, 42, 88
                ],
                [
                    2, 224, 77, 119, 91, 254, 63, 23, 168, 126, 0, 88, 181, 250, 253, 26, 196, 41, 130,
                    89, 120, 92, 203, 32, 238, 33, 183, 235, 75, 52, 232, 185
                ]
            ];
        },
        {
            output_0 = 25_000;
            output_1 = 7_987;
            // prettier-ignore
            expectedSigHashes = [
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
            ];
        },
    ];
};
