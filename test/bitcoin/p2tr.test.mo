import P2tr "../../src/bitcoin/P2tr";
import Blob "mo:base/Blob";

import { expect; test } "mo:test";
import Script "../../src/bitcoin/Script";

let bip340_key_byte_len : Nat = 32;

test(
    "MAST leaf hash",
    func() {
        let public_key_bip340 : [Nat8] = [56, 52, 223, 2, 209, 226, 50, 193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50, 55, 172, 237, 168, 233, 170];
        expect.nat(public_key_bip340.size()).equal(bip340_key_byte_len);

        let script : Script.Script = [#data(public_key_bip340), #opcode(#OP_CHECKSIG)];
        let computed = P2tr.leafHash(script);
        let expected : [Nat8] = [121, 89, 72, 255, 55, 49, 57, 37, 229, 20, 144, 247, 94, 100, 207, 182, 103, 190, 68, 196, 13, 225, 177, 166, 254, 123, 145, 71, 129, 171, 15, 191];
        expect.blob(Blob.fromArray(computed)).equal(Blob.fromArray(expected));
    },
);
