import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Common "../../src/Common";
import Curves "../../src/ec/Curves";
import Debug "mo:base/Debug";
import Fp "../../src/ec/Fp";
import P2tr "../../src/bitcoin/P2tr";
import Result "mo:base/Result";
import Script "../../src/bitcoin/Script";
import { expect; test } "mo:test";

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

func assert_tweak_res_eq(expected : Result.Result<Fp.Fp, Text>, computed : Result.Result<Fp.Fp, Text>) {
  type Res = Result.Result<Fp.Fp, Text>;
  func show(a : Res) : Text = switch (a) {
    case (#ok(tweak)) { debug_show (tweak.value) };
    case (#err(text)) { text };
  };
  func equal(a : Res, b : Res) : Bool {
    switch (a, b) {
      case (#ok(a), #ok(b)) { a.value == b.value };
      case (#err(a), #err(b)) { a == b };
      case _ { false };
    };
  };
  expect.result<Fp.Fp, Text>(expected, show, equal).equal(computed);
};

test(
  "tweak from key and hash: valid inputs",
  func() {
    let expected_tweak_bytes : [Nat8] = [93, 80, 16, 188, 233, 192, 60, 9, 243, 64, 251, 234, 102, 39, 147, 81, 152, 14, 119, 40, 221, 40, 12, 227, 47, 186, 208, 188, 123, 78, 238, 105];
    expect.nat(expected_tweak_bytes.size()).equal(32);
    let expected_tweak : Fp.Fp = Curves.secp256k1.Fp(Common.readBE256(expected_tweak_bytes, 0));

    let internal_key : [Nat8] = [56, 52, 223, 2, 209, 226, 50, 193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50, 55, 172, 237, 168, 233, 170];
    expect.nat(internal_key.size()).equal(32);
    let hash : [Nat8] = [121, 89, 72, 255, 55, 49, 57, 37, 229, 20, 144, 247, 94, 100, 207, 182, 103, 190, 68, 196, 13, 225, 177, 166, 254, 123, 145, 71, 129, 171, 15, 191];
    expect.nat(hash.size()).equal(32);

    let computed_tweak : Result.Result<Fp.Fp, Text> = P2tr.tweakFromKeyAndHash(internal_key, hash);

    assert_tweak_res_eq(computed_tweak, #ok expected_tweak);
  },
);

test(
  "tweak from key and hash: invalid input sizes",
  func() {
    func array_of_size(size : Nat) : [Nat8] = Array.freeze(Array.init<Nat8>(size, 0));
    let valid_key_or_hash = array_of_size(32);

    for (i in [0, 1, 31, 33].vals()) {
      assert_tweak_res_eq(
        P2tr.tweakFromKeyAndHash(array_of_size(i), valid_key_or_hash),
        #err("Failed to compute tweak, invalid internal key length: expected 32 but got " # debug_show (i)),
      );
      assert_tweak_res_eq(
        P2tr.tweakFromKeyAndHash(valid_key_or_hash, array_of_size(i)),
        #err("Failed to compute tweak, invalid hash length: expected 32 but got " # debug_show (i)),
      );
    };
  },
);

test(
  "add zero tweak",
  func() {
    let public_key_bip340 : [Nat8] = [56, 52, 223, 2, 209, 226, 50, 193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50, 55, 172, 237, 168, 233, 170];
    let zero_tweak : Fp.Fp = Curves.secp256k1.Fp(0);
    switch (P2tr.tweakPublicKey(public_key_bip340, zero_tweak)) {
      case (#ok(tweaked)) {
        expect.blob(Blob.fromArray(tweaked.bip340_public_key)).equal(Blob.fromArray(public_key_bip340));
        expect.bool(tweaked.is_even).isTrue();
      };
      case (#err(text)) {
        Debug.trap(text);
      };
    };
  },
);

test(
  "tweaked public key",
  func() {
    let public_key_bip340 : [Nat8] = [56, 52, 223, 2, 209, 226, 50, 193, 145, 4, 96, 207, 104, 89, 54, 45, 238, 254, 164, 193, 142, 173, 243, 44, 173, 50, 55, 172, 237, 168, 233, 170];

    let script : Script.Script = [#data(public_key_bip340), #opcode(#OP_CHECKSIG)];
    let merkle_root = P2tr.leafHash(script);

    let tweak = switch (P2tr.tweakFromKeyAndHash(public_key_bip340, merkle_root)) {
      case (#ok(tweak)) { tweak };
      case (#err(text)) { Debug.trap(text) };
    };

    let expected : [Nat8] = [100, 6, 11, 39, 35, 146, 187, 231, 26, 61, 8, 17, 107, 6, 180, 177, 70, 67, 14, 141, 245, 171, 35, 208, 45, 113, 164, 60, 177, 196, 74, 202];
    assert expected.size() == bip340_key_byte_len;

    switch (P2tr.tweakPublicKey(public_key_bip340, tweak)) {
      case (#ok(tweaked)) {
        // make sure the key has changed
        expect.blob(Blob.fromArray(tweaked.bip340_public_key)).notEqual(Blob.fromArray(public_key_bip340));
        // make sure the key has changed to the right value
        expect.blob(Blob.fromArray(tweaked.bip340_public_key)).equal(Blob.fromArray(expected));

        expect.bool(tweaked.is_even).isFalse();
      };
      case (#err(text)) {
        Debug.trap(text);
      };
    };
  },
);
