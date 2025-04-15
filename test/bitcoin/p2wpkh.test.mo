// test/bitcoin/p2wpkh.test.mo
// @testmode wasi

import Debug "mo:base/Debug";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import TestUtils "../TestUtils";
import Curves "../../src/ec/Curves";
import EcdsaTypes "../../src/ecdsa/Types";
import Script "../../src/bitcoin/Script";
import P2wpkh "../../src/bitcoin/P2wpkh";
import Types "../../src/bitcoin/Types";
import Hex "../Hex";
import ByteUtils "../../src/ByteUtils";




type AddressTestCase = {
  compressedPublicKeyHex : Text;
  expectedAddressMainnet : Types.P2WPkhAddress;
  expectedAddressTestnet : Types.P2WPkhAddress;
};

type MakeScriptTestCase = {
  address : Types.P2WPkhAddress;
  expectedScriptHex : Text;
};

type DecodeAddressTestCase = {
  address : Types.P2WPkhAddress;
  expectedHrp : Text;
  expectedHash160Hex : Text;
};

// Test cases obtained from:
// - https://guggero.github.io/cryptography-toolkit/#!/hd-wallet
// - https://guggero.github.io/cryptography-toolkit/#!/ecc

let addressTestData : [AddressTestCase] = [
  {
    compressedPublicKeyHex = "039f791acf20c911a766979dc25c3a2a5e86a281933029bca02f67a8ad57726fb3";
    expectedAddressMainnet = "bc1qjn90fmjwht2z07zq32lxalu9j4vrdee9fswawk";
    expectedAddressTestnet = "tb1qjn90fmjwht2z07zq32lxalu9j4vrdee9rk4w49";
  },
  {
    compressedPublicKeyHex = "02fafa7ba8e2c69041f1081b58d1a8bd74a62b846756094078b5d8d71b25a2315b";
    expectedAddressMainnet = "bc1q2nwhc5jyu4y266awtw4pz8argftwv59ntvjvek";
    expectedAddressTestnet = "tb1q2nwhc5jyu4y266awtw4pz8argftwv59np2flz9";
  },
];

let makeScriptTestCases : [MakeScriptTestCase] = [
  {
    address = "bc1qjn90fmjwht2z07zq32lxalu9j4vrdee9fswawk";
    // script = OP_0 PUSH20 <pubkey hash160>
    expectedScriptHex = "001494caf4ee4ebad427f8408abe6eff85955836e725";
  },
  {
    address = "tb1qjn90fmjwht2z07zq32lxalu9j4vrdee9rk4w49";
    expectedScriptHex = "001494caf4ee4ebad427f8408abe6eff85955836e725";
  },
  {
    address = "bc1q2nwhc5jyu4y266awtw4pz8argftwv59ntvjvek";
    expectedScriptHex = "001454dd7c5244e548ad6bae5baa111fa34256e650b3";
  },
  {
    address = "tb1q2nwhc5jyu4y266awtw4pz8argftwv59np2flz9";
    expectedScriptHex = "001454dd7c5244e548ad6bae5baa111fa34256e650b3";
  },
];


let decodeAddressTestCases : [DecodeAddressTestCase] = [
  {
    address = "bc1qjn90fmjwht2z07zq32lxalu9j4vrdee9fswawk";
    expectedHrp = "bc";
    expectedHash160Hex = "94caf4ee4ebad427f8408abe6eff85955836e725";
  },
  {
    address = "tb1qjn90fmjwht2z07zq32lxalu9j4vrdee9rk4w49";
    expectedHrp = "tb";
    expectedHash160Hex = "94caf4ee4ebad427f8408abe6eff85955836e725";
  },
  {
    address = "tb1q2nwhc5jyu4y266awtw4pz8argftwv59np2flz9";
    expectedHrp = "tb";
    expectedHash160Hex = "54dd7c5244e548ad6bae5baa111fa34256e650b3";
  },
  {
    address = "bc1q2nwhc5jyu4y266awtw4pz8argftwv59ntvjvek";
    expectedHrp = "bc";
    expectedHash160Hex = "54dd7c5244e548ad6bae5baa111fa34256e650b3";
  },
];


func testP2wpkhDeriveAddress(testCase : AddressTestCase) {
  let pkBytes = switch (Hex.decode(testCase.compressedPublicKeyHex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad hex key: " # e);
  };
  let sec1Key : EcdsaTypes.Sec1PublicKey = (pkBytes, Curves.secp256k1);

  switch (P2wpkh.deriveAddress(#Mainnet, sec1Key)) {
    case (#ok addr) assert (testCase.expectedAddressMainnet == addr);
    case (#err msg) Debug.trap("Mainnet derivation failed: " # msg);
  };

  switch (P2wpkh.deriveAddress(#Testnet, sec1Key)) {
    case (#ok addr) assert (testCase.expectedAddressTestnet == addr);
    case (#err msg) Debug.trap("Testnet derivation failed: " # msg);
  };
};

func testP2wpkhDecodeAddress(testCase : DecodeAddressTestCase) {
  let expectedHash = switch (Hex.decode(testCase.expectedHash160Hex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad hex hash: " # e);
  };

  switch (P2wpkh.decodeAddress(testCase.address)) {
    case (#ok decoded) {
      assert (testCase.expectedHrp == decoded.hrp);
      assert (
        Array.equal(
          expectedHash,
          decoded.publicKeyHash,
          Nat8.equal,
        ) == true
      );
    };
    case (#err msg) {
      Debug.trap("Decode failed: " # msg);
    };
  };
};

func testP2wpkhMakeScript(testCase : MakeScriptTestCase) {
  let expectedScriptContentBytes = switch (Hex.decode(testCase.expectedScriptHex)) {
    case (#ok bytes) bytes;
    case (#err e) Debug.trap("Bad hex script: " # e);
  };

  let prefixBytes = ByteUtils.writeVarint(expectedScriptContentBytes.size());

  let finalExpectedBytes = Array.append<Nat8>(prefixBytes, expectedScriptContentBytes);

  switch (P2wpkh.makeScript(testCase.address)) {
    case (#ok script) {
      let actualBytes = Script.toBytes(script);
      assert (
        Array.equal(
          finalExpectedBytes,
          actualBytes,
          Nat8.equal,
        ) == true
      );
    };
    case (#err msg) {
      Debug.trap("MakeScript failed: " # msg);
    };
  };
};

let runTest = TestUtils.runTestWithDefaults;

runTest({
  title = "P2WPKH address derivation";
  fn = testP2wpkhDeriveAddress;
  vectors = addressTestData;
});

runTest({
  title = "Decode P2WPKH address";
  fn = testP2wpkhDecodeAddress;
  vectors = decodeAddressTestCases;
});

runTest({
  title = "Make P2WPKH script";
  fn = testP2wpkhMakeScript;
  vectors = makeScriptTestCases;
});
