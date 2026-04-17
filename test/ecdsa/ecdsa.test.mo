// @testmode wasi

import Blob "mo:core/Blob";
import Runtime "mo:core/Runtime";

import Curves "../../src/ec/Curves";
import Der "../../src/ecdsa/Der";
import Ecdsa "../../src/ecdsa/Ecdsa";
import Hex "../Hex";
import PublicKey "../../src/ecdsa/Publickey";
import TestUtils "../TestUtils";
import WycheproofEcdsaTestVectors "wycheproofEcdsaSecp256k1TestVectors";

type WycheproofEcdsaTestCase = WycheproofEcdsaTestVectors.WycheproofEcdsaTestCase;
let runTest = TestUtils.runTestWithDefaults;

func testWycheproofEcdsa(testCase : WycheproofEcdsaTestCase) {
  let (key, sig, msg) = switch (
    Hex.decode(testCase.key),
    Hex.decode(testCase.sig),
    Hex.decode(testCase.msg),
  ) {
    case (#ok(key), #ok(sig), #ok(msg)) { (key, sig, msg) };
    case _ {
      // Converting data from hex failed.
      Runtime.trap("Could not decode test data.");
    };
  };

  switch (
    PublicKey.decode(#sec1(key, Curves.secp256k1)),
    Der.decodeSignature(Blob.fromArray(sig)),
  ) {
    case (#ok(publicKey), #ok(signature)) {
      let actual = Ecdsa.verify(signature, publicKey, msg);
      let expected = testCase.result == "valid" or testCase.result == "acceptable";
      assert (expected == actual);
    };
    case _ {
      assert (testCase.result == "invalid");
    };
  };
};

runTest({
  title = "Wycheproof ECDSA";
  fn = testWycheproofEcdsa;
  vectors = WycheproofEcdsaTestVectors.testVectors;
});
