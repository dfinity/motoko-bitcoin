import Transaction "../../src/bitcoin/Transaction";
import TxInput "../../src/bitcoin/TxInput";
import TxOutput "../../src/bitcoin/TxOutput";
import P2pkh "../../src/bitcoin/P2pkh";
import Witness "../../src/bitcoin/Witness";
import Curves "../../src/ec/Curves";
import TestUtils "../TestUtils";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import Blob "mo:base/Blob";

type TxInput = {
  txid : [Nat8];
  vout : Nat32;
  seq : Nat32;
  sigder : [Nat8];
  publicKey : [Nat8];
};

type TxOutput = { amount : Nat64; publicKey : [Nat8] };

type TransactionTestCase = {
  version : Nat32;
  txIns : [TxInput];
  txOuts : [TxOutput];
  expectedBytes : [Nat8];
  expectedId : [Nat8];
};

func makeTransaction(testCase : TransactionTestCase) : Transaction.Transaction {
  let txIns = Array.map<TxInput, TxInput.TxInput>(
    testCase.txIns,
    func(input : TxInput) {
      // Convert RPC byte-order to Internal byte-order.
      let txid = Array.tabulate<Nat8>(
        input.txid.size(),
        func(n : Nat) {
          input.txid[input.txid.size() - 1 - n];
        },
      );
      let tx = TxInput.TxInput(
        { txid = Blob.fromArray(txid); vout = input.vout },
        input.seq,
      );
      tx.script := [#data(input.sigder), #data(input.publicKey)];
      tx;
    },
  );
  let txOuts = Array.map<TxOutput, TxOutput.TxOutput>(
    testCase.txOuts,
    func(output : TxOutput) {
      switch (
        P2pkh.makeScript(
          P2pkh.deriveAddress(#Mainnet, (output.publicKey, Curves.secp256k1))
        )
      ) {
        case (#ok script) {
          TxOutput.TxOutput(output.amount, script);
        };
        case (#err msg) {
          Debug.trap(msg);
        };
      };
    },
  );

  let emptyWitness = Array.thaw<Witness.Witness>([]);

  return Transaction.Transaction(testCase.version, txIns, txOuts, emptyWitness, 0);
};

let transactionTestCases : [TransactionTestCase] = [{
  version = 1;
  txIns = [
    {
      // prettier-ignore
      txid = [
        0x24, 0x5e, 0x2d, 0x1f, 0x87, 0x41, 0x58, 0x36, 0xcb, 0xb7,
        0xb0, 0xbc, 0x84, 0xe4, 0x0f, 0x4c, 0xa1, 0xd2, 0xa8, 0x12,
        0xbe, 0x0e, 0xda, 0x38, 0x1f, 0x02, 0xfb, 0x22, 0x24, 0xb4,
        0xad, 0x69
      ];
      vout = 0;
      seq = 0xffffffff;
      // prettier-ignore
      sigder = [
        0x30, 0x44, 0x02, 0x20, 0x19, 0x9a, 0x6a, 0xa5, 0x63, 0x06, 0xce, 0xbc,
        0xda, 0xcd, 0x1e, 0xba, 0x26, 0xb5, 0x5e, 0xaf, 0x6f, 0x92, 0xeb, 0x46,
        0xeb, 0x90, 0xd1, 0xb7, 0xe7, 0x72, 0x4b, 0xac, 0xbe, 0x1d, 0x19, 0x14,
        0x02, 0x20, 0x10, 0x1c, 0x0d, 0x46, 0xe0, 0x33, 0x36, 0x1c, 0x60, 0x53,
        0x6b, 0x69, 0x89, 0xef, 0xdd, 0x6f, 0xa6, 0x92, 0x26, 0x5f, 0xcd, 0xa1,
        0x64, 0x67, 0x6e, 0x2f, 0x49, 0x88, 0x58, 0x71, 0x03, 0x8a, 0x01
      ];
      // prettier-ignore
      publicKey = [
        0x03, 0x9a, 0xc8, 0xba, 0xc8, 0xf6, 0xd9, 0x16, 0xb8, 0xa8, 0x5b, 0x45,
        0x8e, 0x08, 0x7e, 0x0c, 0xd0, 0x7e, 0x6a, 0x76, 0xa6, 0xbf, 0xdd, 0xe9,
        0xbb, 0x76, 0x6b, 0x17, 0x08, 0x6d, 0x9a, 0x5c, 0x8a
      ];
    },
    {
      // prettier-ignore
      txid = [
        0x24, 0x5e, 0x2d, 0x1f, 0x87, 0x41, 0x58, 0x36, 0xcb, 0xb7,
        0xb0, 0xbc, 0x84, 0xe4, 0x0f, 0x4c, 0xa1, 0xd2, 0xa8, 0x12,
        0xbe, 0x0e, 0xda, 0x38, 0x1f, 0x02, 0xfb, 0x22, 0x24, 0xb4,
        0xad, 0x69
      ];
      vout = 1;
      seq = 0xffffffff;
      // prettier-ignore
      sigder = [
        0x30, 0x45, 0x02, 0x21, 0x00, 0x84, 0xec, 0x43, 0x23, 0xed, 0x07, 0xda,
        0x4a, 0xf6, 0x46, 0x20, 0x91, 0xb4, 0x67, 0x62, 0x50, 0xc3, 0x77, 0x52,
        0x73, 0x30, 0x19, 0x1a, 0x3f, 0xf3, 0xf5, 0x59, 0xa8, 0x8b, 0xea, 0xe2,
        0xe2, 0x02, 0x20, 0x77, 0x25, 0x13, 0x92, 0xec, 0x2f, 0x52, 0x32, 0x7c,
        0xb7, 0x29, 0x6b, 0xe8, 0x9c, 0xc0, 0x01, 0x51, 0x6e, 0x40, 0x39, 0xba,
        0xdd, 0x2a, 0xd7, 0xbb, 0xc9, 0x50, 0xc4, 0xc1, 0xb6, 0xd7, 0xcc, 0x01
      ];
      // prettier-ignore
      publicKey = [
        0x03, 0xb9, 0xb5, 0x54, 0xe2, 0x50, 0x22, 0xc2, 0xae, 0x54, 0x9b, 0x0c,
        0x30, 0xc1, 0x8d, 0xf0, 0xa8, 0xe0, 0x49, 0x52, 0x23, 0xf6, 0x27, 0xae,
        0x38, 0xdf, 0x09, 0x92, 0xef, 0xb4, 0x77, 0x94, 0x75
      ]
    },
  ];
  txOuts = [{
    amount = 95000;
    // prettier-ignore
      publicKey = [
        0x03, 0x17, 0x10, 0x20, 0x58, 0x5c, 0x37, 0x23, 0xa0, 0x40, 0x29, 0xe5,
        0x61, 0xb8, 0x9e, 0xd2, 0xd5, 0xed, 0xf9, 0x04, 0xb6, 0xca, 0x58, 0x61,
        0xcd, 0x60, 0x92, 0xc1, 0x4c, 0x88, 0x04, 0x98, 0x0c
      ]
  }];
  // prettier-ignore
  expectedBytes = [
    0x01, 0x00, 0x00, 0x00, 0x02, 0x69, 0xad, 0xb4, 0x24, 0x22, 0xfb, 0x02,
    0x1f, 0x38, 0xda, 0x0e, 0xbe, 0x12, 0xa8, 0xd2, 0xa1, 0x4c, 0x0f, 0xe4,
    0x84, 0xbc, 0xb0, 0xb7, 0xcb, 0x36, 0x58, 0x41, 0x87, 0x1f, 0x2d, 0x5e,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x47, 0x30, 0x44, 0x02, 0x20, 0x19,
    0x9a, 0x6a, 0xa5, 0x63, 0x06, 0xce, 0xbc, 0xda, 0xcd, 0x1e, 0xba, 0x26,
    0xb5, 0x5e, 0xaf, 0x6f, 0x92, 0xeb, 0x46, 0xeb, 0x90, 0xd1, 0xb7, 0xe7,
    0x72, 0x4b, 0xac, 0xbe, 0x1d, 0x19, 0x14, 0x02, 0x20, 0x10, 0x1c, 0x0d,
    0x46, 0xe0, 0x33, 0x36, 0x1c, 0x60, 0x53, 0x6b, 0x69, 0x89, 0xef, 0xdd,
    0x6f, 0xa6, 0x92, 0x26, 0x5f, 0xcd, 0xa1, 0x64, 0x67, 0x6e, 0x2f, 0x49,
    0x88, 0x58, 0x71, 0x03, 0x8a, 0x01, 0x21, 0x03, 0x9a, 0xc8, 0xba, 0xc8,
    0xf6, 0xd9, 0x16, 0xb8, 0xa8, 0x5b, 0x45, 0x8e, 0x08, 0x7e, 0x0c, 0xd0,
    0x7e, 0x6a, 0x76, 0xa6, 0xbf, 0xdd, 0xe9, 0xbb, 0x76, 0x6b, 0x17, 0x08,
    0x6d, 0x9a, 0x5c, 0x8a, 0xff, 0xff, 0xff, 0xff, 0x69, 0xad, 0xb4, 0x24,
    0x22, 0xfb, 0x02, 0x1f, 0x38, 0xda, 0x0e, 0xbe, 0x12, 0xa8, 0xd2, 0xa1,
    0x4c, 0x0f, 0xe4, 0x84, 0xbc, 0xb0, 0xb7, 0xcb, 0x36, 0x58, 0x41, 0x87,
    0x1f, 0x2d, 0x5e, 0x24, 0x01, 0x00, 0x00, 0x00, 0x6b, 0x48, 0x30, 0x45,
    0x02, 0x21, 0x00, 0x84, 0xec, 0x43, 0x23, 0xed, 0x07, 0xda, 0x4a, 0xf6,
    0x46, 0x20, 0x91, 0xb4, 0x67, 0x62, 0x50, 0xc3, 0x77, 0x52, 0x73, 0x30,
    0x19, 0x1a, 0x3f, 0xf3, 0xf5, 0x59, 0xa8, 0x8b, 0xea, 0xe2, 0xe2, 0x02,
    0x20, 0x77, 0x25, 0x13, 0x92, 0xec, 0x2f, 0x52, 0x32, 0x7c, 0xb7, 0x29,
    0x6b, 0xe8, 0x9c, 0xc0, 0x01, 0x51, 0x6e, 0x40, 0x39, 0xba, 0xdd, 0x2a,
    0xd7, 0xbb, 0xc9, 0x50, 0xc4, 0xc1, 0xb6, 0xd7, 0xcc, 0x01, 0x21, 0x03,
    0xb9, 0xb5, 0x54, 0xe2, 0x50, 0x22, 0xc2, 0xae, 0x54, 0x9b, 0x0c, 0x30,
    0xc1, 0x8d, 0xf0, 0xa8, 0xe0, 0x49, 0x52, 0x23, 0xf6, 0x27, 0xae, 0x38,
    0xdf, 0x09, 0x92, 0xef, 0xb4, 0x77, 0x94, 0x75, 0xff, 0xff, 0xff, 0xff,
    0x01, 0x18, 0x73, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9,
    0x14, 0x0c, 0xe1, 0x76, 0x49, 0xc1, 0x30, 0x6c, 0x29, 0x1c, 0xa9, 0xe5,
    0x87, 0xf8, 0x79, 0x3b, 0x5b, 0x06, 0x56, 0x3c, 0xea, 0x88, 0xac, 0x00,
    0x00, 0x00, 0x00
  ];
  // prettier-ignore
  expectedId = [
    0x36, 0x1f, 0xbb, 0x9d, 0xe4, 0xef, 0x5b, 0xfa, 0x8c, 0x1c, 0xbd, 0x5e,
    0xff, 0x81, 0x8e, 0xd9, 0x27, 0x3f, 0x6e, 0x1f, 0x74, 0xb4, 0x1a, 0x7f,
    0x9a, 0x9e, 0x84, 0x27, 0xc9, 0x00, 0x8b, 0x93
  ];
}];

func testTransactionToBytes(testCase : TransactionTestCase) {
  let transaction = makeTransaction(testCase);
  let actualBytes = transaction.toBytes();

  assert (testCase.expectedBytes == actualBytes);
};

func testTransactionId(testCase : TransactionTestCase) {
  let transaction = makeTransaction(testCase);
  let actualId = transaction.txid();

  assert (testCase.expectedId == actualId);
};

let runTest = TestUtils.runTestWithDefaults;

runTest({
  title = "Transaction to bytes";
  fn = testTransactionToBytes;
  vectors = transactionTestCases;
});

runTest({
  title = "Transaction get id";
  fn = testTransactionId;
  vectors = transactionTestCases;
});
