import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat8 "mo:core/Nat8";
import { type Result } "mo:core/Types";
import VarArray "mo:core/VarArray";

import Der "../ecdsa/Der";
import Address "Address";
import Script "Script";
import Transaction "Transaction";
import TxInput "TxInput";
import TxOutput "TxOutput";
import Types "Types";
import Witness "Witness";

module {
  type Utxo = Types.Utxo;
  type Satoshi = Types.Satoshi;
  type OutPoint = Types.OutPoint;

  let dustThreshold : Satoshi = 10_000;
  let defaultSequence : Nat32 = 0xffffffff;

  type EcdsaProxy = {
    // Takes a message hash and a derivation path, outputs a signature encoded
    // as the concatenation of big endian representation of r and s values.
    sign : (Blob, [Blob]) -> Blob;
    // Outputs SEC-1 encoded public key and a chain code.
    publicKey : () -> (Blob, Blob);
  };

  // Builds a transaction.
  // `version` is the transaction version. Currently only 1 and 2 are
  // supported.
  // `utxos` is a set of unspent transaction outputs to construct TxInputs from.
  // `destinations` is a list of address-value pairs indicating the amount to
  // transfer to each address.
  // `changeAddress` is an address to return any remaining amount to.
  // `fees` indicate the transaction fees.
  public func buildTransaction(
    version : Nat32,
    utxos : [Utxo],
    destinations : [(Types.Address, Satoshi)],
    changeAddress : Types.Address,
    fees : Satoshi,
  ) : Result<Transaction.Transaction, Text> {

    if (version != 1 and version != 2) {
      return #err("Unexpected version number: " # version.toText());
    };

    // Collect TxOutputs, making space for a potential extra output for change.
    let txOutputs = List.empty<TxOutput.TxOutput>();
    var totalSpend : Satoshi = fees;

    for (dest in destinations.values()) {
      let (destAddr, destAmount) = dest;
      switch (Address.scriptPubKey(destAddr)) {
        case (#ok destScriptPubKey) {
          txOutputs.add(TxOutput.TxOutput(destAmount, destScriptPubKey));
          totalSpend += destAmount;
        };
        case (#err msg) {
          return #err msg;
        };
      };
    };

    // Select which UTXOs to spend. For now, we spend the first available
    // UTXOs.
    var availableFunds : Satoshi = 0;
    let txInputs = List.empty<TxInput.TxInput>();

    label UtxoLoop for (utxo in utxos.values()) {
      availableFunds += utxo.value;
      txInputs.add(TxInput.TxInput(utxo.outpoint, defaultSequence));

      if (availableFunds >= totalSpend) {
        // We have enough inputs to cover the amount we want to spend.
        break UtxoLoop;
      };
    };

    if (availableFunds < totalSpend) {
      return #err "Insufficient balance";
    };

    // If there is remaining amount that is worth considering then include a
    // change TxOutput.
    let remainingAmount : Satoshi = availableFunds - totalSpend;

    if (remainingAmount > dustThreshold) {
      switch (Address.scriptPubKey(changeAddress)) {
        case (#ok chScriptPubKey) {
          txOutputs.add(TxOutput.TxOutput(remainingAmount, chScriptPubKey));
        };
        case (#err msg) {
          return #err msg;
        };
      };
    };

    return #ok(
      Transaction.Transaction(
        version,
        txInputs.toArray(),
        txOutputs.toArray(),
        VarArray.repeat<Witness.Witness>(Witness.EMPTY_WITNESS, txInputs.size()),
        0,
      )
    );
  };

  // Sign given transaction.
  // `sourceAddress` is the spender's address appearing in the TxOutputs being
  // spent from.
  // `ecdsaProxy` is an interface providing ecdsa signing functionality.
  public func signP2pkhTransaction(
    sourceAddress : Types.Address,
    transaction : Transaction.Transaction,
    ecdsaProxy : EcdsaProxy,
    derivationPath : [Blob],
  ) : Result<Transaction.Transaction, Text> {

    // Obtain the scriptPubKey of the source address which is also the
    // scriptPubKey of the Tx output being spent.
    switch (Address.scriptPubKey(sourceAddress)) {
      case (#ok scriptPubKey) {
        // Obtain scriptSigs for each Tx input.
        let scriptSigs = Array.tabulate<Script.Script>(
          transaction.txInputs.size(),
          func(i) {
            let sighash : [Nat8] = transaction.createP2pkhSignatureHash(
              scriptPubKey,
              Nat32.fromIntWrap(i),
              Types.SIGHASH_ALL,
            );
            let signature : Blob = ecdsaProxy.sign(
              Blob.fromArray(sighash),
              derivationPath,
            );
            let encodedSignature : [Nat8] = Der.encodeSignature(signature).toArray();
            // Append the sighash type.
            let encodedSignatureWithSighashType = Array.tabulate<Nat8>(
              encodedSignature.size() + 1,
              func(n) {
                if (n < encodedSignature.size()) {
                  encodedSignature[n];
                } else {
                  Nat8.fromNat(Types.SIGHASH_ALL.toNat());
                };
              },
            );

            // Create Script Sig which looks like:
            // ScriptSig = <Signature> <Public Key>.
            [
              #data encodedSignatureWithSighashType,
              #data(ecdsaProxy.publicKey().0.toArray()),
            ];
          },
        );
        // Assign ScriptSigs to their associated TxInputs.
        for (i in Nat.range(0, scriptSigs.size())) {
          transaction.txInputs[i].script := scriptSigs[i];
        };

        #ok transaction;
      };
      case (#err msg) {
        #err msg;
      };
    };
  };

  // Create and sign a transaction.
  // `sourceAddress` is the spender's address appearing in the TxOutputs being
  // spent from.
  // `ecdsaProxy` is an interface for ECDSA signing functionality.
  // `version` is the transaction version. Currently only 1 and 2 are
  // supported.
  // `utxos` is a set of unspent transaction outputs to construct TxInputs from.
  // `destinations` is a list of address-value pairs indicating the amount to
  // transfer to each address.
  // `changeAddress` is an address to return any remaining amount to.
  // `fees` indicate the transaction fees.
  public func createSignedP2pkhTransaction(
    sourceAddress : Types.Address,
    ecdsaProxy : EcdsaProxy,
    derivationPath : [Blob],
    version : Nat32,
    utxos : [Utxo],
    destinations : [(Types.Address, Satoshi)],
    changeAddress : Types.Address,
    fees : Satoshi,
  ) : Result<Transaction.Transaction, Text> {

    switch (
      buildTransaction(
        version,
        utxos,
        destinations,
        changeAddress,
        fees,
      )
    ) {
      case (#ok transaction) {
        signP2pkhTransaction(sourceAddress, transaction, ecdsaProxy, derivationPath);
      };
      case (#err msg) {
        #err msg;
      };
    };
  };
};
