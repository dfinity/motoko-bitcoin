import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Nat32 "mo:base/Nat32";
import Nat "mo:base/Nat";
import Blob "mo:base/Blob";
import Text "mo:base/Text";
import Result "mo:base/Result";
import Hash "../Hash";
import Script "./Script";
import Common "../Common";
import ByteUtils "../ByteUtils";
import Types "./Types";
import TxInput "./TxInput";
import TxOutput "./TxOutput";
import Witness "Witness";
import Sha256 "mo:sha2/Sha256";

module {
  // Deserialize transaction from data with the following layout:
  // | version | maybe witness flags | len(txIns) | txIns | len(txOuts) | txOuts
  // | locktime | witness if witness flags present |
  public func fromBytes(data : Iter.Iter<Nat8>) : Result.Result<Transaction, Text> {

    var has_witness = false;

    let version = switch (ByteUtils.readLE32(data)) {
      case (?version) {
        version;
      };
      case _ {
        return #err("Could not read version.");
      };
    };

    // There are 2 possible layouts:
    // 1. No witness:
    // | version | txInSize | txIns | txOutSize | txOuts | locktime |
    // 2. Witness:
    //    | version | 0x00 marker | 0x01 flag | txInSize | txIns | txOutSize |
    //    txOuts | witness | locktime |
    // The marker makes the transaction look like a transaction with 0 inputs
    // if interpreted as "no witness".
    // See [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    // for more details.
    //
    // Note: txInSize and txOutSize are the numbers of inputs and outputs and
    // not their actual size in bytes.
    let txInSize = switch (
      ByteUtils.readVarint(data)
    ) {
      case (?0) {
        let witness_flag = data.next();
        if (witness_flag != ?0x01) {
          return #err("Invalid witness flag.");
        };
        has_witness := true;
        switch (ByteUtils.readVarint(data)) {
          case (?txInSize) { txInSize };
          case (null) {
            return #err("Could not read TxInputs size in a transaction with witness.");
          };
        };
      };
      case (?txInSize) { txInSize };
      case (null) {
        return #err("Could not read TxInputs size in a transaction without witness.");
      };
    };

    // Read transaction inputs.
    let txInputs = Buffer.Buffer<TxInput.TxInput>(txInSize);
    for (_ in Iter.range(0, txInSize - 1)) {
      switch (TxInput.fromBytes(data)) {
        case (#ok txIn) {
          txInputs.add(txIn);
        };
        case (#err(msg)) {
          return #err("Could not deserialize TxInput: " # msg);
        };
      };
    };

    // Read number of transaction outputs.
    let txOutSize = switch (ByteUtils.readVarint(data)) {
      case (?txOutSize) {
        txOutSize;
      };
      case _ {
        return #err("Could not read TxOutputs size.");
      };
    };

    // Read transaction outputs.
    let txOutputs = Buffer.Buffer<TxOutput.TxOutput>(txOutSize);
    for (_ in Iter.range(0, txOutSize - 1)) {
      switch (TxOutput.fromBytes(data)) {
        case (#ok txOut) {
          txOutputs.add(txOut);
        };
        case (#err(msg)) {
          return #err("Could not deserialize TxOutput: " # msg);
        };
      };
    };

    // build witnesses if necessary
    var witnesses = Array.init<Witness.Witness>(txInSize, []);
    if (has_witness) {
      for (i in Iter.range(0, txInSize - 1)) {
        switch (Witness.fromBytes(data)) {
          case (#ok witness) {
            witnesses[i] := witness;
          };
          case (#err(msg)) {
            return #err("Could not deserialize Witness: " # msg);
          };
        };
      };
    };

    // Read transaction locktime.
    let locktime : Nat32 = switch (ByteUtils.readLE32(data)) {
      case (?locktime) {
        locktime;
      };
      case _ {
        return #err("Could not read locktime.");
      };
    };

    return #ok(
      Transaction(
        version,
        Buffer.toArray(txInputs),
        Buffer.toArray(txOutputs),
        witnesses,
        locktime,
      )
    );
  };

  // Representation of a Bitcoin transaction.
  public class Transaction(
    version : Nat32,
    _txIns : [TxInput.TxInput],
    _txOuts : [TxOutput.TxOutput],
    _witnesses : [var Witness.Witness],
    locktime : Nat32,
  ) {

    public let txInputs : [TxInput.TxInput] = _txIns;
    public let txOutputs : [TxOutput.TxOutput] = _txOuts;
    public let witnesses : [var Witness.Witness] = _witnesses;

    /// Compute the transaction id by double hashing
    /// `| version | txInSize | txIns | txOutSize | txOuts | locktime |`
    /// and reversing the output.
    ///
    /// The txid does not include the witness if it's present.
    /// As per
    /// [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki),
    /// the id that includes witness is denoted as wtxid.
    public func txid() : [Nat8] {
      let doubleHash : [Nat8] = Hash.doubleSHA256(toBytesIgnoringWitness());
      return Array.tabulate<Nat8>(
        doubleHash.size(),
        func(n : Nat) {
          doubleHash[doubleHash.size() - 1 - n];
        },
      );
    };

    // Create a signature hash for the given TxIn index.
    // Only SIGHASH_ALL is currently supported.
    // Output: Signature Hash.
    public func createP2pkhSignatureHash(
      scriptPubKey : Script.Script,
      txInputIndex : Nat32,
      sigHashType : Types.SighashType,
    ) : [Nat8] {
      let sighashMask : Nat32 = sigHashType & 0x1f;
      assert (sighashMask != Types.SIGHASH_SINGLE);
      assert (sighashMask != Types.SIGHASH_NONE);
      assert (sigHashType & Types.SIGHASH_ANYONECANPAY == 0);

      // Clear scripts for other TxInputs.
      for (i in Iter.range(0, txInputs.size() - 1)) {
        txInputs[i].script := [];
      };

      // Set script for current TxIn to given scriptPubKey.
      txInputs[Nat32.toNat(txInputIndex)].script := Array.filter<Script.Instruction>(
        scriptPubKey,
        func(instruction) {
          instruction != #opcode(#OP_CODESEPARATOR);
        },
      );

      // Serialize transaction and append SighashType.
      let txData : [Nat8] = toBytes();
      let output : [var Nat8] = Array.init<Nat8>(txData.size() + 4, 0);

      Common.copy(output, 0, txData, 0, txData.size());
      Common.writeLE32(output, txData.size(), sigHashType);

      return Hash.doubleSHA256(Array.freeze(output));
    };

    /// Create a P2TR key spend signature hash for this transaction. This is
    /// computed for each transaction input separately. This function takes in
    /// the `amounts` of the outputs being spent, the `scriptPubKey` of the spender
    /// address and the `txInputIndex` of the input being signed. The full signature
    /// hash computation algorithm is described in
    /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#user-content-Signature_validation_rules).
    public func createTaprootKeySpendSignatureHash(
      amounts : [Nat64],
      scriptPubKey : Script.Script,
      txInputIndex : Nat32,
    ) : [Nat8] {
      createTaprootSignatureHash(amounts, scriptPubKey, txInputIndex, null);
    };

    /// Create a P2TR script spend signature hash for this transaction. This is
    /// computed for each transaction input separately. This function takes in
    /// the `amounts` of the outputs being spent, the `scriptPubKey` of the
    /// spender address, the `txInputIndex` of the input being signed and the
    /// `leaf_hash` of the leaf script. The full signature hash computation
    /// algorithm is described in
    /// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#user-content-Signature_validation_rules)
    /// and
    /// [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki).
    ///
    /// This method traps if the `leaf_hash` is not 32 bytes long.
    public func createTaprootScriptSpendSignatureHash(
      amounts : [Nat64],
      scriptPubKey : Script.Script,
      txInputIndex : Nat32,
      leaf_hash : [Nat8],
    ) : [Nat8] {
      createTaprootSignatureHash(amounts, scriptPubKey, txInputIndex, ?leaf_hash);
    };

    func createTaprootSignatureHash(
      amounts : [Nat64],
      scriptPubKey : Script.Script,
      txInputIndex : Nat32,
      maybe_leaf_hash : ?[Nat8],
    ) : [Nat8] {
      let prevouts = Array.map<TxInput.TxInput, [Nat8]>(
        txInputs,
        func(txin) {
          let vout_buffer = Array.init<Nat8>(4, 0);
          Common.writeLE32(vout_buffer, 0, txin.prevOutput.vout);
          let prevout = Array.flatten([
            Blob.toArray(txin.prevOutput.txid),
            Array.freeze(vout_buffer),
          ]);
          prevout;
        },
      );
      assert prevouts.size() == txInputs.size();

      let epoch : [Nat8] = [0x00];

      let sighash_type : [Nat8] = [0x00];
      var nVersion_buffer = Array.init<Nat8>(4, 0);
      Common.writeLE32(nVersion_buffer, 0, 2);
      let nVersion = Array.freeze<Nat8>(nVersion_buffer);

      let nLockTime : [Nat8] = Array.freeze(Array.init<Nat8>(4, 0));
      let sha_prevouts : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, Array.flatten(prevouts)));

      let amounts_bytes = Array.flatten(
        Array.map<Nat64, [Nat8]>(
          amounts,
          func(amount) {
            let amount_bytes = Array.init<Nat8>(8, 0);
            Common.writeLE64(amount_bytes, 0, amount);
            Array.freeze(amount_bytes);
          },
        )
      );
      let sha_amounts : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, amounts_bytes));

      let scriptpubkeys = Array.init<[Nat8]>(txInputs.size(), Script.toBytes(scriptPubKey));
      let sha_scriptpubkeys : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, Array.flatten(Array.freeze(scriptpubkeys))));

      // ignote the nSequence flag
      // this is inlined generation of the 0xFFFFFFFF flag for each input

      // let sequences = Array.freeze(Array.init<Nat8>(txInputs.size() * 4, 0xFF));
      let sequences_buffer = Array.map<TxInput.TxInput, [Nat8]>(
        txInputs,
        func(txin) {
          let sequence_buffer = Array.init<Nat8>(4, 0);
          Common.writeLE32(sequence_buffer, 0, txin.sequence);
          Array.freeze(sequence_buffer);
        },
      );
      let sequences = Array.flatten(sequences_buffer);
      let sha_sequences : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, sequences));

      let outputs_bytes = Array.flatten(
        Array.map<TxOutput.TxOutput, [Nat8]>(
          txOutputs,
          func(txout : TxOutput.TxOutput) {
            TxOutput.toBytes(txout);
          },
        )
      );

      let sha_outputs : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, outputs_bytes));

      var input_index_buffer = Array.init<Nat8>(4, 0);
      Common.writeLE32(input_index_buffer, 0, txInputIndex);
      let input_index = Array.freeze(input_index_buffer);

      // spend_type = (ext_flag * 2) + annex_present
      let (spend_type, scriptpath_bytes) : ([Nat8], [Nat8]) = switch (maybe_leaf_hash) {
        case (?leaf_hash) {
          // as defined in
          // [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension)
          assert leaf_hash.size() == 32;
          let KEY_VERSION_0 : [Nat8] = [0x00];
          let OP_SEPARATOR_POS : [Nat8] = [0xFF, 0xFF, 0xFF, 0xFF];
          ([0x02], Array.flatten([leaf_hash, KEY_VERSION_0, OP_SEPARATOR_POS]));
        };
        case (null) {
          ([0x00], []);
        };
      };

      let data = Array.flatten<Nat8>([
        epoch,
        sighash_type,
        nVersion,
        nLockTime,
        sha_prevouts,
        sha_amounts,
        sha_scriptpubkeys,
        sha_sequences,
        sha_outputs,
        spend_type,
        input_index,
        scriptpath_bytes,
      ]);

      return Hash.taggedHash(data, "TapSighash");
    };

    /// Serialize transaction to bytes with layout:
    /// `| version | witness flags if it is present | len(txIns) | txIns | len(txOuts) | txOuts | witnesses | locktime |`
    public func toBytes() : [Nat8] {
      let has_non_empty_witness = Array.foldLeft<Witness.Witness, Bool>(
        Array.freeze(witnesses),
        false,
        func(accum, witness) {
          (witness.size() > 0) or accum;
        },
      );

      let maybeAdditionalWitnessFlags : [Nat8] = if (has_non_empty_witness) {
        [0x00, 0x01];
      } else { [] };

      // Serialize TxInputs to bytes.
      let serializedTxIns : [[Nat8]] = Array.map<TxInput.TxInput, [Nat8]>(
        txInputs,
        func(txInput) {
          txInput.toBytes();
        },
      );

      // Serialize TxOutputs to bytes.
      let serializedTxOuts : [[Nat8]] = Array.map<TxOutput.TxOutput, [Nat8]>(
        txOutputs,
        func(txOutput) {
          txOutput.toBytes();
        },
      );

      // Encode the sizes of TxIns and TxOuts as varint.
      let serializedTxInSize : [Nat8] = ByteUtils.writeVarint(txInputs.size());
      let serializedTxOutSize : [Nat8] = ByteUtils.writeVarint(
        txOutputs.size()
      );

      // Compute total size of all serialized TxInputs.
      let totalTxInSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxIns,
        0,
        func(total : Nat, serializedTxIn : [Nat8]) {
          total + serializedTxIn.size();
        },
      );

      // Compute total size of all serialized TxOutputs.
      let totalTxOutSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxOuts,
        0,
        func(total : Nat, serializedTxOut : [Nat8]) {
          total + serializedTxOut.size();
        },
      );

      let witnessesBuffer = Buffer.Buffer<[Nat8]>(0);

      if (has_non_empty_witness) {
        for (i in Iter.range(0, witnesses.size() - 1)) {
          witnessesBuffer.add(Witness.toBytes(witnesses[i]));
        };
      };

      let serializedWitnesses = Array.flatten(Buffer.toArray(witnessesBuffer));

      // Total size of output excluding sigHashType.
      let totalSize : Nat =
      // 4 bytes for version.
      4
      // 2 additional bytes if witness is present.
      + maybeAdditionalWitnessFlags.size()
      // transaction inputs and outputs
      + serializedTxInSize.size() + totalTxInSize + serializedTxOutSize.size() + totalTxOutSize
      // serialized witnesses if any
      + serializedWitnesses.size()
      // 4 bytes for locktime.
      + 4;
      let output = Array.init<Nat8>(totalSize, 0);
      var outputOffset = 0;

      // Write version.
      Common.writeLE32(output, outputOffset, version);
      outputOffset += 4;

      Common.copy(
        output,
        outputOffset,
        maybeAdditionalWitnessFlags,
        0,
        maybeAdditionalWitnessFlags.size(),
      );
      outputOffset += maybeAdditionalWitnessFlags.size();

      // Write TxInputs size.
      Common.copy(
        output,
        outputOffset,
        serializedTxInSize,
        0,
        serializedTxInSize.size(),
      );
      outputOffset += serializedTxInSize.size();

      // Write serialized TxInputs.
      for (serializedTxIn in serializedTxIns.vals()) {
        Common.copy(
          output,
          outputOffset,
          serializedTxIn,
          0,
          serializedTxIn.size(),
        );
        outputOffset += serializedTxIn.size();
      };

      // Write TxOutputs size.
      Common.copy(
        output,
        outputOffset,
        serializedTxOutSize,
        0,
        serializedTxOutSize.size(),
      );
      outputOffset += serializedTxOutSize.size();

      // Write serialized TxOutputs.
      for (serializedTxOut in serializedTxOuts.vals()) {
        Common.copy(
          output,
          outputOffset,
          serializedTxOut,
          0,
          serializedTxOut.size(),
        );
        outputOffset += serializedTxOut.size();
      };

      Common.copy(
        output,
        outputOffset,
        serializedWitnesses,
        0,
        serializedWitnesses.size(),
      );
      outputOffset += serializedWitnesses.size();

      // Write locktime.
      Common.writeLE32(output, outputOffset, locktime);
      outputOffset += 4;

      assert (outputOffset == output.size());
      let result = Array.freeze(output);
      result;
    };

    /// Serialize transaction to bytes with layout:
    /// `| version | len(txIns) | txIns | len(txOuts) | txOuts | locktime |`
    ///
    /// This function is required to compute the transaction txid if it contains a
    /// witness, since the txid is a hash over the serialized transaction
    /// ignoring the witness. See
    /// [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    /// for more details.
    public func toBytesIgnoringWitness() : [Nat8] {
      // Serialize TxInputs to bytes.
      let serializedTxIns : [[Nat8]] = Array.map<TxInput.TxInput, [Nat8]>(
        txInputs,
        func(txInput) {
          txInput.toBytes();
        },
      );

      // Serialize TxOutputs to bytes.
      let serializedTxOuts : [[Nat8]] = Array.map<TxOutput.TxOutput, [Nat8]>(
        txOutputs,
        func(txOutput) {
          txOutput.toBytes();
        },
      );

      // Encode the sizes of TxIns and TxOuts as varint.
      let serializedTxInSize : [Nat8] = ByteUtils.writeVarint(txInputs.size());
      let serializedTxOutSize : [Nat8] = ByteUtils.writeVarint(
        txOutputs.size()
      );

      // Compute total size of all serialized TxInputs.
      let totalTxInSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxIns,
        0,
        func(total : Nat, serializedTxIn : [Nat8]) {
          total + serializedTxIn.size();
        },
      );

      // Compute total size of all serialized TxOutputs.
      let totalTxOutSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxOuts,
        0,
        func(total : Nat, serializedTxOut : [Nat8]) {
          total + serializedTxOut.size();
        },
      );

      // Total size of output excluding sigHashType.
      let totalSize : Nat =
      // 4 bytes for version.
      4
      // transaction inputs and outputs
      + serializedTxInSize.size() + totalTxInSize + serializedTxOutSize.size() + totalTxOutSize
      // 4 bytes for locktime.
      + 4;
      let output = Array.init<Nat8>(totalSize, 0);
      var outputOffset = 0;

      // Write version.
      Common.writeLE32(output, outputOffset, version);
      outputOffset += 4;

      // Write TxInputs size.
      Common.copy(
        output,
        outputOffset,
        serializedTxInSize,
        0,
        serializedTxInSize.size(),
      );
      outputOffset += serializedTxInSize.size();

      // Write serialized TxInputs.
      for (serializedTxIn in serializedTxIns.vals()) {
        Common.copy(
          output,
          outputOffset,
          serializedTxIn,
          0,
          serializedTxIn.size(),
        );
        outputOffset += serializedTxIn.size();
      };

      // Write TxOutputs size.
      Common.copy(
        output,
        outputOffset,
        serializedTxOutSize,
        0,
        serializedTxOutSize.size(),
      );
      outputOffset += serializedTxOutSize.size();

      // Write serialized TxOutputs.
      for (serializedTxOut in serializedTxOuts.vals()) {
        Common.copy(
          output,
          outputOffset,
          serializedTxOut,
          0,
          serializedTxOut.size(),
        );
        outputOffset += serializedTxOut.size();
      };

      // Write locktime.
      Common.writeLE32(output, outputOffset, locktime);
      outputOffset += 4;

      assert (outputOffset == output.size());
      Array.freeze(output);
    };
  };
};
