import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import { type Iter; type Result } "mo:core/Types";
import VarArray "mo:core/VarArray";

import Sha256 "mo:sha2/Sha256";

import ByteUtils "../ByteUtils";
import Common "../Common";
import Hash "../Hash";
import Script "Script";
import TxInput "TxInput";
import TxOutput "TxOutput";
import Types "Types";
import Witness "Witness";

module {
  // Deserialize transaction from data with the following layout:
  // | version | maybe witness flags | len(txIns) | txIns | len(txOuts) | txOuts
  // | locktime | witness if witness flags present |
  public func fromBytes(data : Iter<Nat8>) : Result<Transaction, Text> {

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
    let txInputs = List.empty<TxInput.TxInput>();
    for (_ in Nat.range(0, txInSize)) {
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
    let txOutputs = List.empty<TxOutput.TxOutput>();
    for (_ in Nat.range(0, txOutSize)) {
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
    let witnesses = VarArray.repeat<Witness.Witness>([], txInSize);
    if (has_witness) {
      for (i in Nat.range(0, txInSize)) {
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
        txInputs.toArray(),
        txOutputs.toArray(),
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
      Array.tabulate<Nat8>(
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
      for (i in Nat.range(0, txInputs.size())) {
        txInputs[i].script := [];
      };

      // Set script for current TxIn to given scriptPubKey.
      txInputs[txInputIndex.toNat()].script := scriptPubKey.filter<Script.Instruction>(
        func(instruction) {
          instruction != #opcode(#OP_CODESEPARATOR);
        }
      );

      // Serialize transaction and append SighashType.
      let txData : [Nat8] = toBytes();
      let output : [var Nat8] = VarArray.repeat<Nat8>(0, txData.size() + 4);

      Common.copy(output, 0, txData, 0, txData.size());
      Common.writeLE32(output, txData.size(), sigHashType);

      Hash.doubleSHA256(output.toArray());
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
      let prevouts = txInputs.map<TxInput.TxInput, [Nat8]>(
        func(txin) {
          let vout_buffer = VarArray.repeat<Nat8>(0, 4);
          Common.writeLE32(vout_buffer, 0, txin.prevOutput.vout);
          let prevout = [
            txin.prevOutput.txid.toArray(),
            vout_buffer.toArray(),
          ].flatten();
          prevout;
        }
      );
      assert prevouts.size() == txInputs.size();

      let epoch : [Nat8] = [0x00];

      let sighash_type : [Nat8] = [0x00];
      let nVersion_buffer = VarArray.repeat<Nat8>(0, 4);
      Common.writeLE32(nVersion_buffer, 0, version);
      let nVersion = nVersion_buffer.toArray();

      let nLockTime_buffer = VarArray.repeat<Nat8>(0, 4);
      Common.writeLE32(nLockTime_buffer, 0, locktime);
      let nLockTime = nLockTime_buffer.toArray();
      let sha_prevouts : [Nat8] = Sha256.fromArray(#sha256, prevouts.flatten()).toArray();

      let amounts_bytes = amounts.map<Nat64, [Nat8]>(
        func(amount) {
          let amount_bytes = VarArray.repeat<Nat8>(0, 8);
          Common.writeLE64(amount_bytes, 0, amount);
          amount_bytes.toArray();
        }
      ).flatten();
      let sha_amounts : [Nat8] = Sha256.fromArray(#sha256, amounts_bytes).toArray();

      let scriptpubkeys = VarArray.repeat<[Nat8]>(Script.toBytes(scriptPubKey), txInputs.size());
      let sha_scriptpubkeys : [Nat8] = Sha256.fromArray(#sha256, scriptpubkeys.toArray().flatten()).toArray();

      // ignote the nSequence flag
      // this is inlined generation of the 0xFFFFFFFF flag for each input

      // let sequences = Array.fromVarArray(VarArray.repeat<Nat8>(0xFF, txInputs.size() * 4));
      let sequences_buffer = txInputs.map<TxInput.TxInput, [Nat8]>(
        func(txin) {
          let sequence_buffer = VarArray.repeat<Nat8>(0, 4);
          Common.writeLE32(sequence_buffer, 0, txin.sequence);
          sequence_buffer.toArray();
        }
      );
      let sequences = sequences_buffer.flatten();
      let sha_sequences : [Nat8] = Sha256.fromArray(#sha256, sequences).toArray();

      let outputs_bytes = txOutputs.map<TxOutput.TxOutput, [Nat8]>(
        func(txout : TxOutput.TxOutput) {
          txout.toBytes();
        }
      ).flatten();

      let sha_outputs : [Nat8] = Sha256.fromArray(#sha256, outputs_bytes).toArray();

      let input_index_buffer = VarArray.repeat<Nat8>(0, 4);
      Common.writeLE32(input_index_buffer, 0, txInputIndex);
      let input_index = input_index_buffer.toArray();

      // spend_type = (ext_flag * 2) + annex_present
      let (spend_type, scriptpath_bytes) : ([Nat8], [Nat8]) = switch (maybe_leaf_hash) {
        case (?leaf_hash) {
          // as defined in
          // [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension)
          assert leaf_hash.size() == 32;
          let KEY_VERSION_0 : [Nat8] = [0x00];
          let OP_SEPARATOR_POS : [Nat8] = [0xFF, 0xFF, 0xFF, 0xFF];
          ([0x02], [leaf_hash, KEY_VERSION_0, OP_SEPARATOR_POS].flatten());
        };
        case (null) {
          ([0x00], []);
        };
      };

      let data = [
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
      ].flatten<Nat8>();

      Hash.taggedHash(data, "TapSighash");
    };

    /// Serialize transaction to bytes with layout:
    /// `| version | witness flags if it is present | len(txIns) | txIns | len(txOuts) | txOuts | witnesses | locktime |`
    public func toBytes() : [Nat8] {
      let has_non_empty_witness = witnesses.toArray().foldLeft<Witness.Witness, Bool>(
        false,
        func(accum, witness) {
          (witness.size() > 0) or accum;
        },
      );

      let maybeAdditionalWitnessFlags : [Nat8] = if (has_non_empty_witness) {
        [0x00, 0x01];
      } else { [] };

      // Serialize TxInputs to bytes.
      let serializedTxIns : [[Nat8]] = txInputs.map<TxInput.TxInput, [Nat8]>(
        func(txInput) {
          txInput.toBytes();
        }
      );

      // Serialize TxOutputs to bytes.
      let serializedTxOuts : [[Nat8]] = txOutputs.map<TxOutput.TxOutput, [Nat8]>(
        func(txOutput) {
          txOutput.toBytes();
        }
      );

      // Encode the sizes of TxIns and TxOuts as varint.
      let serializedTxInSize : [Nat8] = ByteUtils.writeVarint(txInputs.size());
      let serializedTxOutSize : [Nat8] = ByteUtils.writeVarint(
        txOutputs.size()
      );

      // Compute total size of all serialized TxInputs.
      let totalTxInSize : Nat = serializedTxIns.foldLeft<[Nat8], Nat>(
        0,
        func(total : Nat, serializedTxIn : [Nat8]) {
          total + serializedTxIn.size();
        },
      );

      // Compute total size of all serialized TxOutputs.
      let totalTxOutSize : Nat = serializedTxOuts.foldLeft<[Nat8], Nat>(
        0,
        func(total : Nat, serializedTxOut : [Nat8]) {
          total + serializedTxOut.size();
        },
      );

      let witnessesBuffer = List.empty<[Nat8]>();

      if (has_non_empty_witness) {
        for (i in Nat.range(0, witnesses.size())) {
          witnessesBuffer.add(Witness.toBytes(witnesses[i]));
        };
      };

      let serializedWitnesses = witnessesBuffer.toArray().flatten();

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
      let output = VarArray.repeat<Nat8>(0, totalSize);
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
      for (serializedTxIn in serializedTxIns.values()) {
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
      for (serializedTxOut in serializedTxOuts.values()) {
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
      let result = output.toArray();
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
      let serializedTxIns : [[Nat8]] = txInputs.map<TxInput.TxInput, [Nat8]>(
        func(txInput) {
          txInput.toBytes();
        }
      );

      // Serialize TxOutputs to bytes.
      let serializedTxOuts : [[Nat8]] = txOutputs.map<TxOutput.TxOutput, [Nat8]>(
        func(txOutput) {
          txOutput.toBytes();
        }
      );

      // Encode the sizes of TxIns and TxOuts as varint.
      let serializedTxInSize : [Nat8] = ByteUtils.writeVarint(txInputs.size());
      let serializedTxOutSize : [Nat8] = ByteUtils.writeVarint(
        txOutputs.size()
      );

      // Compute total size of all serialized TxInputs.
      let totalTxInSize : Nat = serializedTxIns.foldLeft<[Nat8], Nat>(
        0,
        func(total : Nat, serializedTxIn : [Nat8]) {
          total + serializedTxIn.size();
        },
      );

      // Compute total size of all serialized TxOutputs.
      let totalTxOutSize : Nat = serializedTxOuts.foldLeft<[Nat8], Nat>(
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
      let output = VarArray.repeat<Nat8>(0, totalSize);
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
      for (serializedTxIn in serializedTxIns.values()) {
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
      for (serializedTxOut in serializedTxOuts.values()) {
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
      output.toArray();
    };
  };
};
