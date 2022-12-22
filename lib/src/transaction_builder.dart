import 'dart:convert';
import 'dart:typed_data';
import 'package:coinslib/src/payments/multisig.dart';
import 'package:coinslib/src/utils/constants/op.dart';
import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import 'utils/script.dart' as bscript;
import 'ecpair.dart';
import 'models/networks.dart';
import 'transaction.dart';
import 'address.dart';
import 'payments/p2pkh.dart';
import 'classify.dart';
import 'input_signature.dart';

class TransactionBuilder {
  NetworkType network;
  int maximumFeeRate;
  final List<Input> _inputs = [];
  final Transaction _tx = Transaction()..version = 2;
  final Map _prevTxSet = {};

  TransactionBuilder({NetworkType? network, int? maximumFeeRate})
      : network = network ?? bitcoin,
        maximumFeeRate = maximumFeeRate ?? 2500;

  List<Input> get inputs => _inputs;

  factory TransactionBuilder.fromTransaction(
    Transaction transaction, [
    NetworkType? network,
  ]) {
    final txb = TransactionBuilder(network: network);
    // Copy transaction fields
    txb.setVersion(transaction.version);
    txb.setLockTime(transaction.locktime);

    // Copy outputs (done first to avoid signature invalidation)
    for (final txOut in transaction.outs) {
      txb.addOutput(txOut.script, txOut.value!);
    }

    for (final txIn in transaction.ins) {
      txb._addInputUnsafe(
        txIn.hash!,
        txIn.index!,
        Input(
          sequence: txIn.sequence,
          script: txIn.script,
          witness: txIn.witness,
        ),
      );
    }

    return txb;
  }

  setVersion(int version) {
    if (version < 0 || version > 0xFFFFFFFF) {
      throw ArgumentError('Expected Uint32');
    }
    _tx.version = version;
  }

  setLockTime(int locktime) {
    if (locktime < 0 || locktime > 0xFFFFFFFF) {
      throw ArgumentError('Expected Uint32');
    }
    // if any signatures exist, throw
    if (_inputs.any((input) => input.signatures.isNotEmpty)) {
      throw ArgumentError(
        'Can\'t set lock time; this would invalidate signatures',
      );
    }
    _tx.locktime = locktime;
  }

  int _addOutputFromScript(Uint8List script, BigInt value) {
    if (!_canModifyOutputs()) {
      throw ArgumentError('No, this would invalidate signatures');
    }
    return _tx.addOutput(script, value);
  }

  int addOutput(dynamic data, BigInt value) {
    late Uint8List scriptPubKey;
    if (data is String) {
      scriptPubKey = Address.addressToOutputScript(data, network);
    } else if (data is Uint8List) {
      scriptPubKey = data;
    } else {
      throw ArgumentError('Address invalid');
    }
    return _addOutputFromScript(scriptPubKey, value);
  }

  int addNullOutput(dynamic data) {
    // Encode string to Uint8List or take Uint8List
    late Uint8List pushData;
    if (data is String) {
      pushData = Uint8List.fromList(utf8.encode(data));
    } else if (data is Uint8List) {
      pushData = data;
    } else {
      throw ArgumentError('Invalid data');
    }

    // Enforce the limit of the allowed data size
    if (data.length > network.opreturnSize) {
      throw ArgumentError(
        "Too much data, max OP_RETURN size is ${network.opreturnSize.toString()}",
      );
    }

    // Encode output script with OP_RETURN followed by the push data
    final script = bscript.compile([ops['OP_RETURN'], pushData]);
    return _addOutputFromScript(script, BigInt.zero);
  }

  int addInput(
    dynamic txHash,
    int vout, [
    int? sequence,
    Uint8List? prevOutScript,
  ]) {
    if (!_canModifyInputs()) {
      throw ArgumentError('No, this would invalidate signatures');
    }

    Uint8List hash;
    BigInt? value;

    if (txHash is String) {
      hash = Uint8List.fromList(HEX.decode(txHash).reversed.toList());
    } else if (txHash is Uint8List) {
      hash = txHash;
    } else if (txHash is Transaction) {
      final txOut = txHash.outs[vout];
      prevOutScript = txOut.script;
      value = txOut.value;
      hash = txHash.getHash();
    } else {
      throw ArgumentError('txHash invalid');
    }

    return _addInputUnsafe(
      hash,
      vout,
      Input(sequence: sequence, prevOutScript: prevOutScript, value: value),
    );
  }

  /// Sign the transaction input at [vin] with [keyPair]. The [witnessScript]
  /// can be provided for a P2WSH input and must be a simple CHECKMULTISIG
  /// script.
  sign({
    required int vin,
    required ECPair keyPair,
    BigInt? witnessValue,
    Uint8List? witnessScript,
    Uint8List? redeemScript,
    int? hashType,
  }) {
    hashType ??= sigHashAll;

    if (keyPair.network != network) {
      throw ArgumentError('Inconsistent network');
    }

    if (vin >= _inputs.length) {
      throw ArgumentError('No input at index: $vin');
    }

    if (_needsOutputs(hashType)) {
      throw ArgumentError('Transaction needs outputs');
    }

    final input = _inputs[vin];

    // Do not sign if fully signed
    if (input.isComplete()) {
      throw ArgumentError("Can't sign a complete transaction input");
    }

    final ourPubKey = keyPair.publicKey!;

    if (witnessScript != null) {
      // Assume multisig P2WSH when witnessScript provided

      input.prevOutType = scriptTypes['P2WSH'];
      input.witness = [];
      input.signScript = witnessScript;

      // Decompile and parse the multisig script
      final multisig = MultisigScript.fromScriptBytes(witnessScript);

      // Extract public keys from the witnessScript
      input.pubkeys = multisig.pubkeys;
      input.threshold = multisig.threshold;
    } else if (redeemScript != null) {
      // P2SH input when redeemScript is provided

      final multisig = MultisigScript.fromScriptBytes(redeemScript);

      input.prevOutType = scriptTypes['P2SH'];
      input.signScript = redeemScript;
      input.pubkeys = multisig.pubkeys;
      input.threshold = multisig.threshold;
    } else if (input.prevOutScript != null &&
        classifyOutput(input.prevOutScript!) == scriptTypes['P2WPKH']) {
      input.prevOutType = scriptTypes['P2WPKH'];
      input.witness = [];
      input.pubkeys = [ourPubKey];
      input.signScript = P2PKH.fromPublicKey(ourPubKey).outputScript;
    } else {
      input.prevOutType = scriptTypes['P2PKH'];
      input.pubkeys = [ourPubKey];
      input.signScript = P2PKH.fromPublicKey(ourPubKey).outputScript;
    }

    // Check outPubKey is in input.pubkeys or we cannot sign
    if (input.pubkeys!.every((pk) => !ListEquality().equals(ourPubKey, pk))) {
      throw ArgumentError('Key pair cannot sign for this input');
    }

    if (input.isWitness) {
      if (witnessValue == null) {
        throw ArgumentError('Require previous output value for witness inputs');
      }
      input.value = witnessValue;
    }

    // Add signature to list of signatures
    Uint8List sighash = _tx.signatureHash(vin, input, hashType);
    final newSignature = InputSignature(
      rawSignature: keyPair.sign(sighash),
      hashType: hashType,
    );
    input.addSignature(newSignature);
  }

  Transaction build() {
    return _build(false);
  }

  Transaction buildIncomplete() {
    return _build(true);
  }

  Iterable<Uint8List> _orderedEncodedSigs({
    required int inIndex,
    required Input input,
  }) {
    // Ensure signatures are matched to public keys in the correct order

    final pubkeys = input.pubkeys!;
    List<InputSignature?> positionedSigs = List.filled(pubkeys.length, null);

    for (final sig in input.signatures) {
      var matched = false;
      for (var i = 0; i < pubkeys.length; i++) {
        // Check if the signature matches the public key
        if (sig.verify(
          pubkeys[i],
          _tx.signatureHash(inIndex, input, sig.hashType),
        )) {
          // Add signature in this position
          positionedSigs[i] = sig;
          matched = true;
          break;
        }
      }

      if (!matched) {
        throw ArgumentError(
          'A signature in an input has no corresponding public key',
        );
      }
    }

    // Remove nulls
    return positionedSigs.whereType<InputSignature>().map(
          (sig) => sig.encode(),
        );
  }

  Transaction _build(bool allowIncomplete) {
    if (!allowIncomplete) {
      if (_tx.ins.isEmpty) {
        throw ArgumentError('Transaction has no inputs');
      }
      if (_tx.outs.isEmpty) {
        throw ArgumentError('Transaction has no outputs');
      }
    }

    final tx = Transaction.clone(_tx);

    for (var i = 0; i < _inputs.length; i++) {
      final input = _inputs[i];

      if (!input.isComplete() && !allowIncomplete) {
        throw ArgumentError('Transaction is not complete');
      }

      // Set input type
      tx.ins[i].prevOutType = input.prevOutType;

      if (input.prevOutType == scriptTypes['P2WSH']) {
        // Build multisig P2WSH even when incomplete

        tx.setInputScript(i, Uint8List(0));

        if (input.hasNewSignatures) {
          // Need to rebuild witness with new signature data, ensuring that it
          // is ordered correctly
          input.witness = [
            Uint8List.fromList([]),
            // Ensure signatures are in the correct order for multisig
            ..._orderedEncodedSigs(inIndex: i, input: input),
            input.signScript!
          ];
        }

        tx.setWitness(i, input.witness);
      } else if (input.prevOutType == scriptTypes['P2SH']) {
        // Build P2SH input script even if incomplete

        if (input.hasNewSignatures) {
          final script = bscript.compile([
            0,
            ..._orderedEncodedSigs(inIndex: i, input: input),
            input.signScript!
          ]);

          tx.setInputScript(i, script);
        }
      } else if (input.isComplete()) {
        // Build the following types of input only when complete

        final pubkey = input.pubkeys![0];
        final signature = input.signatures.first.encode();

        if (input.prevOutType == scriptTypes['P2WPKH']) {
          tx.setInputScript(i, Uint8List(0));
          tx.setWitness(i, [signature, pubkey]);
        } else if (input.prevOutType == scriptTypes['P2PKH']) {
          tx.setInputScript(i, bscript.compile([signature, pubkey]));
          tx.setWitness(i, []);
        }
      }
    }

    if (!allowIncomplete) {
      // do not rely on this, its merely a last resort
      if (_overMaximumFees(tx.virtualSize())) {
        throw ArgumentError('Transaction has absurd fees');
      }
    }

    return tx;
  }

  bool _overMaximumFees(int bytes) {
    BigInt sumValues(list) =>
        list.fold(BigInt.zero, (cur, acc) => cur + (acc.value ?? BigInt.zero));
    BigInt incoming = sumValues(_inputs);
    BigInt outgoing = sumValues(_tx.outs);
    BigInt fee = incoming - outgoing;
    BigInt feeRate = fee ~/ BigInt.from(bytes);
    return feeRate > BigInt.from(maximumFeeRate);
  }

  bool _canModifyInputs() {
    return _inputs.every((input) {
      if (input.signatures.isEmpty) return true;
      return input.signatures
          .every((signature) => signature.hashType & sigHashAnyoneCanPay != 0);
    });
  }

  bool _canModifyOutputs() {
    final nInputs = _tx.ins.length;
    final nOutputs = _tx.outs.length;
    return _inputs.every((input) {
      if (input.signatures.isEmpty) return true;
      return input.signatures.every((signature) {
        final hashTypeMod = signature.hashType & 0x1f;
        if (hashTypeMod == sigHashNone) return true;
        if (hashTypeMod == sigHashSingle) {
          // if SIGHASH_SINGLE is set, and nInputs > nOutputs
          // some signatures would be invalidated by the addition
          // of more outputs
          return nInputs <= nOutputs;
        }
        return false;
      });
    });
  }

  bool _needsOutputs(int signingHashType) {
    if (signingHashType == sigHashAll) {
      return _tx.outs.isEmpty;
    }

    // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
    // .build() will fail, but .buildIncomplete() is OK
    return _tx.outs.isEmpty &&
        _inputs.any((input) {
          if (input.signatures.isEmpty) return false;

          return input.signatures
              .any((signature) => signature.hashType & sigHashNone == 0);
        });
  }

  _addInputUnsafe(Uint8List hash, int vout, Input options) {
    String txHash = HEX.encode(hash);
    Input input;

    if (isCoinbaseHash(hash)) {
      throw ArgumentError('coinbase inputs not supported');
    }

    final prevTxOut = '$txHash:$vout';

    if (_prevTxSet[prevTxOut] != null) {
      throw ArgumentError("Duplicate TxOut: $prevTxOut");
    }

    input = options.script != null
        ? Input.expandInput(options.script!, options.witness)
        : Input();

    if (options.value != null) input.value = options.value;

    if (input.prevOutScript == null && options.prevOutScript != null) {
      if (input.pubkeys == null && input.signatures.isEmpty) {
        var expanded = Output.expandOutput(options.prevOutScript!);
        if (expanded.pubkeys != null && expanded.pubkeys!.isNotEmpty) {
          input.pubkeys = expanded.pubkeys;
        }
      }
      input.prevOutScript = options.prevOutScript;
      input.prevOutType = classifyOutput(options.prevOutScript!);
    }

    int vin = _tx.addInput(hash, vout, options.sequence, options.script);
    _inputs.add(input);
    _prevTxSet[prevTxOut] = true;

    return vin;
  }

  Transaction get tx => _tx;

  Map get prevTxSet => _prevTxSet;
}
