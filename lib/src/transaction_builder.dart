import 'dart:convert';
import 'dart:typed_data';
import 'package:coinslib/src/payments/multisig.dart';
import 'package:coinslib/src/utils/constants/op.dart';
import 'package:collection/equality.dart';
import 'package:hex/hex.dart';
import 'utils/script.dart' as bscript;
import 'ecpair.dart';
import 'models/networks.dart';
import 'transaction.dart';
import 'address.dart';
import 'payments/index.dart' show PaymentData;
import 'payments/p2pkh.dart';
import 'payments/p2wpkh.dart';
import 'classify.dart';

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
    Transaction transaction, [NetworkType? network]
  ) {

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
              witness: txIn.witness
          )
      );
    }

    return txb;

  }

  setVersion(int version) {
    if (version < 0 || version > 0xFFFFFFFF)
      throw ArgumentError('Expected Uint32');
    _tx.version = version;
  }

  setLockTime(int locktime) {
    if (locktime < 0 || locktime > 0xFFFFFFFF)
      throw ArgumentError('Expected Uint32');
    // if any signatures exist, throw
    if (this._inputs.map((input) {
      if (input.signatures == null) return false;
      return input.signatures!.map((s) {
        return s != null;
      }).contains(true);
    }).contains(true)) {
      throw ArgumentError('No, this would invalidate signatures');
    }
    _tx.locktime = locktime;
  }

  int _addOutputFromScript(Uint8List script, int value) {
    if (!_canModifyOutputs()) {
      throw ArgumentError('No, this would invalidate signatures');
    }
    return _tx.addOutput(script, value);
  }

  int addOutput(dynamic data, int value) {
    late Uint8List scriptPubKey;
    if (data is String) {
      scriptPubKey = Address.addressToOutputScript(data, this.network);
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
        'Too much data, max OP_RETURN size is ' +
        network.opreturnSize.toString()
      );
    }

    // Encode output script with OP_RETURN followed by the push data
    final script = bscript.compile([OPS['OP_RETURN'], pushData]);
    return _addOutputFromScript(script, 0);

  }

  int addInput(dynamic txHash, int vout,
      [int? sequence, Uint8List? prevOutScript]) {
    if (!_canModifyInputs()) {
      throw ArgumentError('No, this would invalidate signatures');
    }
    Uint8List hash;
    var value;
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
        Input(sequence: sequence, prevOutScript: prevOutScript, value: value)
    );
  }

  /// Sign the transaction input at [vin] with [keyPair]. The [witnessScript]
  /// can be provided for a P2WSH input and must be a simple CHECKMULTISIG
  /// script.
  sign({
      required int vin,
      required ECPair keyPair,
      int? witnessValue,
      Uint8List? witnessScript,
      int? hashType
  }) {

    hashType ??= SIGHASH_ALL;

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

      input.prevOutType = SCRIPT_TYPES['P2WSH'];
      input.hasWitness = true;
      input.signScript = witnessScript;

      // Decompile and parse the multisig script
      final multisig = MultisigScript.fromScriptBytes(witnessScript);

      // Extract public keys from the witnessScript
      input.pubkeys = multisig.pubkeys;
      input.threshold = multisig.threshold;

    } else if (
        input.prevOutScript != null &&
        classifyOutput(input.prevOutScript!) == SCRIPT_TYPES['P2WPKH']
    ) {

      input.prevOutType = SCRIPT_TYPES['P2WPKH'];
      input.hasWitness = true;
      input.pubkeys = [ourPubKey];
      input.signScript = P2PKH(
        data: PaymentData(pubkey: ourPubKey),
        network: network
      ).data.output;

    } else {

      Uint8List prevOutScript = pubkeyToOutputScript(ourPubKey);
      input.prevOutType = SCRIPT_TYPES['P2PKH'];
      input.pubkeys = [ourPubKey];
      input.signScript = prevOutScript;

    }

    if (input.hasWitness) {
      if (witnessValue == null) {
        throw ArgumentError('Require previous output value for witness inputs');
      }
      input.value = witnessValue;
    }

    // Make signatures list equal to the number of public keys so that they are
    // mapped one to one in order. Null signatures will be removed upon build.
    input.signatures ??= List.filled(input.pubkeys!.length, null);

    late Uint8List signatureHash;
    if (input.hasWitness) {
      signatureHash = _tx.hashForWitnessV0(
          vin, input.signScript!, input.value!, hashType
      );
    } else {
      signatureHash = _tx.hashForSignature(
          vin, input.signScript!, hashType
      );
    }

    // enforce in order signing of public keys
    var signed = false;
    for (var i = 0; i < input.pubkeys!.length; i++) {

      if (!ListEquality().equals(ourPubKey, input.pubkeys![i])) continue;

      if (input.signatures![i] != null) {
        throw ArgumentError('Signature already exists');
      }

      final signature = keyPair.sign(signatureHash);
      input.signatures![i] = bscript.encodeSignature(signature, hashType);
      signed = true;

    }

    if (!signed) throw ArgumentError('Key pair cannot sign for this input');

  }

  Transaction build() {
    return _build(false);
  }

  Transaction buildIncomplete() {
    return _build(true);
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

      if (!input.isComplete()) {
        if (allowIncomplete) continue;
        throw ArgumentError('Transaction is not complete');
      }

      if (input.prevOutType == SCRIPT_TYPES['P2PKH']) {

        P2PKH payment = P2PKH(
            data: PaymentData(
                pubkey: input.pubkeys![0],
                signature: input.signatures![0]
            ),
            network: network
        );
        tx.setInputScript(i, payment.data.input!);
        tx.setWitness(i, payment.data.witness);

      } else if (input.prevOutType == SCRIPT_TYPES['P2WPKH']) {

        P2WPKH payment = P2WPKH(
            data: PaymentData(
                pubkey: input.pubkeys![0],
                signature: input.signatures![0]
            ),
            network: network
        );
        tx.setInputScript(i, payment.data.input!);
        tx.setWitness(i, payment.data.witness!);

      } else if (input.prevOutType == SCRIPT_TYPES['P2WSH']) {

        tx.setInputScript(i, Uint8List(0));

        // If we don't yet have the witness data, construct it here.
        // The code is all over the place, with no clear structure. It would be
        // much better if there were clear abstractions for all parts of the
        // transaction that are serialised in one place
        if (input.witness == null) {
          // Remove all null signatures
          final signatures = input.signatures!.whereType<Uint8List>();
          input.witness = [
              Uint8List.fromList([0]), ...signatures, input.signScript!
          ];
        }

        tx.setWitness(i, input.witness);

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
    int incoming = _inputs.fold(0, (cur, acc) => cur + (acc.value ?? 0));
    int outgoing = _tx.outs.fold(0, (cur, acc) => cur + (acc.value ?? 0));
    int fee = incoming - outgoing;
    int feeRate = fee ~/ bytes;
    return feeRate > maximumFeeRate;
  }

  bool _canModifyInputs() {
    return _inputs.every((input) {
      if (input.signatures == null) return true;
      return input.signatures!.every((signature) {
        if (signature == null) return true;
        return _signatureHashType(signature) & SIGHASH_ANYONECANPAY != 0;
      });
    });
  }

  bool _canModifyOutputs() {
    final nInputs = _tx.ins.length;
    final nOutputs = _tx.outs.length;
    return _inputs.every((input) {
      if (input.signatures == null) return true;
      return input.signatures!.every((signature) {
        if (signature == null) return true;
        final hashType = _signatureHashType(signature);
        final hashTypeMod = hashType & 0x1f;
        if (hashTypeMod == SIGHASH_NONE) return true;
        if (hashTypeMod == SIGHASH_SINGLE) {
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
    if (signingHashType == SIGHASH_ALL) {
      return this._tx.outs.length == 0;
    }
    // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
    // .build() will fail, but .buildIncomplete() is OK
    return (this._tx.outs.length == 0) &&
        _inputs.map((input) {
          if (input.signatures == null || input.signatures!.length == 0)
            return false;
          return input.signatures!.map((signature) {
            if (signature == null) return false; // no signature, no issue
            final hashType = _signatureHashType(signature);
            if (hashType & SIGHASH_NONE != 0)
              return false; // SIGHASH_NONE doesn't care about outputs
            return true; // SIGHASH_* does care
          }).contains(true);
        }).contains(true);
  }


  _addInputUnsafe(Uint8List hash, int vout, Input options) {

    String txHash = HEX.encode(hash);
    Input input;

    if (isCoinbaseHash(hash)) {
      throw ArgumentError('coinbase inputs not supported');
    }

    final prevTxOut = '$txHash:$vout';

    if (_prevTxSet[prevTxOut] != null) {
      throw ArgumentError('Duplicate TxOut: ' + prevTxOut);
    }

    input = options.script != null
      ? Input.expandInput(
          options.script!, options.witness ?? EMPTY_WITNESS
      )
      : Input();

    if (options.value != null) input.value = options.value;
    if (input.prevOutScript == null && options.prevOutScript != null) {
      if (input.pubkeys == null && input.signatures == null) {
        var expanded = Output.expandOutput(options.prevOutScript!);
        if (expanded.pubkeys != null && expanded.pubkeys!.isNotEmpty) {
          input.pubkeys = expanded.pubkeys;
          input.signatures = expanded.signatures;
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

  int _signatureHashType(Uint8List buffer) {
    return buffer.buffer.asByteData().getUint8(buffer.length - 1);
  }

  Transaction get tx => _tx;

  Map get prevTxSet => _prevTxSet;
}

Uint8List pubkeyToOutputScript(Uint8List pubkey, [NetworkType? nw]) {
  NetworkType network = nw ?? bitcoin;
  P2PKH p2pkh =
      P2PKH(data: PaymentData(pubkey: pubkey), network: network);
  return p2pkh.data.output!;
}
