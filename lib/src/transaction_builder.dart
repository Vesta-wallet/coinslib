import 'dart:convert';
import 'dart:typed_data';
import 'package:coinslib/src/utils/constants/op.dart';
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

  factory TransactionBuilder.fromTransaction(Transaction transaction,
      [NetworkType? network]) {
    final txb = TransactionBuilder(network: network);
    // Copy transaction fields
    txb.setVersion(transaction.version);
    txb.setLockTime(transaction.locktime);

    // Copy outputs (done first to avoid signature invalidation)
    for (var txOut in transaction.outs) {
      txb.addOutput(txOut.script, txOut.value!);
    }

    for (var txIn in transaction.ins) {
      txb._addInputUnsafe(
          txIn.hash!,
          txIn.index!,
          Input(
              sequence: txIn.sequence,
              script: txIn.script,
              witness: txIn.witness));
    }

    // fix some things not possible through the public API
    // print(txb.toString());
    // txb.__INPUTS.forEach((input, i) => {
    //   fixMultisigOrder(input, transaction, i);
    // });

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
    if (_inputs.map((input) {
      if (input.signatures == null) return false;
      return input.signatures!.map((s) {
        return s != null;
      }).contains(true);
    }).contains(true)) {
      throw ArgumentError('No, this would invalidate signatures');
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
          'Too much data, max OP_RETURN size is ${network.opreturnSize}');
    }

    // Encode output script with OP_RETURN followed by the push data
    final script = bscript.compile([ops['OP_RETURN'], pushData]);
    return _addOutputFromScript(script, BigInt.zero);
  }

  int addInput(dynamic txHash, int vout,
      [int? sequence, Uint8List? prevOutScript]) {
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

    return _addInputUnsafe(hash, vout,
        Input(sequence: sequence, prevOutScript: prevOutScript, value: value));
  }

  sign(
      {required int vin,
      required ECPair keyPair,
      Uint8List? redeemScript,
      BigInt? witnessValue,
      Uint8List? witnessScript,
      int? hashType}) {
    if (keyPair.network.toString().compareTo(network.toString()) != 0) {
      throw ArgumentError('Inconsistent network');
    }
    if (vin >= _inputs.length) throw ArgumentError('No input at index: $vin');
    hashType = hashType ?? sigHashAll;
    if (_needsOutputs(hashType)) {
      throw ArgumentError('Transaction needs outputs');
    }
    final input = _inputs[vin];
    final ourPubKey = keyPair.publicKey;
    if (!_canSign(input)) {
      if (witnessValue != null) {
        input.value = witnessValue;
      }
      if (redeemScript != null && witnessScript != null) {
        // TODO p2wsh
      }
      if (redeemScript != null) {
        // TODO
      }
      if (witnessScript != null) {
        // TODO
      }
      if (input.prevOutScript != null && input.prevOutType != null) {
        var type = classifyOutput(input.prevOutScript!);
        if (type == scriptTypes['P2WPKH']) {
          input.prevOutType = scriptTypes['P2WPKH'];
          input.hasWitness = true;
          input.signatures = [null];
          input.pubkeys = [ourPubKey];
          input.signScript =
              P2PKH(data: PaymentData(pubkey: ourPubKey), network: network)
                  .data
                  .output;
        } else {
          // DRY CODE
          Uint8List prevOutScript = pubkeyToOutputScript(ourPubKey!);
          input.prevOutType = scriptTypes['P2PKH'];
          input.signatures = [null];
          input.pubkeys = [ourPubKey];
          input.signScript = prevOutScript;
        }
      } else {
        Uint8List prevOutScript = pubkeyToOutputScript(ourPubKey!);
        input.prevOutType = scriptTypes['P2PKH'];
        input.signatures = [null];
        input.pubkeys = [ourPubKey];
        input.signScript = prevOutScript;
      }
    }
    dynamic signatureHash;
    if (input.hasWitness) {
      signatureHash =
          _tx.hashForWitnessV0(vin, input.signScript!, input.value!, hashType);
    } else {
      signatureHash = _tx.hashForSignature(vin, input.signScript!, hashType);
    }

    // enforce in order signing of public keys
    var signed = false;
    for (var i = 0; i < input.pubkeys!.length; i++) {
      if (HEX
              .encode(ourPubKey!)
              .compareTo(HEX.encode(input.pubkeys![i] as Uint8List)) !=
          0) continue;
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
      if (_tx.ins.isEmpty) throw ArgumentError('Transaction has no inputs');
      if (_tx.outs.isEmpty) {
        throw ArgumentError('Transaction has no outputs');
      }
    }

    final tx = Transaction.clone(_tx);

    for (var i = 0; i < _inputs.length; i++) {
      if (_inputs[i].pubkeys != null &&
          _inputs[i].signatures != null &&
          _inputs[i].pubkeys!.isNotEmpty &&
          _inputs[i].signatures!.isNotEmpty) {
        if (_inputs[i].prevOutType == scriptTypes['P2PKH']) {
          P2PKH payment = P2PKH(
              data: PaymentData(
                  pubkey: _inputs[i].pubkeys![0],
                  signature: _inputs[i].signatures![0]),
              network: network);
          tx.setInputScript(i, payment.data.input!);
          tx.setWitness(i, payment.data.witness);
        } else if (_inputs[i].prevOutType == scriptTypes['P2WPKH']) {
          P2WPKH payment = P2WPKH(
              data: PaymentData(
                  pubkey: _inputs[i].pubkeys![0],
                  signature: _inputs[i].signatures![0]),
              network: network);
          tx.setInputScript(i, payment.data.input!);
          tx.setWitness(i, payment.data.witness!);
        }
      } else if (!allowIncomplete) {
        throw ArgumentError('Transaction is not complete');
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
      if (input.signatures == null) return true;
      return input.signatures!.every((signature) {
        if (signature == null) return true;
        return _signatureHashType(signature) & sigHashAnyoneCanPay != 0;
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
    return (_tx.outs.isEmpty) &&
        _inputs.map((input) {
          if (input.signatures == null || input.signatures!.isEmpty) {
            return false;
          }
          return input.signatures!.map((signature) {
            if (signature == null) return false; // no signature, no issue
            final hashType = _signatureHashType(signature);
            if (hashType & sigHashNone != 0) {
              return false;
            } // SIGHASH_NONE doesn't care about outputs
            return true; // SIGHASH_* does care
          }).contains(true);
        }).contains(true);
  }

  bool _canSign(Input input) {
    return input.pubkeys != null &&
        input.signScript != null &&
        input.signatures != null &&
        input.signatures!.length == input.pubkeys!.length &&
        input.pubkeys!.isNotEmpty;
  }

  _addInputUnsafe(Uint8List hash, int vout, Input options) {
    String txHash = HEX.encode(hash);
    Input input;
    if (isCoinbaseHash(hash)) {
      throw ArgumentError('coinbase inputs not supported');
    }
    final prevTxOut = '$txHash:$vout';
    if (_prevTxSet[prevTxOut] != null) {
      throw ArgumentError('Duplicate TxOut: $prevTxOut');
    }
    if (options.script != null) {
      input =
          Input.expandInput(options.script!, options.witness ?? emptyWitness);
    } else {
      input = Input();
    }
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
  P2PKH p2pkh = P2PKH(data: PaymentData(pubkey: pubkey), network: network);
  return p2pkh.data.output!;
}
