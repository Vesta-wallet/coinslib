import 'dart:typed_data';
import '../utils/ecurve.dart' show isPoint;
import 'package:bs58check/bs58check.dart' as bs58check;

import '../crypto.dart';
import '../models/networks.dart';
import '../payments/index.dart' show PaymentData;
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

class P2PKH {
  PaymentData data;
  NetworkType network;

  P2PKH({required this.data, NetworkType? network})
      : network = network ?? bitcoin {
    _init();
  }

  _init() {
    if (data.address != null) {
      _getDataFromAddress(data.address!);
      _getDataFromHash();
    } else if (data.hash != null) {
      _getDataFromHash();
    } else if (data.output != null) {
      if (!isValidOutput(data.output!)) {
        throw ArgumentError('Output is invalid');
      }
      data.hash = data.output!.sublist(3, 23);
      _getDataFromHash();
    } else if (data.pubkey != null) {
      data.hash = hash160(data.pubkey!);
      _getDataFromHash();
      _getDataFromChunk();
    } else if (data.input != null) {
      List<dynamic> chunks = bscript.decompile(data.input)!;
      _getDataFromChunk(chunks);
      if (chunks.length != 2) throw ArgumentError('Input is invalid');
      if (!bscript.isCanonicalScriptSignature(chunks[0])) {
        throw ArgumentError('Input has invalid signature');
      }
      if (!isPoint(chunks[1])) {
        throw ArgumentError('Input has invalid pubkey');
      }
    } else {
      throw ArgumentError('Not enough data');
    }
  }

  void _getDataFromChunk([List<dynamic>? chunks]) {
    if (data.pubkey == null && chunks != null) {
      data.pubkey =
          (chunks[1] is int) ? Uint8List.fromList([chunks[1]]) : chunks[1];
      data.hash = hash160(data.pubkey!);
      _getDataFromHash();
    }
    if (data.signature == null && chunks != null) {
      data.signature =
          (chunks[0] is int) ? Uint8List.fromList([chunks[0]]) : chunks[0];
    }
    if (data.input == null && data.pubkey != null && data.signature != null) {
      data.input = bscript.compile([data.signature!, data.pubkey!]);
    }
  }

  void _getDataFromHash() {
    if (data.address == null) {
      final payload = Uint8List(21);
      payload.buffer.asByteData().setUint8(0, network.pubKeyHash);
      payload.setRange(1, payload.length, data.hash!);
      data.address = bs58check.encode(payload);
    }
    data.output ??= bscript.compile([
      ops['OP_DUP'],
      ops['OP_HASH160'],
      data.hash,
      ops['OP_EQUALVERIFY'],
      ops['OP_CHECKSIG']
    ]);
  }

  void _getDataFromAddress(String address) {
    Uint8List payload = bs58check.decode(address);
    final version = payload.buffer.asByteData().getUint8(0);
    if (version != network.pubKeyHash) {
      throw ArgumentError('Invalid version or Network mismatch');
    }
    data.hash = payload.sublist(1);
    if (data.hash!.length != 20) throw ArgumentError('Invalid address');
  }
}

isValidOutput(Uint8List data) {
  return data.length == 25 &&
      data[0] == ops['OP_DUP'] &&
      data[1] == ops['OP_HASH160'] &&
      data[2] == 0x14 &&
      data[23] == ops['OP_EQUALVERIFY'] &&
      data[24] == ops['OP_CHECKSIG'];
}

// Backward compatibility
@Deprecated(
    "The 'P2PKHData' class is deprecated. Use the 'PaymentData' package instead.")
class P2PKHData extends PaymentData {
  P2PKHData({address, hash, output, pubkey, input, signature, witness})
      : super(
            address: address,
            hash: hash,
            output: output,
            pubkey: pubkey,
            input: input,
            signature: signature,
            witness: witness);
}
