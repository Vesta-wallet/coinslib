import 'dart:typed_data';
import '../utils/ecurve.dart' show isPoint;
import 'package:coinslib/bech32/bech32.dart';

import '../crypto.dart';
import '../models/networks.dart';
import '../payments/index.dart' show PaymentData;
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

class P2WPKH {
  final EMPTY_SCRIPT = Uint8List.fromList([]);

  PaymentData data;
  NetworkType network;

  P2WPKH({required this.data, NetworkType? network})
      : network = network ?? bitcoin {
    _init();
  }

  _init() {
    if (
      data.address == null &&
      data.hash == null &&
      data.output == null &&
      data.pubkey == null &&
      data.witness.isEmpty
    ) throw ArgumentError('Not enough data');

    if (data.address != null) {
      _getDataFromAddress(data.address!);
    }

    if (data.hash != null) {
      _getDataFromHash();
    }

    final output = data.output;
    if (output != null) {
      if (output.length != 22 ||
          output[0] != OPS['OP_0'] ||
          output[1] != 20) // 0x14
        throw ArgumentError('Output is invalid');
      if (data.hash == null) {
        data.hash = output.sublist(2);
      }
      _getDataFromHash();
    }

    if (data.pubkey != null) {
      data.hash = hash160(data.pubkey!);
      _getDataFromHash();
    }

    final witness = data.witness;
    if (witness.isNotEmpty) {
      if (witness.length != 2) throw ArgumentError('Witness is invalid');
      if (!bscript.isCanonicalScriptSignature(witness[0])) {
        throw ArgumentError('Witness has invalid signature');
      }
      if (!isPoint(witness[1])) {
        throw ArgumentError('Witness has invalid pubkey');
      }
      _getDataFromWitness(witness);
    } else if (data.pubkey != null && data.signature != null) {
      data.witness = [data.signature!, data.pubkey!];
      if (data.input == null) data.input = EMPTY_SCRIPT;
    }

  }

  void _getDataFromWitness(List<Uint8List> witness) {
    data.input ??= EMPTY_SCRIPT;
    if (data.pubkey == null) {
      data.pubkey = witness[1];
      data.hash ??= hash160(data.pubkey!);
      _getDataFromHash();
    }
    if (data.signature == null) data.signature = witness[0];
  }

  void _getDataFromHash() {
    if (data.address == null) {
      data.address = segwit.encode(Segwit(network.bech32!, 0, data.hash!));
    }
    if (data.output == null) {
      data.output = bscript.compile([OPS['OP_0'], data.hash]);
    }
  }

  void _getDataFromAddress(String address) {
    try {
      Segwit _address = segwit.decode(address);
      if (network.bech32 != _address.hrp)
        throw ArgumentError('Invalid prefix or Network mismatch');
      if (_address.version != 0) // Only support version 0 now;
        throw ArgumentError('Invalid address version');
      data.hash = Uint8List.fromList(_address.program);
    } on InvalidHrp {
      throw ArgumentError('Invalid prefix or Network mismatch');
    } on InvalidProgramLength {
      throw ArgumentError('Invalid address data');
    } on InvalidWitnessVersion {
      throw ArgumentError('Invalid witness address version');
    }
  }
}
