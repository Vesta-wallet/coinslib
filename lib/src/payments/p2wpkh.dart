import 'dart:typed_data';
import '../utils/ecurve.dart' show isPoint;
import 'package:coinslib/bech32/bech32.dart';

import '../crypto.dart';
import '../models/networks.dart';
import '../payments/index.dart' show PaymentData;
import '../utils/script.dart' as bscript;
import '../utils/constants/op.dart';

class P2WPKH {
  final emptyScript = Uint8List.fromList([]);

  PaymentData data;
  NetworkType network;

  P2WPKH({required this.data, NetworkType? network})
      : network = network ?? bitcoin {

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
      if (output.length != 22 || output[0] != ops['OP_0'] || output[1] != 20) {
        throw ArgumentError('Output is invalid');
      }
      data.hash ??= output.sublist(2);
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
      data.input ??= emptyScript;
    }

  }

  void _getDataFromWitness(List<Uint8List> witness) {
    data.input ??= emptyScript;
    if (data.pubkey == null) {
      data.pubkey = witness[1];
      data.hash ??= hash160(data.pubkey!);
      _getDataFromHash();
    }
    data.signature ??= witness[0];
  }

  void _getDataFromHash() {
    data.address ??= segwit.encode(Segwit(network.bech32!, 0, data.hash!));
    data.output ??= bscript.compile([ops['OP_0'], data.hash]);
  }

  void _getDataFromAddress(String address) {
    try {
      Segwit segwitAddress = segwit.decode(address);
      if (network.bech32 != segwitAddress.hrp) {
        throw ArgumentError('Invalid prefix or Network mismatch');
      }
      // Only support version 0 now;
      if (segwitAddress.version != 0) {
        throw ArgumentError('Invalid address version');
      }
      data.hash = Uint8List.fromList(segwitAddress.program);
    } on InvalidHrp {
      throw ArgumentError('Invalid prefix or Network mismatch');
    } on InvalidProgramLength {
      throw ArgumentError('Invalid address data');
    } on InvalidWitnessVersion {
      throw ArgumentError('Invalid witness address version');
    }
  }
}
