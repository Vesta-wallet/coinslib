// ignore_for_file: empty_catches

import 'dart:typed_data';
import 'package:coinslib/src/payments/p2wsh.dart';

import 'models/networks.dart';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:coinslib/bech32/bech32.dart';
import 'payments/index.dart' show PaymentData;
import 'payments/p2pkh.dart';
import 'payments/p2wpkh.dart';
import 'payments/p2sh.dart';

class Address {
  static bool validateAddress(String address, [NetworkType? nw]) {
    try {
      addressToOutputScript(address, nw);
      return true;
    } catch (err) {
      return false;
    }
  }

  static Uint8List addressToOutputScript(String address, [NetworkType? nw]) {
    NetworkType network = nw ?? bitcoin;
    dynamic decodeBase58;
    dynamic decodeBech32;

    try {
      decodeBase58 = bs58check.decode(address);
    } catch (err) {}

    if (decodeBase58 != null) {
      final prefix = decodeBase58[0];
      final data = decodeBase58.sublist(1);

      if (prefix == network.pubKeyHash) {
        P2PKH p2pkh =
            P2PKH(data: PaymentData(address: address), network: network);
        return p2pkh.data.output!;
      }

      if (prefix == network.scriptHash) {
        return P2SH.fromScriptHash(data).outputScript;
      }

      throw ArgumentError('Invalid version or Network mismatch');
    }

    try {
      decodeBech32 = segwit.decode(address);
    } catch (err) {}

    if (decodeBech32 != null) {
      if (network.bech32 != decodeBech32.hrp) {
        throw ArgumentError('Invalid prefix or Network mismatch');
      }

      if (decodeBech32.version != 0) {
        throw ArgumentError('Invalid address version');
      }

      final program = Uint8List.fromList(decodeBech32.program);
      final progLen = program.length;

      if (progLen == 20) {
        P2WPKH p2wpkh =
            P2WPKH(data: PaymentData(address: address), network: network);
        return p2wpkh.data.output!;
      }

      if (progLen == 32) {
        return P2WSH.fromScriptHash(program).outputScript;
      }

      throw ArgumentError('The bech32 witness program is not the correct size');
    }

    throw ArgumentError('$address has no matching Script');
  }
}
