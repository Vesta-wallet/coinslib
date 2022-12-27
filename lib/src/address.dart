// ignore_for_file: empty_catches

import 'dart:typed_data';
import 'package:coinslib/src/payments/p2wsh.dart';
import 'package:coinslib/src/utils/magic_hash.dart';
import 'package:collection/collection.dart';
import 'classify.dart';
import 'crypto.dart';
import 'models/networks.dart';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:coinslib/bech32/bech32.dart';
import 'payments/p2pkh.dart';
import 'payments/p2wpkh.dart';
import 'payments/p2sh.dart';
import './utils/script.dart' as bscript;
import './utils/ecurve.dart' as ecc;

bool validateAddress(String address, [NetworkType? nw]) {
  try {
    addressToOutputScript(address, nw);
    return true;
  } catch (err) {
    return false;
  }
}

Uint8List addressToOutputScript(String address, [NetworkType? nw]) {
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
      return P2PKH.fromPublicKeyHash(data).outputScript;
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
      return P2WPKH.fromPublicKeyHash(program).outputScript;
    }

    if (progLen == 32) {
      return P2WSH.fromScriptHash(program).outputScript;
    }

    throw ArgumentError('The bech32 witness program is not the correct size');
  }

  throw ArgumentError('$address has no matching Script');
}

/// For a given P2PKH or P2WPKH [address], verify the [message] and recoverable
/// [signature]. Note that the client does not currently sign or verify
/// signatures for P2WPKH addresses.
bool verifySignedMessageForAddress({
  required String address,
  required String message,
  required Uint8List signature,
  NetworkType? network,
}) {
  // Decode address to public key hash
  // It would be better if there was an output base class for the different
  // output types to better encapsulate the logic.
  final outputScript = addressToOutputScript(address, network);
  final chunks = bscript.decompile(outputScript)!;
  final outType = classifyOutput(outputScript);
  late Uint8List pubkeyhash;

  if (outType == scriptTypes['P2PKH']) {
    pubkeyhash = chunks[2];
  } else if (outType == scriptTypes['P2WPKH']) {
    pubkeyhash = chunks[1];
  } else {
    return false;
  }

  // Get hash for message
  Uint8List hash = magicHash(message, network);

  try {
    // Extract public key from signature
    final pubkey = ecc.recover(hash, signature);

    // Check public key against address and verify signature with recid removed
    final rsSig = signature.sublist(1);
    return ListEquality().equals(hash160(pubkey), pubkeyhash) &&
        ecc.verify(hash, pubkey, rsSig);
  } on Exception {
    return false;
  }
}
