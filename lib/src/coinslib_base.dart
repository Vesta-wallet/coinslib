// TODO: Put public facing types in this file.
import 'dart:typed_data';
import 'package:coinslib/src/utils/magic_hash.dart';
import 'package:hex/hex.dart';
import 'bip32_base.dart' as bip32;
import 'models/networks.dart';
import 'payments/index.dart' show PaymentData;
import 'payments/p2pkh.dart';
import 'ecpair.dart';

/// Checks if you are awesome. Spoiler: you are.
class HDWallet {
  bip32.BIP32? _bip32;
  P2PKH? _p2pkh;
  String? seed;
  NetworkType network;

  String? get privKey {
    if (_bip32 == null) return null;
    try {
      return HEX.encode(_bip32!.privateKey!);
    } catch (_) {
      return null;
    }
  }

  Uint8List? get pubKeyBytes => _bip32?.publicKey;
  String? get pubKey => _bip32 != null ? HEX.encode(_bip32!.publicKey) : null;

  String? get base58Priv {
    if (_bip32 == null) return null;
    try {
      return _bip32!.toBase58();
    } catch (_) {
      return null;
    }
  }

  String? get base58 => _bip32 != null ? _bip32!.neutered().toBase58() : null;

  String? get wif {
    if (_bip32 == null) return null;
    try {
      return _bip32!.toWIF();
    } catch (_) {
      return null;
    }
  }

  String? get address => _p2pkh != null ? _p2pkh!.data.address : null;

  HDWallet({required bip32, required p2pkh, required this.network, this.seed}) {
    _bip32 = bip32;
    _p2pkh = p2pkh;
  }

  HDWallet derivePath(String path) {
    final bip32 = _bip32!.derivePath(path);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: bip32.publicKey), network: network);
    return HDWallet(bip32: bip32, p2pkh: p2pkh, network: network);
  }

  HDWallet derive(int index) {
    final bip32 = _bip32!.derive(index);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: bip32.publicKey), network: network);
    return HDWallet(bip32: bip32, p2pkh: p2pkh, network: network);
  }

  factory HDWallet.fromSeed(Uint8List seed, {NetworkType? network}) {
    network = network ?? bitcoin;
    final seedHex = HEX.encode(seed);
    final wallet = bip32.BIP32.fromSeed(seed, network);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: wallet.publicKey), network: network);
    return HDWallet(
      bip32: wallet,
      p2pkh: p2pkh,
      network: network,
      seed: seedHex,
    );
  }

  factory HDWallet.fromBase58(String xpub, {NetworkType? network}) {
    network = network ?? bitcoin;
    final wallet = bip32.BIP32.fromBase58(xpub, network);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: wallet.publicKey), network: network);
    return HDWallet(bip32: wallet, p2pkh: p2pkh, network: network, seed: null);
  }

  Uint8List sign(String message) {
    Uint8List messageHash = magicHash(message, network);
    return _bip32!.signRecoverable(messageHash);
  }

  bool verify({required String message, required Uint8List signature}) {
    // Remove recid as it isn't needed when we have the public key
    signature = signature.sublist(1);
    Uint8List messageHash = magicHash(message);
    return _bip32!.verify(messageHash, signature);
  }
}

class Wallet {
  ECPair? _keyPair;
  P2PKH? _p2pkh;

  String? get privKey =>
      _keyPair != null ? HEX.encode(_keyPair!.privateKey!) : null;

  String? get pubKey =>
      _keyPair != null ? HEX.encode(_keyPair!.publicKey!) : null;

  String? get wif => _keyPair != null ? _keyPair!.toWIF() : null;

  String? get address => _p2pkh != null ? _p2pkh!.data.address : null;

  NetworkType? network;

  Wallet(this._keyPair, this._p2pkh, this.network);

  factory Wallet.random([NetworkType? network]) {
    final keyPair = ECPair.makeRandom(network: network);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: keyPair.publicKey), network: network);
    return Wallet(keyPair, p2pkh, network);
  }

  factory Wallet.fromWIF(String wif, [NetworkType? network]) {
    network = network ?? bitcoin;
    final keyPair = ECPair.fromWIF(wif, network: network);
    final p2pkh =
        P2PKH(data: PaymentData(pubkey: keyPair.publicKey), network: network);
    return Wallet(keyPair, p2pkh, network);
  }

  Uint8List sign(String message) {
    Uint8List messageHash = magicHash(message, network);
    return _keyPair!.signRecoverable(messageHash);
  }

  bool verify({required String message, required Uint8List signature}) {
    // Remove recid as it isn't needed when we have the public key
    signature = signature.sublist(1);
    Uint8List messageHash = magicHash(message, network);
    return _keyPair!.verify(messageHash, signature);
  }
}
