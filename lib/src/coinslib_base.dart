import 'dart:typed_data';
import 'package:coinslib/src/utils/magic_hash.dart';
import 'package:hex/hex.dart';
import 'bip32_base.dart' as bip32;
import 'models/networks.dart';
import 'payments/p2pkh.dart';
import 'ecpair.dart';

/// Checks if you are awesome. Spoiler: you are.
class HDWallet {
  bip32.BIP32 _bip32;
  P2PKH _p2pkh;
  String? seed;
  NetworkType network;

  String? get privKey {
    try {
      return HEX.encode(_bip32.privateKey!);
    } catch (_) {
      return null;
    }
  }

  Uint8List get pubKeyBytes => _bip32.publicKey;
  String get pubKey => HEX.encode(_bip32.publicKey);

  String? get base58Priv {
    try {
      return _bip32.toBase58();
    } catch (_) {
      return null;
    }
  }

  String get base58 => _bip32.neutered().toBase58();

  String? get wif {
    try {
      return _bip32.toWIF();
    } catch (_) {
      return null;
    }
  }

  String get address => _p2pkh.address(network);

  HDWallet({
    required bip32,
    required p2pkh,
    required this.network,
    this.seed,
  }) : _bip32 = bip32, _p2pkh = p2pkh;

  HDWallet derivePath(String path) {
    final bip32 = _bip32.derivePath(path);
    final p2pkh = P2PKH.fromPublicKey(bip32.publicKey);
    return HDWallet(bip32: bip32, p2pkh: p2pkh, network: network);
  }

  HDWallet derive(int index) {
    final bip32 = _bip32.derive(index);
    final p2pkh = P2PKH.fromPublicKey(bip32.publicKey);
    return HDWallet(bip32: bip32, p2pkh: p2pkh, network: network);
  }

  factory HDWallet.fromSeed(Uint8List seed, {NetworkType? network}) {
    network = network ?? bitcoin;
    final seedHex = HEX.encode(seed);
    final wallet = bip32.BIP32.fromSeed(seed, network);
    final p2pkh = P2PKH.fromPublicKey(wallet.publicKey);
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
    final p2pkh = P2PKH.fromPublicKey(wallet.publicKey);
    return HDWallet(bip32: wallet, p2pkh: p2pkh, network: network, seed: null);
  }

  Uint8List sign(String message) {
    Uint8List messageHash = magicHash(message, network);
    return _bip32.signRecoverable(messageHash);
  }

  bool verify({required String message, required Uint8List signature}) {
    Uint8List messageHash = magicHash(message);
    return _bip32.verify(messageHash, signature);
  }
}

class Wallet {
  ECPair _keyPair;
  P2PKH _p2pkh;
  NetworkType network;

  String get privKey => HEX.encode(_keyPair.privateKey!);
  String get pubKey => HEX.encode(_keyPair.publicKey!);
  String get wif => _keyPair.toWIF();
  String get address => _p2pkh.address(network);

  Wallet(this._keyPair, this._p2pkh, this.network);

  factory Wallet.random([NetworkType? network]) {
    network ??= bitcoin;
    final keyPair = ECPair.makeRandom(network: network);
    final p2pkh = P2PKH.fromPublicKey(keyPair.publicKey!);
    return Wallet(keyPair, p2pkh, network);
  }

  factory Wallet.fromWIF(String wif, [NetworkType? network]) {
    network = network ?? bitcoin;
    final keyPair = ECPair.fromWIF(wif, network: network);
    final p2pkh = P2PKH.fromPublicKey(keyPair.publicKey!);
    return Wallet(keyPair, p2pkh, network);
  }

  Uint8List sign(String message) {
    Uint8List messageHash = magicHash(message, network);
    return _keyPair.signRecoverable(messageHash);
  }

  bool verify({required String message, required Uint8List signature}) {
    Uint8List messageHash = magicHash(message, network);
    return _keyPair.verify(messageHash, signature);
  }
}
