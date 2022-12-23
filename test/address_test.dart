import 'dart:convert';

import 'package:coinslib/coinslib.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/address.dart';
import 'package:coinslib/src/models/networks.dart' as networks;
import 'dart:typed_data';

main() {
  group('validateAddress', () {
    test('base58 addresses and valid network', () {
      expect(
        validateAddress(
          'mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT',
          networks.testnet,
        ),
        true,
      );
      expect(
        validateAddress('1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ'),
        true,
      );
      // P2SH
      expect(
        validateAddress('3L1YkZjdeNSqaZcNKZFXQfyokx3zVYm7r6'),
        true,
      );
    });

    test('base58 addresses and invalid network', () {
      expect(
        validateAddress(
          'mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT',
          networks.bitcoin,
        ),
        false,
      );
      expect(
        validateAddress(
          '1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ',
          networks.testnet,
        ),
        false,
      );
    });

    test('bech32 addresses and valid network', () {
      expect(
        validateAddress(
          'tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya',
          networks.testnet,
        ),
        true,
      );
      expect(
        validateAddress(
          'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
        ),
        true,
      );
      expect(
        validateAddress(
          'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
          networks.testnet,
        ),
        true,
      );
    });

    test('bech32 addresses and invalid network', () {
      expect(
        validateAddress(
          'tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya',
        ),
        false,
      );
      expect(
        validateAddress(
          'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          networks.testnet,
        ),
        false,
      );
    });

    test('invalid addresses', () {
      expect(validateAddress('3333333casca'), false);
    });

    test('wrong size base58 address', () {
      expect(
        validateAddress('12D2adLM3UKy4Z4giRbReR6gjWx1w6Dz'),
        false,
        reason: "P2PKH too short",
      );

      expect(
        validateAddress('1QXEx2ZQ9mEdvMSaVKHznFv6iZq2LQbDz8'),
        false,
        reason: "P2PKH too long",
      );

      expect(
        validateAddress('TTazDDREDxxh1mPyGySut6H98h4UKPG6'),
        false,
        reason: "P2SH too short",
      );

      expect(
        validateAddress('9tT9KH26AxgN8j9uTpKdwUkK6LFcSKp4FpF'),
        false,
        reason: "P2SH too long",
      );
    });

    test('wrong size bech32 addresses', () {
      // 31 bytes
      expect(
        validateAddress(
          'bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqy20t',
        ),
        false,
        reason: "P2WSH too short",
      );

      // 33 bytes
      expect(
        validateAddress(
          'bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq88p3kr',
        ),
        false,
        reason: "P2WSH too long",
      );
    });
  });

  group('addressToOutputScript', () {
    expectScript(address, expectedScript) {
      final actual = addressToOutputScript(address);
      expect(HEX.encode(actual), expectedScript);
    }

    test('returns p2pkh scripts', () {
      expectP2PKH(address, expectedHash) =>
          expectScript(address, "76a914${expectedHash}88ac");

      expectP2PKH(
        "1111111111111111111114oLvT2",
        "0000000000000000000000000000000000000000",
      );
      expectP2PKH(
        "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr",
        "ffffffffffffffffffffffffffffffffffffffff",
      );
    });

    test('returns p2sh scripts', () {
      expectP2SH(address, expectedHash) =>
          expectScript(address, "a914${expectedHash}87");

      expectP2SH(
        "31h1vYVSYuKP6AhS86fbRdMw9XHieotbST",
        "0000000000000000000000000000000000000000",
      );
      expectP2SH(
        "3R2cuenjG5nFubqX9Wzuukdin2YfBbQ6Kw",
        "ffffffffffffffffffffffffffffffffffffffff",
      );
    });

    test('returns p2wsh scripts', () {
      expectP2WSH(address, expectedHash) =>
          expectScript(address, "0020$expectedHash");

      expectP2WSH(
        "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8",
        "0000000000000000000000000000000000000000000000000000000000000000",
      );

      expectP2WSH(
        "bc1qlllllllllllllllllllllllllllllllllllllllllllllllllllsffrpzs",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      );
    });

    test('returns p2wpkh scripts', () {
      expectP2WPKH(address, expectedHash) =>
          expectScript(address, "0014$expectedHash");
      expectP2WPKH(
        "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs",
        "0000000000000000000000000000000000000000",
      );
      expectP2WPKH(
        "bc1qllllllllllllllllllllllllllllllllfglmy6",
        "ffffffffffffffffffffffffffffffffffffffff",
      );
    });
  });

  group("verifySignedMessageForAddress", () {
    expectVerify({
      required String address,
      required String message,
      required Uint8List signature,
      required bool exp,
    }) {
      expect(
        verifySignedMessageForAddress(
          address: address,
          message: message,
          signature: signature,
          network: networks.peercoin,
        ),
        exp,
      );
    }

    test("returns true for correct signatures", () {
      expectVerify(
        address: "PBMtsXHQRgSGPG7VKt4g9ris6GcmtJYEVn",
        message: "This is a message to test with!",
        signature: base64.decode(
          "ILq7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
        ),
        exp: true,
      );
    });

    test("returns true for P2WPKH address for same public key", () {
      // The code should accept P2WPKH but the client cannot sign messages with
      // these at the moment

      expectVerify(
        address: "pc1qrejkpq9264etmlvlzhzka7xc4ev2lanxfpajh2",
        message: "This is a message to test with!",
        signature: base64.decode(
          "ILq7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
        ),
        exp: true,
      );
    });

    test("returns false for signatures for different pubkey", () {
      expectVerify(
        address: "PGgYh12SkCtQ4jy99skqjdYDq2iCd6NKJS",
        message: "This is a message to test with!",
        signature: base64.decode(
          "ILq7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
        ),
        exp: false,
      );
    });

    test("returns false for signatures for different messages", () {
      expectVerify(
        address: "PBMtsXHQRgSGPG7VKt4g9ris6GcmtJYEVn",
        message: "This is a message to test with",
        signature: base64.decode(
          "ILq7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
        ),
        exp: false,
      );
    });

    test("returns false for wrong recid", () {
      expectVerify(
        address: "PBMtsXHQRgSGPG7VKt4g9ris6GcmtJYEVn",
        message: "This is a message to test with!",
        signature: base64.decode(
          "H7q7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
        ),
        exp: false,
      );
    });

    test("throws for non-recoverable signature", () {
      expect(
        () => verifySignedMessageForAddress(
          address: "PBMtsXHQRgSGPG7VKt4g9ris6GcmtJYEVn",
          message: "This is a message to test with!",
          signature: base64
              .decode(
                "ILq7D/Rh+sUe7qrVNROQGgU3GLQJjL78eEhz2zlmN2pHE6LhTavBovN2oDVxN+bERT9SD+HHDCrvnNIDrllMXQ4=",
              )
              .sublist(1),
          network: networks.peercoin,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
