import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:coinslib/coinslib.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/coinslib_base.dart';
import 'package:coinslib/src/models/networks.dart' as networks;

main() {

  final testWallet = Wallet.fromWIF(
    "cTk3w9wHkw54aH2MHCWzQjT1AT25VkeGGCyVMFQfXaSNMvi847T1",
    networks.peercoinRegtest,
  );

  final p2pkhAddr = "mi6UP27mWx2SFuCe2VHm2ypp5L1iycDLde";
  final p2wpkhAddr = "pcrt1qr3r30t6wd962cu6dr27rtehwtkdzufvs2s68c2";

  final fixtures = json.decode(
    File('test/fixtures/message_sigs.json').readAsStringSync(encoding: utf8),
  );

  test('sign message', () {
    for (final testCase in fixtures) {
      final signature = testWallet.sign(testCase["message"]);
      final base64Encoded = base64.encode(signature);

      expect(base64Encoded, testCase["sig"]);
    }
  });

  test('verify message', () {
    for (final testCase in fixtures) {
      final signature = base64.decode(testCase["sig"]);
      final message = testCase["message"];
      expect(testWallet.verify(message: message, signature: signature), true);
    }
  });

  test('verify against address', () {

    for (final testCase in fixtures) {
      final signature = base64.decode(testCase["sig"]);
      final message = testCase["message"];

      for (final addr in [p2pkhAddr, p2wpkhAddr]) {
        expect(
          verifySignedMessageForAddress(
            address: addr,
            message: message,
            signature: signature,
            network: networks.peercoinRegtest,
          ),
          true,
        );
      }

    }

  });

}
