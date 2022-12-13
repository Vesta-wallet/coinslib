import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:coinslib/src/coinslib_base.dart';
import 'package:coinslib/src/models/networks.dart' as networks;

main() {
  test('sign message', () {

    final testWallet = Wallet.fromWIF(
      "cTk3w9wHkw54aH2MHCWzQjT1AT25VkeGGCyVMFQfXaSNMvi847T1",
      networks.peercoinRegtest
    );

    final fixtures = json.decode(
      File('test/fixtures/message_sigs.json').readAsStringSync(encoding: utf8)
    );

    for (final testCase in fixtures) {
      final signature = testWallet.sign(testCase["message"]);
      final base64Encoded = base64.encode(signature);

      expect(base64Encoded, testCase["sig"]);
    }

  });
}
