import 'dart:typed_data';

import 'package:coinslib/coinslib.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/payments/multisig.dart';
import 'package:hex/hex.dart';

uint8ListFromHex(String hex) => Uint8List.fromList(HEX.decode(hex));

main() {

  final wallet = HDWallet.fromSeed(Uint8List(16));
  const successThreshold = 17;
  // Generate 20 keys from HD Wallet
  final pubkeys = List.generate(20, (i) => wallet.derive(i).pubKeyBytes!);
  final pubkey = pubkeys[0];

  final pksWithPush = pubkeys.fold<List<int>>(
      [], (li, pk) => li + [0x21] + pk.toList()
  );

  final Uint8List successScript = Uint8List.fromList(
      // 17 threshold with 1 byte push data
      [0x01, 0x11] +
      // Keys starting with 0x21 push
      pksWithPush +
      // 20, CHECKMULTISIG
      [0x01, 0x14, 0xae]
  );
  final beforePKNum = successScript.take(successScript.length - 3);

  test('MultisigScript() failures', () {

    expect(() => MultisigScript(pubkeys: []), throwsArgumentError);
    expect(
      () => MultisigScript(pubkeys: List.filled(21, pubkey)),
      throwsArgumentError
    );
    expect(
      () => MultisigScript(pubkeys: [pubkey], threshold: 0), throwsArgumentError
    );
    expect(
      () => MultisigScript(pubkeys: [pubkey], threshold: 2), throwsArgumentError
    );
    expect(
      () => MultisigScript(pubkeys: [Uint8List(32)], threshold: 2),
      throwsArgumentError
    );

  });

  test('MultisigScript() success', () {

    // Single key, default threshold
    expect(
      MultisigScript(pubkeys: [pubkey]).scriptBytes,
      HEX.decode(
        // 1, push 0x21 (33) bytes
        "5121"
        // PK data
        "03d8b90a8dd908c261e46088d31d9fbef0e6bef20b0283511d1bba62ad660d70ac"
        // 1, CHECKMULTISIG (0xae)
        "51ae"
      )
    );

    // 20 keys
    expect(
      MultisigScript(pubkeys: pubkeys, threshold: successThreshold).scriptBytes,
      successScript
    );

  });

  test('MultisigScript.fromScriptBytes() failures', () {

    expectFailure(Uint8List script) => expect(
      () => MultisigScript.fromScriptBytes(script), throwsArgumentError
    );

    // Script that can't be decompiled
    expectFailure(uint8ListFromHex("4c"));

    // Incorrect number of chunks.
    expectFailure(uint8ListFromHex("000000"));

    // Not enough chunks for public keys. Remove threshold chunk (first two bytes)
    expectFailure(successScript.sublist(2));

    // Doesn't have CHECKMULTISIG. CHECKSIG instead
    var noCheckMultiSig = Uint8List.fromList(successScript);
    noCheckMultiSig.last = 0xac;
    expectFailure(noCheckMultiSig);

    // Doesn't have public key number.
    // Add back CHECKMULTISIG
    expectFailure(Uint8List.fromList(beforePKNum.toList() + [0xae]));

    // Public key number = 0
    expectFailure(uint8ListFromHex("000000ae"));

    // Public key number = 21
    final extraKey = Uint8List.fromList(
      beforePKNum.toList() +
      // Add PK
      [0x21] + wallet.derive(20).pubKeyBytes! +
      // Add PK num and CHECKMULTISIG
      [0x01, 0x15, 0xae]
    );
    expectFailure(extraKey);

    // Invalid public key. Change first byte of first PK
    var badPK = Uint8List.fromList(successScript);
    badPK[3] = 0xff;
    expectFailure(badPK);

    // Doesn't have threshold integer
    expectFailure(Uint8List.fromList([0xae] + successScript.sublist(2)));

    // Threshold outside 1-publickeyN. In this case 2 when only one PK
    expectFailure(
        uint8ListFromHex(
            "52"
            "2103d8b90a8dd908c261e46088d31d9fbef0e6bef20b0283511d1bba62ad660d70ac"
            "51ae"
        )
    );

  });

  test('MultisigScript.fromScriptBytes() success', () {
    final multisig = MultisigScript.fromScriptBytes(successScript);
    expect(multisig.threshold, successThreshold);
    expect(multisig.pubkeys, pubkeys);
  });

}

