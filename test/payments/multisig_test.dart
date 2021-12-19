import 'dart:typed_data';

import 'package:coinslib/coinslib.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/payments/multisig.dart';
import 'package:hex/hex.dart';

main() {

  final wallet = HDWallet.fromSeed(Uint8List(16));
  final pubkey = wallet.derive(0).pubKeyBytes!;

  test('createMultisigScript() failures', () {


    expectArgumentError(Function() f) => expect(f, throwsArgumentError);

    expectArgumentError(() => createMultisigScript(pubkeys: []));
    expectArgumentError(
      () => createMultisigScript(pubkeys: List.filled(21, pubkey))
    );

    expectArgumentError(
      () => createMultisigScript(pubkeys: [pubkey], threshold: 0)
    );
    expectArgumentError(
      () => createMultisigScript(pubkeys: [pubkey], threshold: 2)
    );
    expectArgumentError(
      () => createMultisigScript(pubkeys: [Uint8List(32)], threshold: 2)
    );

  });

  test('createMultisigScript() success', () {

    expectScript(Uint8List script, String expected) {
      expect(HEX.encode(script), expected);
    }

    // Single key, default threshold

    expectScript(
      createMultisigScript(pubkeys: [pubkey]),
      // 1, push 0x21 (33) bytes
      "5121"
      // PK data
      "03d8b90a8dd908c261e46088d31d9fbef0e6bef20b0283511d1bba62ad660d70ac"
      // 1, CHECKMULTISIG (0xae)
      "51ae"
    );

    // 20 keys, threshold of 17

    // Generate 20 keys from HD Wallet
    final pubkeys = List.generate(20, (i) => wallet.derive(i).pubKeyBytes!);

    expectScript(
      createMultisigScript(pubkeys: pubkeys, threshold: 17),
      // 17 threshold with 1 byte push data
      "0111"
      // Keys starting with 0x21 push
      "2103d8b90a8dd908c261e46088d31d9fbef0e6bef20b0283511d1bba62ad660d70ac"
      "2103478e553714ec27ce3e2c34548ffe844a2a8a5f03f05cee4fc1f5f75e97a3e321"
      "21022b8989e24ecd8339c856ac385ced4ac3e3ec3cbe4120cceaa40d0edd70a420e5"
      "21033f91389bc75f73c682f74b6f4d67bb141df48ae3f425cfacb81f6a1fc906d56a"
      "21028777787b3e262ac30d8ba126070a7754a900f6e9ccc76f5bef4511426bf2f7d0"
      "2102b22dabf62c0111e18bf562cabf73588f57137e3c1c21056f440561a3824c53c1"
      "2102f68576a94763886c1c4ae498d12a9a2b597e873a9ec3f3dc03333c45e2968691"
      "21033d24a227d7b09b12d8b9847538c651c09f839c609ae331799735c268056860e9"
      "210235e52abaecce03d7f52d15eed23fa8a63b500809c65de7903f5de332346ab832"
      "2103dbd8f5d8afe3fd0d5a52abc6b47a69d8c46336dfed7c0f163f705b67af42db0c"
      "2102be714ffc9dce99521694c8c1f6f0af765f10516ee6c62a75ebb06e8a79ad42ee"
      "210362c60306336a38bd8f7c2f25142ade4cb849aaa0f73d89722d169f93ba48532f"
      "210359197a6efd255f32ffe3406146557c348a8abaa66d80d8606a24b840095ca64a"
      "2102daeeabff69b2c1923ab9666b33921ed177488be16ce3ab67e729d759985c1824"
      "2103ab9a141f44de2de347ad00e84fd8a9355ce00da1ab415d9a76778dea6fc3fca7"
      "21022adf51f31f2f47aed01cc38ca071c0b830b1cec842ea84ba67c07200149a8033"
      "21035f1c74f336c0d4d865a7978ac97f62193f02a69003c66213878152a4a85c1cd4"
      "2102003f392d565848912e1c2c52f9beadcbb40bd4f8f7b2469c5d6a27daf82ae526"
      "21038b0a39c11379a414fd21532a27911e10fe89b6a042cd6819a926245b80033a8a"
      "2102d2ce20dd7b5b099eb2cf0f7a93469bfaa19bf8ad9a230e950f0647178286587e"
      // 20, CHECKMULTISIG
      "0114ae"
    );

  });

}
