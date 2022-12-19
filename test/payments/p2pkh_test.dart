import 'package:coinslib/src/payments/p2pkh.dart';
import 'package:test/test.dart';
import 'package:hex/hex.dart';
import 'dart:typed_data';
import 'package:coinslib/src/models/networks.dart';

main() {

  test("P2PKH.fromPublicKeyHash", () {
    final p2pkh = P2PKH.fromPublicKeyHash(
      HEX.decode("168b992bcfc44050310b3a94bd0771136d0b28d1") as Uint8List,
    );
    expect(
      p2pkh.address(bitcoin),
      "134D6gYy8DsR5m4416BnmgASuMBqKvogQh",
    );
    expect(
      p2pkh.outputScript,
      HEX.decode("76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac") as Uint8List,
    );
  });

  test("P2PKH.fromPublicKey", () {

    final p2pkh = P2PKH.fromPublicKey(
      HEX.decode(
        "030000000000000000000000000000000000000000000000000000000000000001",
      ) as Uint8List,
    );
    expect(
      p2pkh.address(bitcoin),
      "134D6gYy8DsR5m4416BnmgASuMBqKvogQh",
    );
    expect(
      p2pkh.pubKeyHash,
      HEX.decode("168b992bcfc44050310b3a94bd0771136d0b28d1") as Uint8List,
    );
    expect(
      p2pkh.outputScript,
      HEX.decode("76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac") as Uint8List,
    );

  });

  test("invalid P2PKH hash length", () {

    expect(
      () => P2PKH.fromPublicKeyHash(
         HEX.decode("168b992bcfc44050310b3a94bd0771136d0b28") as Uint8List,
      ),
      throwsA(
        predicate(
          (e) => e is ArgumentError &&
          e.message == 'Invalid P2PKH public key hash length',
        ),
      ),
    );

  });

}

