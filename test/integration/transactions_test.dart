import 'package:test/test.dart';
import 'package:coinslib/src/ecpair.dart';
import 'package:coinslib/src/transaction_builder.dart';
import 'package:coinslib/src/models/networks.dart' as networks;
import 'package:coinslib/src/payments/p2wpkh.dart' show P2WPKH;
import 'package:coinslib/src/payments/index.dart' show PaymentData;

main() {
  final aliceKey =
      ECPair.fromWIF('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy');

  group('bitcoinjs-lib (transactions)', () {
    test('can create a 1-to-1 Transaction', () {
      final txb = TransactionBuilder();

      txb.setVersion(1);
      txb.addInput(
          '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d',
          0); // Alice's previous transaction output, has 15000 satoshis
      txb.addOutput('1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', BigInt.from(12000));
      // (in)15000 - (out)12000 = (fee)3000, this is the miner fee

      txb.sign(vin: 0, keyPair: aliceKey);

      // prepare for broadcast to the Bitcoin network, see 'can broadcast a Transaction' below
      expect(txb.build().toHex(),
          '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a4730440220730c3da33eded733722545be42d4a2c456551daabbc7b6de973b79fa4b5247b9022032884d2822201fa2dae1f80b9ed0cb54f186e3576f6e722cf93c1037ef9e8db10121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac00000000');
    });

    test('can create a 2-to-2 Transaction', () {
      final alice = ECPair.fromWIF(
          'L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1');
      final bob = ECPair.fromWIF(
          'KwcN2pT3wnRAurhy7qMczzbkpY5nXMW2ubh696UBc1bcwctTx26z');

      final txb = TransactionBuilder();
      txb.setVersion(1);
      txb.addInput(
          'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
          6); // Alice's previous transaction output, has 200000 satoshis
      txb.addInput(
          '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730',
          0); // Bob's previous transaction output, has 300000 satoshis
      txb.addOutput('1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb', BigInt.from(180000));
      txb.addOutput('1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9', BigInt.from(170000));
      // (in)(200000 + 300000) - (out)(180000 + 170000) = (fee)150000, this is the miner fee

      txb.sign(
          vin: 1,
          keyPair:
              bob); // Bob signs his input, which was the second input (1th)
      txb.sign(
          vin: 0,
          keyPair:
              alice); // Alice signs her input, which was the first input (0th)

      // prepare for broadcast to the Bitcoin network, see 'can broadcast a Transaction' below
      expect(txb.build().toHex(),
          '01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a4730440220372bdb77ae7206a2d16077679c98620a1c138a9f0a105ebf55e1774001bd6a3002205256f5da9abd99fde6a1df931025a112f78745a6a3a32a938d048df7bf4527fd012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006a47304402200e3207bf77614bbe5bd8f9b2491929c85c657df95a80b838a2e9e1292aad9069022003ef3f53a99616323c5e2cd473cd949e2ab0e0cc96f6e3562073d7c280623c6a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000');
    });

    test('can create an "null data" Transaction', () {
      final txb = TransactionBuilder();

      txb.setVersion(1);
      txb.addInput(
          '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d',
          0);
      txb.addNullOutput('Hey this is a random string without coins');
      //If no other output is set, coins in the input tx gets burned

      txb.sign(vin: 0, keyPair: aliceKey);

      // prepare for broadcast to the Bitcoin network, see 'can broadcast a Transaction' below
      expect(txb.build().toHex(),
          '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a47304402201c026f4849736e8e126d84637275631e4bb443642b2d17ce4616525543a96e7e022009c6e2c6a54a047f84106b99d66b4cfe45102d21b829ec6d449aaf3df3261e510121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff0100000000000000002b6a29486579207468697320697320612072616e646f6d20737472696e6720776974686f757420636f696e7300000000');
    });

    test('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input',
        () {
      final alice = ECPair.fromWIF(
          'cUNfunNKXNNJDvUvsjxz5tznMR6ob1g5K6oa4WGbegoQD3eqf4am',
          network: networks.testnet);
      final p2wpkh = P2WPKH(
              data: PaymentData(pubkey: alice.publicKey),
              network: networks.testnet)
          .data;
      final txb = TransactionBuilder(network: networks.testnet);
      txb.setVersion(1);
      txb.addInput(
        '53676626f5042d42e15313492ab7e708b87559dc0a8c74b7140057af51a2ed5b',
        0,
        null,
        p2wpkh.output,
      ); // Alice's previous transaction output, has 200000 satoshis
      txb.addOutput(
          'tb1qchsmnkk5c8wsjg8vxecmsntynpmkxme0yvh2yt', BigInt.from(1000000));
      txb.addOutput(
          'tb1qn40fftdp6z2lvzmsz4s0gyks3gq86y2e8svgap', BigInt.from(8995000));

      txb.sign(vin: 0, keyPair: alice, witnessValue: BigInt.from(10000000));
      // // prepare for broadcast to the Bitcoin network, see 'can broadcast a Transaction' below
      expect(txb.build().toHex(),
          '010000000001015beda251af570014b7748c0adc5975b808e7b72a491353e1422d04f5266667530000000000ffffffff0240420f0000000000160014c5e1b9dad4c1dd0920ec3671b84d649877636f2fb8408900000000001600149d5e94ada1d095f60b701560f412d08a007d115902473044022028dfa12874da651c6fcf01b77162904030fe3b9e1f1067120bf15200bbf8a5500220760f762ba1c3f5353063fa8231d6ccbd44f4e1c1f526017faf8b024eea990ad0012102f9f43a191c6031a5ffae27c5f9911218e78857923284ac1154abc2cc008544b200000000');
    });

    test('can create a P2SH output', () {
      final txb = TransactionBuilder();
      txb.setVersion(1);
      txb.addInput(
          '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d',
          0);
      txb.addOutput('31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLj', BigInt.from(1000));
      // Reusing key from above
      txb.sign(vin: 0, keyPair: aliceKey);

      expect(txb.build().toHex(),
          '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a4730440220094ad6e0c3353d35dee4321bb9ac2bcef7d4de5f6e55715a1f5f580a1720938102202c2777b31b9281e4814320a898f17468db32f05f21f20c569d66c1fb601a27ee0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e80300000000000017a9140102030405060708090a0b0c0d0e0f10111213148700000000');
    });

    test('can create a P2WSH output', () {
      final txb = TransactionBuilder();
      txb.setVersion(1);
      txb.addInput(
          '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d',
          0);
      txb.addOutput(
          'bc1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0szrtjt7',
          BigInt.from(1000));
      txb.sign(vin: 0, keyPair: aliceKey);

      expect(txb.build().toHex(),
          '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a47304402205cf3fe67ea8eb0fb92dcbc489117834b7cd75c8fa17c12b4a0d4ed59d912ff7a02204ebeecdc9e3d0552b52c7d3b09b7c04110ba9dc7e39181575d38e2bd37bdf35c0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e803000000000000220020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000');
    });
  });
}
