import 'dart:typed_data';

import 'package:coinslib/src/transaction.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/ecpair.dart';
import 'package:coinslib/src/transaction_builder.dart';
import 'package:coinslib/src/models/networks.dart' as networks;
import 'package:coinslib/src/payments/p2wpkh.dart' show P2WPKH;
import 'package:coinslib/src/payments/index.dart' show PaymentData;
import 'package:coinslib/src/payments/multisig.dart' show MultisigScript;
import '../keys.dart';

main() {

  getTxBuilderWithIn() {
    final txb = TransactionBuilder();
    txb.setVersion(1);
    txb.addInput(
      '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d', 0
    );
    return txb;
  }

  test('can create a 1-to-1 Transaction', () {
    final txb = getTxBuilderWithIn();

    txb.addOutput('1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', BigInt.from(12000));
    // (in)15000 - (out)12000 = (fee)3000, this is the miner fee

    txb.sign(vin: 0, keyPair: aliceKey);

    expect(
        txb.build().toHex(),
        '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a4730440220730c3da33eded733722545be42d4a2c456551daabbc7b6de973b79fa4b5247b9022032884d2822201fa2dae1f80b9ed0cb54f186e3576f6e722cf93c1037ef9e8db10121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac00000000'
    );

  });

  test('can create a 2-to-2 Transaction', () {

    final txb = TransactionBuilder();
    txb.setVersion(1);
    txb.addInput(
        'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c', 6
    ); // Alice's previous transaction output, has 200000 satoshis
    txb.addInput(
        '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730', 0
    ); // Bob's previous transaction output, has 300000 satoshis
    txb.addOutput('1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb', BigInt.from(180000));
    txb.addOutput('1JtK9CQw1syfWj1WtFMWomrYdV3W2tWBF9', BigInt.from(170000));
    // (in)(200000 + 300000) - (out)(180000 + 170000) = (fee)150000, this is the miner fee

    // Bob signs his input, which was the second input (1th)
    txb.sign(vin: 1, keyPair: bobKey);
    // Carol signs her input, which was the first input (0th)
    txb.sign(vin: 0, keyPair: carolKey);

    expect(
        txb.build().toHex(),
        '01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a4730440220372bdb77ae7206a2d16077679c98620a1c138a9f0a105ebf55e1774001bd6a3002205256f5da9abd99fde6a1df931025a112f78745a6a3a32a938d048df7bf4527fd012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006a47304402200e3207bf77614bbe5bd8f9b2491929c85c657df95a80b838a2e9e1292aad9069022003ef3f53a99616323c5e2cd473cd949e2ab0e0cc96f6e3562073d7c280623c6a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000'
    );

  });

  test('can create an "null data" Transaction', () {

    final txb = getTxBuilderWithIn();

    txb.addNullOutput('Hey this is a random string without coins');
    //If no other output is set, coins in the input tx gets burned

    txb.sign(vin: 0, keyPair: aliceKey);

    expect(
        txb.build().toHex(),
        '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a47304402201c026f4849736e8e126d84637275631e4bb443642b2d17ce4616525543a96e7e022009c6e2c6a54a047f84106b99d66b4cfe45102d21b829ec6d449aaf3df3261e510121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff0100000000000000002b6a29486579207468697320697320612072616e646f6d20737472696e6720776974686f757420636f696e7300000000'
    );

  });

  test('can create  a Transaction, w/ a P2WPKH input', () {

    final alice = ECPair.fromWIF(
        'cUNfunNKXNNJDvUvsjxz5tznMR6ob1g5K6oa4WGbegoQD3eqf4am',
        network: networks.testnet
    );
    final p2wpkh = P2WPKH(
        data: PaymentData(pubkey: alice.publicKey),
        network: networks.testnet
    ).data;

    final txb = TransactionBuilder(network: networks.testnet);
    txb.setVersion(1);
    txb.addInput(
        '53676626f5042d42e15313492ab7e708b87559dc0a8c74b7140057af51a2ed5b',
        0,
        null,
        p2wpkh.output
    ); // Alice's previous transaction output, has 200000 satoshis

    txb.addOutput(
      'tb1qchsmnkk5c8wsjg8vxecmsntynpmkxme0yvh2yt',
      BigInt.from(1000000)
    );
    txb.addOutput(
      'tb1qn40fftdp6z2lvzmsz4s0gyks3gq86y2e8svgap',
      BigInt.from(8995000)
    );

    txb.sign(vin: 0, keyPair: alice, witnessValue: BigInt.from(10000000));
    expect(
        txb.build().toHex(),
        '010000000001015beda251af570014b7748c0adc5975b808e7b72a491353e1422d04f5266667530000000000ffffffff0240420f0000000000160014c5e1b9dad4c1dd0920ec3671b84d649877636f2fb8408900000000001600149d5e94ada1d095f60b701560f412d08a007d115902473044022028dfa12874da651c6fcf01b77162904030fe3b9e1f1067120bf15200bbf8a5500220760f762ba1c3f5353063fa8231d6ccbd44f4e1c1f526017faf8b024eea990ad0012102f9f43a191c6031a5ffae27c5f9911218e78857923284ac1154abc2cc008544b200000000'
    );

  });

  test('can create a P2SH output', () {

    final txb = getTxBuilderWithIn();

    txb.addOutput('31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLj', BigInt.from(1000));
    // Reusing key from above
    txb.sign(vin: 0, keyPair: aliceKey);

    expect(
        txb.build().toHex(),
        '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a4730440220094ad6e0c3353d35dee4321bb9ac2bcef7d4de5f6e55715a1f5f580a1720938102202c2777b31b9281e4814320a898f17468db32f05f21f20c569d66c1fb601a27ee0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e80300000000000017a9140102030405060708090a0b0c0d0e0f10111213148700000000'
    );

  });

  test('can create a P2WSH output', () {

    final txb = getTxBuilderWithIn();
    txb.addOutput(
      'bc1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0szrtjt7',
      BigInt.from(1000)
    );
    txb.sign(vin: 0, keyPair: aliceKey);

    expect(
        txb.build().toHex(),
        '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006a47304402205cf3fe67ea8eb0fb92dcbc489117834b7cd75c8fa17c12b4a0d4ed59d912ff7a02204ebeecdc9e3d0552b52c7d3b09b7c04110ba9dc7e39181575d38e2bd37bdf35c0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e803000000000000220020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000'
    );

  });

  test('create partial P2WSH and then complete', () {

    // 2-of-2 multisig P2WSH, to be signed twice checking the incomplete
    // builds work

    var txb = getTxBuilderWithIn();
    txb.addOutput('1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', BigInt.from(12000));

    Uint8List witnessScript = MultisigScript(
        pubkeys: [aliceKey.publicKey!, bobKey.publicKey!], threshold: 2
    ).scriptBytes;

    txb.sign(
        vin: 0,
        keyPair: aliceKey,
        witnessValue: BigInt.from(10000),
        witnessScript: witnessScript
    );

    // Test building partial
    final partialHex = txb.buildIncomplete().toHex();

    // Recreate from hex and complete transaction
    txb = TransactionBuilder.fromTransaction(Transaction.fromHex(partialHex));

    txb.sign(
      vin: 0,
      keyPair: bobKey,
      witnessValue:  BigInt.from(10000),
      witnessScript: witnessScript
    );

    final hexStr = '010000000001019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d5610000000000ffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac0400473044022013f4f7b304d0d934cfefe3429188eff9484c681bb772ceff60d6a48e31bc39e302203b6ab05a7a90e7e525f7d8263bfec40f5d0ed7c10e3141d65b9bfb8e5c3bfb220147304402200afb1a6c72b437179a83b4557e6f1ce6101187b2884bd5f6dd68b294d4a9353502202896dd07c2cc3b5b303944b9a1c32ab724070d77f0ac34d247d2cfad1a589c8901475221029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59f2103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a28952ae00000000';

    final tx = txb.build();

    // Ensure that the transaction has 4 witness items: dummy 0, 2 signatures
    // and the serialised script
    expect(tx.ins[0].witness.length, 4);

    expect(tx.toHex(), hexStr);

    // Should remain the same after decode and encode again
    expect(Transaction.fromBuffer(tx.toBuffer()).toHex(), hexStr);

  });

  test('sign P2WSH multisig transaction, out of order', () {

    // Sign 3-of-4 with keys 3, 1, 2 on the second input
    // This is a transaction successfully tested on peercoin testnet, with the
    // tx hash of 7012f9319c4f65c3544e35688ceccd3621988d2ec19587043cc863b0c493c6e6

    var txb = TransactionBuilder();

    // PPC using v3 txs
    txb.setVersion(3);

    // Output of 180PPC
    txb.addOutput(
      '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP',
      BigInt.from(180000000)
    );

    Uint8List witnessScript = MultisigScript(
        pubkeys: [aliceKey, bobKey, carolKey, davidKey]
          .map((key) => key.publicKey!).toList(),
        threshold: 3
    ).scriptBytes;

    // Add first P2PKH input of 90 PPC
    txb.addInput(
        "fbffd416274f6afb8256a34224aa1600db28944bafd4c5cecb3c3b12cadbceb9", 0
    );

    // Add input for multisig address of 100 PPC
    txb.addInput(
        "67f29de2c480a6b18e53b5a2823ad196509bf60dc9a52813d22bfa519db22053", 1
    );

    // Sign first input
    txb.sign(vin: 0, keyPair: aliceKey);

    // Out of order signing with encode/decode between each

    void partialSign(ECPair key) {

      txb.sign(
          vin: 1,
          keyPair: key,
          witnessValue: BigInt.from(100000000),
          witnessScript: witnessScript
      );

      final encoded = txb.buildIncomplete().toBuffer();
      txb = TransactionBuilder.fromTransaction(Transaction.fromBuffer(encoded));

    }

    // 3, 1, 2
    partialSign(carolKey);
    partialSign(aliceKey);
    partialSign(bobKey);

    expect(
      txb.build().toHex(),
      "03000000000102b9cedbca123b3ccbcec5d4af4b9428db0016aa2442a35682fb6a4f2716d4fffb000000006a473044022033542dff70c2ea736c20cdd13e2b9fb9ebaa8ec6dfb408a54fadc4956e3f2bb9022079219767f3450046120691d1b6898e7790d2abec7cb22d851d4a639f31bc64fb0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff5320b29d51fa2bd21328a5c90df69b5096d13a82a2b5538eb1a680c4e29df2670100000000ffffffff010095ba0a000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac000500463043021f602bb521f57b7db4e3ca299cb3cb859184c0fdd295b15761f587800b0a3dc902202a912c71a707bf3c0c13fd70a9fffa86d7a1a2b1e02d86cd689ef8ec8fdbc28d0147304402205cd6be52f472e0a42d9e886a7cbfad205c6e71042badc03de34b778630cb93b902201b266eaccb47dc027a812ab9cf3e9025bfec0530824a3bfe43c5b491cb13a5f40147304402201beab62418df3e4028d7641d1f570e770c8c5c38d2df7c27aeff4d725a8dfdf002207235a1cf54653669cb419b82886d38d3e94853408e882a007a99e8a9eb5baf48018b5321029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59f2103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a2892103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baac2103aea0dfd576151cb399347aa6732f8fdf027b9ea3ea2e65fb754803f776e0a50954ae00000000"
    );

  });

  test('construct fully comprehensive transcation', () {

    // Constructs a transaction with all supported input and output types that
    // works on Peercoin testnet.
    // Inlcudes P2PKH, P2WPKH and P2WSH inputs and outputs.
    // Also includes a P2SH output
    // Sucessfully broadcast as 1b67064ab827e00d163796ec6ee0e12f6006223f7610b29d1a8684543e7ec10e

    var txb = TransactionBuilder();
    txb.setVersion(3);

    // Outputs
    final outAmt = BigInt.from(10000);
    txb.addOutput("1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP", outAmt);
    txb.addOutput("bc1qg7rzlct9ucfp47qdth0paj683mghq4jmg8l7ga", outAmt);
    txb.addOutput("bc1qqk7z8s30kzdn9zwuxxrdmga3txymeljpsc42cdm7khww9xqa8w2qkp0v4s", outAmt);
    txb.addOutput("31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLj", outAmt);

    // P2PKH input (alice)
    txb.addInput(
        "12ddf17179751b378b5983ce6c1a83444ba770510c603d869e7d5553b2bbbf73", 1
    );

    // P2WPKH input (carol)

    final p2wpkh = P2WPKH(
      data: PaymentData(pubkey: carolKey.publicKey),
      network: networks.peercoinTestnet
    ).data;

    txb.addInput(
        "03975de4457cecd2e5681eb2126844427003680e1c30d7c2422fef3aa85b4461", 1,
        null, p2wpkh.output
    );

    // P2WSH input (alice and bob)

    Uint8List witnessScript = MultisigScript(
        pubkeys: [aliceKey.publicKey!, bobKey.publicKey!], threshold: 1
    ).scriptBytes;

    txb.addInput(
        "35f1fb897f5bb24254771132bbedd7732406154afc64418ce3ba9c1326808c73", 1
    );

    // Sign P2PKH
    txb.sign(vin: 0, keyPair: aliceKey);
    // Sign P2WPKH with 0.02ppc
    txb.sign(vin: 1, keyPair: carolKey, witnessValue: BigInt.from(20000));
    // Sign P2WSH with 0.031234ppc
    txb.sign(
      vin: 2,
      keyPair: bobKey,
      witnessValue: BigInt.from(31234),
      witnessScript: witnessScript
    );

    // Check hex, including after decode and encode again
    final expectHex = "0300000000010373bfbbb253557d9e863d600c5170a74b44831a6cce83598b371b757971f1dd12010000006a473044022062e6eb08c2b3e2bf1affc7be56c26ade94758eb70b508eab00899b583a67f35b022048dcad4ea0d39c0dc139c7bc15d155129925e7223f2a83392d950c2a23d20e780121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff61445ba83aef2f42c2d7301c0e68037042446812b21e68e5d2ec7c45e45d97030100000000ffffffff738c8026139cbae38c4164fc4a15062473d7edbb3211775442b25b7f89fbf1350100000000ffffffff0410270000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac102700000000000016001447862fe165e6121af80d5dde1ecb478ed170565b102700000000000022002005bc23c22fb09b3289dc3186dda3b15989bcfe41862aac377eb5dce2981d3b94102700000000000017a9140102030405060708090a0b0c0d0e0f1011121314870002473044022022b28be22b288c2738ea011378a54d9ef0d0c4453878f6d555985283ab1e884702200dc48c78d82775f501543178b5bcad64c8dc6b463d2823b9b2f9328bb1b7c335012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baac0300473044022028d35b6f95dc9fb1ff2eacc3071fbcf36cf56c3d0233a58f4e83931d5c16cc5202202ba4bb8c07560ab3b42146c2475438828db9283c4f5650fb03aceb88945a6f9001475121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59f2103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a28952ae00000000";

    expect(txb.build().toHex(), expectHex);
    expect(Transaction.fromHex(expectHex).toHex(), expectHex);

  });

}
