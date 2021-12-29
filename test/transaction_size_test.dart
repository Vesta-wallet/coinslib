import 'package:coinslib/src/ecpair.dart';
import 'package:coinslib/src/transaction_builder.dart';
import 'package:test/test.dart';
import 'package:coinslib/src/transaction.dart';
import 'package:coinslib/src/models/networks.dart' as NETWORKS;

main() {

  group('Transaction.txSize', () {

    test('transaction size is not 1 byte under', () {

      // Taken from
      // 471b4cfb93d94c74d7f8a3f6b4e877502d6deeba6902086be342b80386342a46 which
      // supposedly has the incorrect size

      final tx = Transaction.fromHex(
        '03000000010ddc883396c194c2f9b5210128140ebb62468c6b6dd6eae96e0dd308a826f1b8010000006b483045022100a2f306471fb843832a90bc0638dce45f3cb71b4116964200756eac347e821d530220158822ee763acf1d007a94e17c643ac964edf970799d84d9da378a52f27626d101210371bdd9211a51b6b72e902291649970b2a1783d6f2ac40808ca6cdc7f5e36002cffffffff0300000000000000001976a914b8be9179431a4ffd394589426ec802648bdc4d9e88ac04e80e00000000001976a914bff646a216d87099390cb3f68ff54b828870ae6988ac00000000000000004b6a49576973682050656572636f696e20746f206d616b6520616c6c2069747320686f646c6572732068617070792074686973204368726973746d617320616e64204e657720596561723b2900000000'
      );

      expect(tx.txSize, 310);

    });

    test('transaction is not 1 byte over', () {

      // Taken from 8de5e69a1f306ab64242b576d7de2ae03645df93f6b07acf5ce392eb9ed3ce28
      // Supposedly overpays 20 satoshis

      final tx = Transaction.fromHex(
        '0300000001185117b997598905fb7eb8caf144f80ac929bb446dc0ad30bcdd22e502d38d4f010000006a47304402201859cb81611f3af1ad6389c6d2c9f9cbbd6dd683cd5de84da1cd38447df14648022028c2a5827c221cfeaa9e77a24eeb6bdc9693ff172db82165a02e4ccb85d1c3b30121027c447812d54c147b61cb1f7947bee25adcb40787c795f240bd91e912b12ccb28ffffffff0300000000000000001976a914b8be9179431a4ffd394589426ec802648bdc4d9e88ac06264c00000000001976a9146dc10797a388d19bbd64d82f814cf174c0379ca288ac0000000000000000166a14476f64206a756c20667261204e6f726765203a2900000000'
      );

      expect(tx.txSize, 256);

    });

    test('built tranasaction gives correct size', () {

      // Peercoin WIF format
      final aliceKey = ECPair.fromWIF(
        'U9ofQxewXjF48KW7J5zd5FhnC3oCYsj15ESMtUvJnsfbjEDN43aW',
        network: NETWORKS.peercoin
      );

      final txb = TransactionBuilder(network: NETWORKS.peercoin);

      txb.setVersion(3);
      txb.addInput(
        '61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d',
        0
      );

      txb.addOutput('P8gWEwpDSPPohHMHcNA5cg7di7pgRrXGGk', 12000);
      // Do null outputs break it?
      txb.addNullOutput('Hey this is a random string without coins');

      txb.sign(vin: 0, keyPair: aliceKey);

      final tx = txb.build();

      // No witness data so size should equal buffer size
      expect(tx.txSize, tx.toBuffer().length);
      // Deterministically 244 bytes each time
      expect(tx.txSize, 244);

    });

  });

}
