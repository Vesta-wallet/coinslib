import 'package:coinslib/coinslib.dart';
import 'package:bip39/bip39.dart' as bip39;

main() {
  var peercoin = NetworkType(
    messagePrefix: 'Peercoin Signed Message:\n',
    bech32: 'pc',
    bip32: Bip32Type(public: 0x043587cf, private: 0x04358394),
    pubKeyHash: 0x37,
    scriptHash: 0x75,
    wif: 0xb7,
    opreturnSize: 256,
  );

  var seed = bip39.mnemonicToSeed(
      'praise you muffin lion enable neck grocery crumble super myself license ghost');
  var hdWallet = HDWallet.fromSeed(
    seed,
    network: peercoin,
  ); //default network is Bitcoin
  print(hdWallet.address);
  // => PAEeTmyME9rb2j3Ka9M65UG7To5wzZ36nf
  print(hdWallet.pubKey);
  // => 0360729fb3c4733e43bf91e5208b0d240f8d8de239cff3f2ebd616b94faa0007f4
  print(hdWallet.privKey);
  // => 01304181d699cd89db7de6337d597adf5f78dc1f0784c400e41a3bd829a5a226
  print(hdWallet.wif);
  // => U59hdLpi45SME3yjGoXXuYy8FVvW2yUoLdE3TJ3gfRYJZ33iWbfD

  var wallet = Wallet.fromWIF(
      'U59hdLpi45SME3yjGoXXuYy8FVvW2yUoLdE3TJ3gfRYJZ33iWbfD', peercoin);
  print(wallet.address);
  // => PAEeTmyME9rb2j3Ka9M65UG7To5wzZ36nf
  print(wallet.pubKey);
  // => 03aea0dfd576151cb399347aa6732f8fdf027b9ea3ea2e65fb754803f776e0a509
  print(wallet.privKey);
  // => 01304181d699cd89db7de6337d597adf5f78dc1f0784c400e41a3bd829a5a226
  print(wallet.wif);
  // => U59hdLpi45SME3yjGoXXuYy8FVvW2yUoLdE3TJ3gfRYJZ33iWbfD
}
