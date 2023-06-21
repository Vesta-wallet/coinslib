# 3.1.8
- Final release of "coinslib", will be superseeded by a package "coinlib" in the near future, which will be a complete re-write.

# 3.1.7
- Verify message signatures against addresses

# 3.1.6
- **(potentially) Breaking change**: Simplify P2WPKH and P2PKH classes. Add P2SH-P2PKH address generation.
- P2SH Multisig Input Signing and Output Address Generation

# 3.1.5
- P2WSH multisig inputs

# 3.1.4
- Fix message signing

## 3.1.3
- **Breaking change**: Change transaction builder addOutput argument to BigInt for better flutter web compatability 

## 3.1.2
- Produce fixed-size signatures with low r-values (no more inconsistent tx sizes)

## 3.1.1
- Add P2WSH outputs

## 3.1.0
- This release adds P2SH transaction building and address verification  
 
## 3.0.3
- This release adds OP_RETURN to coinslib  

**Breaking change**: The network model has been enhanced and it is **mandatory** to set an OP_RETURN size now for each network. 
## 3.0.2
- fix incomplete entropy https://github.com/Vesta-wallet/coinslib/issues/3

## 3.0.1
- Update readme and examples

## 3.0.0
- Null Safety and fork

## 2.0.2
- Add support for optional 'noStrict' parameter in Transaction.fromBuffer

## 2.0.1
- Add payments/index.dart to lib exports

## 2.0.0 **Backwards Incompatibility**
- Please update your sign function if you use this version. sign now [required parameter name](https://github.com/anicdh/bitcoin_flutter/blob/master/lib/src/transaction_builder.dart#L121)
- Support  building a Transaction with a SegWit P2WPKH input
- Add Address.validateAddress to validate address

## 1.1.0

- Add PaymentData, P2PKHData to be deprecated, will remove next version
- Support p2wpkh

## 1.0.7

- Try catch getter privKey, base58Priv, wif
- Possible to create a neutered HD Wallet

## 1.0.6

- Accept non-standard payment

## 1.0.5

- Add ECPair to index

## 1.0.4

- Add transaction to index

## 1.0.3

- Fix bug testnet BIP32

## 1.0.2

- Add sign and verify for HD Wallet and Wallet

## 1.0.1

- Add derive and derive path for HD Wallet

## 1.0.0

- Transaction implementation

## 0.1.1

- HDWallet from Seed implementation
- Wallet from WIF implementation
