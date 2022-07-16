import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'payments/index.dart' show PaymentData;
import 'payments/p2pkh.dart' show P2PKH;
import 'payments/p2pk.dart' show P2PK;
import 'payments/p2wpkh.dart' show P2WPKH;
import 'crypto.dart' as bcrypto;
import 'classify.dart';
import 'utils/check_types.dart';
import 'utils/script.dart' as bscript;
import 'utils/constants/op.dart';
import 'utils/serialisation.dart';
import 'utils/varuint.dart' as varuint;

const defaultSequence = 0xffffffff;
const sigHashAll = 0x01;
const sigHashNone = 0x02;
const sigHashSingle = 0x03;
const sigHashAnyoneCanPay = 0x80;
const advancedTransactionMarker = 0x00;
const advancedTransactionFlag = 0x01;
final emptyScript = Uint8List.fromList([]);
final List<Uint8List> emptyWitness = [];
final zero = HEX
    .decode('0000000000000000000000000000000000000000000000000000000000000000');
final one = HEX
    .decode('0000000000000000000000000000000000000000000000000000000000000001');
final valueUint64Max = HEX.decode('ffffffffffffffff');
final blankOutput =
    Output(script: emptyScript, valueBuffer: valueUint64Max as Uint8List);

class Transaction {
  int version = 1;
  int locktime = 0;
  List<Input> ins = [];
  List<Output> outs = [];

  Transaction();

  int addInput(Uint8List hash, int index,
      [int? sequence, Uint8List? scriptSig]) {
    ins.add(Input(
        hash: hash,
        index: index,
        sequence: sequence ?? defaultSequence,
        script: scriptSig ?? emptyScript,
        witness: emptyWitness));
    return ins.length - 1;
  }

  int addOutput(Uint8List scriptPubKey, BigInt value) {
    outs.add(Output(script: scriptPubKey, value: value));
    return outs.length - 1;
  }

  bool hasWitnesses() {
    var witness = ins.indexWhere(
        (input) => input.witness != null && input.witness!.isNotEmpty);
    return witness != -1;
  }

  setInputScript(int index, Uint8List scriptSig) {
    ins[index].script = scriptSig;
  }

  setWitness(int index, List<Uint8List>? witness) {
    ins[index].witness = witness;
  }

  hashForWitnessV0(
      int inIndex, Uint8List prevOutScript, BigInt value, int hashType) {
    var hashOutputs = zero;
    var hashPrevouts = zero;
    var hashSequence = zero;

    if ((hashType & sigHashAnyoneCanPay) == 0) {
      final buffer = Uint8List(36 * ins.length);
      final writer = BytesReaderWriter(buffer);
      for (final txIn in ins) {
        writer.writeSlice(txIn.hash!);
        writer.writeUInt32(txIn.index!);
      }
      hashPrevouts = bcrypto.hash256(buffer);
    }

    if ((hashType & sigHashAnyoneCanPay) == 0 &&
        (hashType & 0x1f) != sigHashSingle &&
        (hashType & 0x1f) != sigHashNone) {
      final buffer = Uint8List(4 * ins.length);
      final writer = BytesReaderWriter(buffer);
      for (final txIn in ins) {
        writer.writeUInt32(txIn.sequence!);
      }
      hashSequence = bcrypto.hash256(buffer);
    }

    if ((hashType & 0x1f) != sigHashSingle &&
        (hashType & 0x1f) != sigHashNone) {
      final txOutsSize = outs.fold(
          0, (int sum, output) => sum + 8 + varSliceSize(output.script!));
      final buffer = Uint8List(txOutsSize);
      final writer = BytesReaderWriter(buffer);
      for (final txOut in outs) {
        writer.writeUInt64(txOut.value!);
        writer.writeVarSlice(txOut.script!);
      }
      hashOutputs = bcrypto.hash256(buffer);
    } else if ((hashType & 0x1f) == sigHashSingle && inIndex < outs.length) {
      // SIGHASH_SINGLE only hash that according output
      final output = outs[inIndex];
      final buffer = Uint8List(8 + varSliceSize(output.script!));
      final writer = BytesReaderWriter(buffer);
      writer.writeUInt64(output.value!);
      writer.writeVarSlice(output.script!);
      hashOutputs = bcrypto.hash256(buffer);
    }

    final buffer = Uint8List(156 + varSliceSize(prevOutScript));
    final writer = BytesReaderWriter(buffer);
    final input = ins[inIndex];
    writer.writeUInt32(version);
    writer.writeSlice(hashPrevouts);
    writer.writeSlice(hashSequence);
    writer.writeSlice(input.hash!);
    writer.writeUInt32(input.index!);
    writer.writeVarSlice(prevOutScript);
    writer.writeUInt64(value);
    writer.writeUInt32(input.sequence!);
    writer.writeSlice(hashOutputs);
    writer.writeUInt32(locktime);
    writer.writeUInt32(hashType);

    return bcrypto.hash256(buffer);
  }

  hashForSignature(int inIndex, Uint8List prevOutScript, int hashType) {
    if (inIndex >= ins.length) return one;
    // ignore OP_CODESEPARATOR
    final ourScript =
        bscript.compile(bscript.decompile(prevOutScript)!.where((x) {
      return x != ops['OP_CODESEPARATOR'];
    }).toList());
    final txTmp = Transaction.clone(this);
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) == sigHashNone) {
      txTmp.outs = [];
      // ignore sequence numbers (except at inIndex)
      for (var i = 0; i < txTmp.ins.length; i++) {
        if (i != inIndex) {
          txTmp.ins[i].sequence = 0;
        }
      }

      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) == sigHashSingle) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= outs.length) return one;

      // truncate outputs after
      txTmp.outs.length = inIndex + 1;

      // 'blank' outputs before
      for (var i = 0; i < inIndex; i++) {
        txTmp.outs[i] = blankOutput;
      }
      // ignore sequence numbers (except at inIndex)
      for (var i = 0; i < txTmp.ins.length; i++) {
        if (i != inIndex) {
          txTmp.ins[i].sequence = 0;
        }
      }
    }

    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & sigHashAnyoneCanPay != 0) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;
      // SIGHASH_ALL: only ignore input scripts
    } else {
      // 'blank' others input scripts
      for (var input in txTmp.ins) {
        input.script = emptyScript;
      }
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    final buffer = Uint8List(txTmp.virtualSize() + 4);
    buffer.buffer
        .asByteData()
        .setUint32(buffer.length - 4, hashType, Endian.little);
    txTmp._toBuffer(buffer, 0);
    return bcrypto.hash256(buffer);
  }

  _byteLength(allowWitness) {
    var hasWitness = allowWitness && hasWitnesses();
    return (hasWitness ? 10 : 8) +
        varuint.encodingLength(ins.length) +
        varuint.encodingLength(outs.length) +
        ins.fold(0, (sum, input) => sum + 40 + varSliceSize(input.script!)) +
        outs.fold(0, (sum, output) => sum + 8 + varSliceSize(output.script!)) +
        (hasWitness
            ? ins.fold(0, (sum, input) => sum + vectorSize(input.witness!))
            : 0);
  }

  int vectorSize(List<Uint8List> someVector) {
    var length = someVector.length;
    return varuint.encodingLength(length) +
        someVector.fold(0, (sum, witness) => sum + varSliceSize(witness));
  }

  int weight() {
    var base = _byteLength(false);
    var total = _byteLength(true);
    return base * 3 + total;
  }

  int byteLength() {
    return _byteLength(true);
  }

  int virtualSize() {
    return (weight() / 4).ceil();
  }

  int get txSize {
    return virtualSize();
  }

  Uint8List toBuffer([Uint8List? buffer, int initialOffset = 0]) {
    return _toBuffer(buffer, initialOffset, true);
  }

  String toHex() {
    return HEX.encode(toBuffer());
  }

  bool isCoinbaseHash(buffer) {
    isHash256bit(buffer);
    for (var i = 0; i < 32; ++i) {
      if (buffer[i] != 0) return false;
    }
    return true;
  }

  bool isCoinbase() {
    return ins.length == 1 && isCoinbaseHash(ins[0].hash);
  }

  Uint8List getHash() {
    // if (isCoinbase()) return Uint8List.fromList(List.generate(32, (i) => 0));
    return bcrypto.hash256(_toBuffer(null, 0, false));
  }

  String getId() {
    return HEX.encode(getHash().reversed.toList());
  }

  _toBuffer(
      [Uint8List? buffer, int initialOffset = 0, bool allowWitness = false]) {
    // _ALLOW_WITNESS is used to separate witness part when calculating tx id
    buffer ??= Uint8List(_byteLength(allowWitness));

    var writer = BytesReaderWriter(buffer, initialOffset);

    // Start writeBuffer
    writer.writeInt32(version);

    if (allowWitness && hasWitnesses()) {
      writer.writeUInt8(advancedTransactionMarker);
      writer.writeUInt8(advancedTransactionFlag);
    }

    writer.writeVarInt(ins.length);

    for (var txIn in ins) {
      writer.writeSlice(txIn.hash!);
      writer.writeUInt32(txIn.index!);
      writer.writeVarSlice(txIn.script!);
      writer.writeUInt32(txIn.sequence!);
    }

    writer.writeVarInt(outs.length);

    for (var txOut in outs) {
      if (txOut.valueBuffer == null) {
        writer.writeUInt64(txOut.value!);
      } else {
        writer.writeSlice(txOut.valueBuffer!);
      }
      writer.writeVarSlice(txOut.script!);
    }

    if (allowWitness && hasWitnesses()) {
      for (var txInt in ins) {
        writer.writeVector(txInt.witness!);
      }
    }

    writer.writeUInt32(locktime);

    // avoid slicing unless necessary
    if (initialOffset > 0) return buffer.sublist(initialOffset, writer.offset);

    return buffer;
  }

  factory Transaction.clone(Transaction txFromArg) {
    Transaction tx = Transaction();
    tx.version = txFromArg.version;
    tx.locktime = txFromArg.locktime;
    tx.ins = txFromArg.ins.map((input) {
      return Input.clone(input);
    }).toList();
    tx.outs = txFromArg.outs.map((output) {
      return Output.clone(output);
    }).toList();
    return tx;
  }

  factory Transaction.fromBuffer(
    Uint8List buffer, {
    bool noStrict = false,
  }) {
    final tx = Transaction();
    final reader = BytesReaderWriter(buffer);

    tx.version = reader.readInt32();

    final marker = reader.readUInt8();
    final flag = reader.readUInt8();

    final hasWitnesses =
        marker == advancedTransactionMarker && flag == advancedTransactionFlag;

    if (!hasWitnesses) reader.offset -= 2; // Reset offset if not segwit tx

    final vinLen = reader.readVarInt();
    for (var i = 0; i < vinLen; ++i) {
      tx.ins.add(Input(
          hash: reader.readSlice(32),
          index: reader.readUInt32(),
          script: reader.readVarSlice(),
          sequence: reader.readUInt32()));
    }

    final voutLen = reader.readVarInt();
    for (var i = 0; i < voutLen; ++i) {
      tx.outs.add(
          Output(value: reader.readUInt64(), script: reader.readVarSlice()));
    }

    if (hasWitnesses) {
      for (var i = 0; i < vinLen; ++i) {
        tx.ins[i].witness = reader.readVector();
      }
    }

    tx.locktime = reader.readUInt32();

    if (noStrict) return tx;

    if (!reader.atEnd) throw ArgumentError('Transaction has unexpected data');

    return tx;
  }

  factory Transaction.fromHex(
    String hex, {
    bool noStrict = false,
  }) {
    return Transaction.fromBuffer(
      HEX.decode(hex) as Uint8List,
      noStrict: noStrict,
    );
  }

  @override
  String toString() {
    var buf = StringBuffer();
    for (var txInput in ins) {
      buf.write(txInput.toString());
    }
    for (var txOutput in outs) {
      buf.write(txOutput.toString());
    }
    return buf.toString();
  }
}

class Input {
  Uint8List? hash;
  int? index;
  int? sequence;
  BigInt? value;
  Uint8List? script;
  Uint8List? signScript;
  Uint8List? prevOutScript;
  String? prevOutType;
  bool hasWitness = false;
  List<Uint8List?>? pubkeys;
  List<Uint8List?>? signatures;
  List<Uint8List>? witness;

  Input(
      {this.hash,
      this.index,
      this.script,
      this.sequence,
      this.value,
      this.prevOutScript,
      this.pubkeys,
      this.signatures,
      this.witness,
      this.prevOutType}) {
    if (hash != null && !isHash256bit(hash!)) {
      throw ArgumentError('Invalid input hash');
    }
    if (index != null && !isUint(index!, 32)) {
      throw ArgumentError('Invalid input index');
    }
    if (sequence != null && !isUint(sequence!, 32)) {
      throw ArgumentError('Invalid input sequence');
    }
    if (value != null && !isSatoshi(value!)) {
      throw ArgumentError('Invalid ouput value');
    }
  }

  factory Input.expandInput(Uint8List scriptSig, List<Uint8List> witness,
      [String? type, Uint8List? scriptPubKey]) {
    if (type == null || type == '') {
      var ssType = classifyInput(scriptSig);
      var wsType = classifyWitness(witness);
      if (ssType == scriptTypes['NONSTANDARD']) ssType = null;
      if (wsType == scriptTypes['NONSTANDARD']) wsType = null;
      type = ssType ?? wsType;
    }
    if (type == scriptTypes['P2WPKH']) {
      P2WPKH p2wpkh = P2WPKH(data: PaymentData(witness: witness));
      return Input(
          prevOutScript: p2wpkh.data.output,
          prevOutType: scriptTypes['P2WPKH'],
          pubkeys: [p2wpkh.data.pubkey!],
          signatures: [p2wpkh.data.signature!]);
    } else if (type == scriptTypes['P2PKH']) {
      P2PKH p2pkh = P2PKH(data: PaymentData(input: scriptSig));
      return Input(
          prevOutScript: p2pkh.data.output,
          prevOutType: scriptTypes['P2PKH'],
          pubkeys: [p2pkh.data.pubkey!],
          signatures: [p2pkh.data.signature!]);
    } else if (type == scriptTypes['P2PK']) {
      P2PK p2pk = P2PK(data: PaymentData(input: scriptSig));
      return Input(
          prevOutType: scriptTypes['P2PK'],
          pubkeys: [],
          signatures: [p2pk.data.signature!]);
    }
    throw UnsupportedError('type "$type"');
  }

  factory Input.clone(Input input) {
    return Input(
      hash: input.hash != null ? Uint8List.fromList(input.hash!) : null,
      index: input.index,
      script: input.script != null ? Uint8List.fromList(input.script!) : null,
      sequence: input.sequence,
      value: input.value,
      prevOutScript: input.prevOutScript != null
          ? Uint8List.fromList(input.prevOutScript!)
          : null,
      pubkeys: input.pubkeys != null
          ? input.pubkeys!
              .map((pubkey) =>
                  pubkey != null ? Uint8List.fromList(pubkey) : null)
              .toList()
          : null,
      signatures: input.signatures != null
          ? input.signatures!
              .map((signature) =>
                  signature != null ? Uint8List.fromList(signature) : null)
              .toList()
          : null,
    );
  }

  @override
  String toString() {
    return 'Input{hash: $hash, index: $index, sequence: $sequence, value: $value, script: $script, signScript: $signScript, prevOutScript: $prevOutScript, pubkeys: $pubkeys, signatures: $signatures, witness: $witness, prevOutType: $prevOutType}';
  }
}

class Output {
  Uint8List? script;
  BigInt? value;
  Uint8List? valueBuffer;
  List<Uint8List?>? pubkeys;
  List<Uint8List?>? signatures;

  Output(
      {this.script,
      this.value,
      this.pubkeys,
      this.signatures,
      this.valueBuffer}) {
    if (value != null && !isSatoshi(value!)) {
      throw ArgumentError('Invalid ouput value');
    }
  }

  factory Output.expandOutput(Uint8List script, [Uint8List? ourPubKey]) {
    if (ourPubKey == null) return Output();
    var type = classifyOutput(script);
    if (type == scriptTypes['P2WPKH']) {
      Uint8List wpkh1 = P2WPKH(data: PaymentData(output: script)).data.hash!;
      Uint8List wpkh2 = bcrypto.hash160(ourPubKey);
      if (wpkh1 != wpkh2) throw ArgumentError('Hash mismatch!');
      return Output(pubkeys: [ourPubKey], signatures: [null]);
    } else if (type == scriptTypes['P2PKH']) {
      Uint8List pkh1 = P2PKH(data: PaymentData(output: script)).data.hash!;
      Uint8List pkh2 = bcrypto.hash160(ourPubKey);
      if (pkh1 != pkh2) throw ArgumentError('Hash mismatch!');
      return Output(pubkeys: [ourPubKey], signatures: [null]);
    }
    throw UnsupportedError('type "$type"');
  }

  factory Output.clone(Output output) {
    return Output(
      script: output.script != null ? Uint8List.fromList(output.script!) : null,
      value: output.value,
      valueBuffer: output.valueBuffer != null
          ? Uint8List.fromList(output.valueBuffer!)
          : null,
      pubkeys: output.pubkeys != null
          ? output.pubkeys!
              .map((pubkey) =>
                  pubkey != null ? Uint8List.fromList(pubkey) : null)
              .toList()
          : null,
      signatures: output.signatures != null
          ? output.signatures!
              .map((signature) =>
                  signature != null ? Uint8List.fromList(signature) : null)
              .toList()
          : null,
    );
  }

  @override
  String toString() {
    return 'Output{script: $script, value: $value, valueBuffer: $valueBuffer, pubkeys: $pubkeys, signatures: $signatures}';
  }
}

bool isCoinbaseHash(Uint8List buffer) {
  if (!isHash256bit(buffer)) throw ArgumentError('Invalid hash');
  for (var i = 0; i < 32; ++i) {
    if (buffer[i] != 0) return false;
  }
  return true;
}

int varSliceSize(Uint8List someScript) {
  final length = someScript.length;
  return varuint.encodingLength(length) + length;
}
