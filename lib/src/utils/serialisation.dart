import 'dart:typed_data';
import 'varuint.dart' as varuint;

class BytesReaderWriter {

  int offset;
  final ByteData bytes;

  BytesReaderWriter(Uint8List bytes, [this.offset = 0]) : bytes = bytes.buffer.asByteData();

  int readUInt8() => bytes.getUint8(offset++);

  int readUInt32() {
    final i = bytes.getUint32(offset, Endian.little);
    offset += 4;
    return i;
  }

  int readInt32() {
    final i = bytes.getInt32(offset, Endian.little);
    offset += 4;
    return i;
  }

  int readUInt64() {
    final i = bytes.getUint64(offset, Endian.little);
    offset += 8;
    return i;
  }

  Uint8List readSlice(int n) {
    offset += n;
    return Uint8List.fromList(bytes.buffer.asUint8List(offset-n, n));
  }

  int readVarInt() {
    final vi = varuint.decode(bytes.buffer.asUint8List(), offset);
    offset += varuint.encodingLength(vi);
    return vi;
  }

  Uint8List readVarSlice() {
    return readSlice(readVarInt());
  }

  List<Uint8List> readVector() {
    var count = readVarInt();
    List<Uint8List> vector = [];
    for (var i = 0; i < count; ++i) {
      vector.add(readVarSlice());
    }
    return vector;
  }

  writeUInt8(int i) {
    bytes.setUint8(offset, i);
    offset++;
  }

  writeUInt32(int i) {
    bytes.setUint32(offset, i, Endian.little);
    offset += 4;
  }

  writeInt32(int i) {
    bytes.setInt32(offset, i, Endian.little);
    offset += 4;
  }

  writeUInt64(int i) {
    bytes.setUint64(offset, i, Endian.little);
    offset += 8;
  }

  writeSlice(List<int> slice) {
    bytes.buffer.asUint8List().setAll(offset, slice);
    offset += slice.length;
  }

  writeVarInt(int i) {
    varuint.encode(i, bytes.buffer.asUint8List(), offset);
    offset += varuint.encodingLength(i);
  }

  writeVarSlice(Uint8List slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }

  writeVector(List<Uint8List> vector) {
    writeVarInt(vector.length);
    for (final bytes in vector) {
      writeVarSlice(bytes);
    }
  }

  bool get atEnd => offset == bytes.lengthInBytes;

}

