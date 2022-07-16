import '../utils/ecurve.dart' show isPoint;
import '../models/networks.dart';
import '../payments/index.dart' show PaymentData;
import '../utils/constants/op.dart';

class P2PK {
  PaymentData data;
  NetworkType network;

  P2PK({required this.data, NetworkType? network})
      : network = network ?? bitcoin {
    _init();
  }

  _init() {
    final output = data.output;
    if (output != null) {
      if (output[output.length - 1] != ops['OP_CHECKSIG']) {
        throw ArgumentError('Output is invalid');
      }
      if (!isPoint(output.sublist(1, -1))) {
        throw ArgumentError('Output pubkey is invalid');
      }
    }
    if (data.input != null) {
      // TODO
    }
  }
}
