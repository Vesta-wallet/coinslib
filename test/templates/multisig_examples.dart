const String validSig =
    "3045022100a7cf5c28088647557b1b9eea8366d72a9a89ef380ec1c9f00e75a8458a33d6ca0220265a0174092fdcf5f00749463876d34302c64f590e43af7b59cdec7dea9ba2a201";

// Mutate second byte slightly (invalid sig length)
const String invalidSig =
    "3046022100a7cf5c28088647557b1b9eea8366d72a9a89ef380ec1c9f00e75a8458a33d6ca0220265a0174092fdcf5f00749463876d34302c64f590e43af7b59cdec7dea9ba2a201";

const String validPubkeyPush =
    "2102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4";

// OP_1 pk OP_1 OP_CHECKMULTISIG
const String validOneOfOneScript = "51${validPubkeyPush}51AE";

// OP_2 pk1 pk2 OP_2 OP_CHECKMULTISIG
const String validTwoOfTwoScript = "52$validPubkeyPush${validPubkeyPush}52AE";
