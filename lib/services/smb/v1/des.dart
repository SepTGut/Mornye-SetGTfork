import 'dart:typed_data';


/// Pure-Dart implementation of DES (FIPS 46-3) and NTLMv1 / LMv1 challenge response.
class Des {
  Des._();

  static const List<int> _ip = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
  ];

  static const List<int> _fp = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
  ];

  static const List<int> _pc1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
  ];

  static const List<int> _pc2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
  ];

  static const List<int> _shifts = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
  ];

  static const List<int> _e = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
  ];

  static const List<List<int>> _sBoxes = [
    [
      14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
      15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
      10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
      7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
      2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
      12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
      4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
      13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
  ];

  static const List<int> _p = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
  ];

  static Uint8List _permuteBytes(Uint8List inBytes, List<int> table) {
    final outLen = (table.length + 7) >> 3;
    final out = Uint8List(outLen);
    for (var i = 0; i < table.length; i++) {
      final p = table[i];
      final byteIdx = (p - 1) >> 3;
      final bitIdx = 7 - ((p - 1) & 7);
      final bit = (inBytes[byteIdx] >> bitIdx) & 1;
      out[i >> 3] |= (bit << (7 - (i & 7)));
    }
    return out;
  }

  /// Encrypts an 8-byte block using a 64-bit DES key (8 bytes).
  static Uint8List encryptBlock(Uint8List key8, Uint8List block8) {
    if (key8.length != 8 || block8.length != 8) {
      throw ArgumentError('Key and block must be exactly 8 bytes');
    }

    // Key schedule: PC-1 permutation yields 56 bits (7 bytes)
    final key56 = _permuteBytes(key8, _pc1);
    final kBd = ByteData.sublistView(key56);
    // Upper 28 bits: C, Lower 28 bits: D
    // key56 has 7 bytes: kBd.getUint32(0) has top 32 bits, next 3 bytes has remaining 24 bits
    final top32 = kBd.getUint32(0, Endian.big);
    final bot24 = (key56[4] << 16) | (key56[5] << 8) | key56[6];

    var c = (top32 >> 4) & 0x0FFFFFFF;
    var d = ((top32 & 0x0F) << 24) | bot24;

    final subkeys = <Uint8List>[];
    for (final shift in _shifts) {
      c = (((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF);
      d = (((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF);

      // Pack (C << 28) | D into 7 bytes
      final cdBytes = Uint8List(7);
      cdBytes[0] = (c >> 20) & 0xFF;
      cdBytes[1] = (c >> 12) & 0xFF;
      cdBytes[2] = (c >> 4) & 0xFF;
      cdBytes[3] = ((c & 0x0F) << 4) | ((d >> 24) & 0x0F);
      cdBytes[4] = (d >> 16) & 0xFF;
      cdBytes[5] = (d >> 8) & 0xFF;
      cdBytes[6] = d & 0xFF;

      subkeys.add(_permuteBytes(cdBytes, _pc2)); // 48 bits (6 bytes)
    }

    // Initial permutation
    final blockIp = _permuteBytes(block8, _ip);
    final blkBd = ByteData.sublistView(blockIp);
    var l = blkBd.getUint32(0, Endian.big);
    var r = blkBd.getUint32(4, Endian.big);

    final rBytes = Uint8List(4);
    final rBd = ByteData.sublistView(rBytes);
    final pBytes = Uint8List(4);
    final pBd = ByteData.sublistView(pBytes);

    for (final subkey in subkeys) {
      rBd.setUint32(0, r, Endian.big);
      final er = _permuteBytes(rBytes, _e); // 48 bits (6 bytes)

      var sOut = 0;
      for (var i = 0; i < 8; i++) {
        // bit offset in 48 bits: i * 6
        final bitOffset = i * 6;
        final byteIdx = bitOffset >> 3;
        final shiftInByte = bitOffset & 7;

        int chunk;
        if (shiftInByte <= 2) {
          chunk = (er[byteIdx] ^ subkey[byteIdx]) >> (2 - shiftInByte);
        } else {
          final top = ((er[byteIdx] ^ subkey[byteIdx]) << (shiftInByte - 2)) & 0x3F;
          final bot = (er[byteIdx + 1] ^ subkey[byteIdx + 1]) >> (10 - shiftInByte);
          chunk = top | bot;
        }
        chunk &= 0x3F;

        final row = (((chunk >> 5) & 1) << 1) | (chunk & 1);
        final col = (chunk >> 1) & 0x0F;
        final val = _sBoxes[i][(row * 16) + col];
        sOut = (sOut << 4) | val;
      }

      pBd.setUint32(0, sOut, Endian.big);
      final pOut = ByteData.sublistView(_permuteBytes(pBytes, _p)).getUint32(0, Endian.big);

      final nextR = (l ^ pOut) & 0xFFFFFFFF;
      l = r;
      r = nextR;
    }

    // Pre-output (R16, L16)
    final pre = Uint8List(8);
    final preBd = ByteData.sublistView(pre);
    preBd.setUint32(0, r, Endian.big);
    preBd.setUint32(4, l, Endian.big);

    return _permuteBytes(pre, _fp);
  }

  /// Expands a 7-byte (56-bit) key chunk into an 8-byte DES key with parity bits.
  static Uint8List expand56To64(Uint8List k7) {
    if (k7.length != 7) {
      throw ArgumentError('Input must be 7 bytes');
    }
    final k8 = Uint8List(8);
    k8[0] = k7[0] & 0xFE;
    k8[1] = (((k7[0] << 7) | (k7[1] >> 1)) & 0xFE);
    k8[2] = (((k7[1] << 6) | (k7[2] >> 2)) & 0xFE);
    k8[3] = (((k7[2] << 5) | (k7[3] >> 3)) & 0xFE);
    k8[4] = (((k7[3] << 4) | (k7[4] >> 4)) & 0xFE);
    k8[5] = (((k7[4] << 3) | (k7[5] >> 5)) & 0xFE);
    k8[6] = (((k7[5] << 2) | (k7[6] >> 6)) & 0xFE);
    k8[7] = ((k7[6] << 1) & 0xFE);
    return k8;
  }

  /// Computes the 24-byte NTLMv1 challenge response from an 8-byte server challenge
  /// and a 16-byte MD4 NT password hash (RFC 2759 Section 8.5).
  static Uint8List computeNtlmV1Response(
    Uint8List serverChallenge,
    Uint8List ntHash,
  ) {
    if (serverChallenge.length != 8) {
      throw ArgumentError('Server challenge must be 8 bytes');
    }
    if (ntHash.length != 16) {
      throw ArgumentError('NT hash must be 16 bytes');
    }

    final p21 = Uint8List(21);
    p21.setRange(0, 16, ntHash);

    final out = Uint8List(24);
    for (var i = 0; i < 3; i++) {
      final k7 = Uint8List.sublistView(p21, i * 7, (i + 1) * 7);
      final k8 = expand56To64(k7);
      final cipher = encryptBlock(k8, serverChallenge);
      out.setRange(i * 8, (i + 1) * 8, cipher);
    }
    return out;
  }

  /// Computes the 24-byte LMv1 challenge response from an 8-byte server challenge
  /// and a user password.
  static Uint8List computeLmV1Response(
    Uint8List serverChallenge,
    String password,
  ) {
    if (serverChallenge.length != 8) {
      throw ArgumentError('Server challenge must be 8 bytes');
    }

    // Convert password to uppercase OEM/ASCII, pad or truncate to 14 bytes
    final upper = password.toUpperCase();
    final p14 = Uint8List(14);
    for (var i = 0; i < upper.length && i < 14; i++) {
      p14[i] = upper.codeUnitAt(i) & 0x7F;
    }

    final magic = Uint8List.fromList([
      0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25, // 'KGS!@#$%'
    ]);

    final k1 = expand56To64(Uint8List.sublistView(p14, 0, 7));
    final k2 = expand56To64(Uint8List.sublistView(p14, 7, 14));

    final lmHash = Uint8List(21);
    lmHash.setRange(0, 8, encryptBlock(k1, magic));
    lmHash.setRange(8, 16, encryptBlock(k2, magic));

    final out = Uint8List(24);
    for (var i = 0; i < 3; i++) {
      final k7 = Uint8List.sublistView(lmHash, i * 7, (i + 1) * 7);
      final k8 = expand56To64(k7);
      final cipher = encryptBlock(k8, serverChallenge);
      out.setRange(i * 8, (i + 1) * 8, cipher);
    }
    return out;
  }
}
