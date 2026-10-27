import 'dart:typed_data';

/// Pure Dart implementation of MD4 (RFC 1320).
///
/// Used for computing the NT password hash (MD4 of UTF-16LE password bytes)
/// in NTLM / NTLMSSP authentication.
class Md4 {
  static const int _mask32 = 0xFFFFFFFF;

  static Uint8List digest(Uint8List data) {
    var a = 0x67452301;
    var b = 0xEFCDAB89;
    var c = 0x98BADCFE;
    var d = 0x10325476;

    final length = data.length;
    final bitLength = length * 8;
    final mod = length % 64;
    final paddingLength = (mod < 56) ? (56 - mod) : (120 - mod);
    final totalLength = length + paddingLength + 8;

    final buffer = Uint8List(totalLength);
    buffer.setRange(0, length, data);
    buffer[length] = 0x80;

    // 64-bit length in bits (little endian)
    final bd = ByteData.sublistView(buffer);
    bd.setUint32(totalLength - 8, bitLength & _mask32, Endian.little);
    bd.setUint32(
      totalLength - 4,
      (bitLength ~/ 0x100000000) & _mask32,
      Endian.little,
    );

    for (var i = 0; i < totalLength; i += 64) {
      final x = List<int>.generate(
        16,
        (j) => bd.getUint32(i + (j * 4), Endian.little),
      );

      final aa = a;
      final bb = b;
      final cc = c;
      final dd = d;

      // Round 1
      a = _rol1((a + _f(b, c, d) + x[0]) & _mask32, 3);
      d = _rol1((d + _f(a, b, c) + x[1]) & _mask32, 7);
      c = _rol1((c + _f(d, a, b) + x[2]) & _mask32, 11);
      b = _rol1((b + _f(c, d, a) + x[3]) & _mask32, 19);

      a = _rol1((a + _f(b, c, d) + x[4]) & _mask32, 3);
      d = _rol1((d + _f(a, b, c) + x[5]) & _mask32, 7);
      c = _rol1((c + _f(d, a, b) + x[6]) & _mask32, 11);
      b = _rol1((b + _f(c, d, a) + x[7]) & _mask32, 19);

      a = _rol1((a + _f(b, c, d) + x[8]) & _mask32, 3);
      d = _rol1((d + _f(a, b, c) + x[9]) & _mask32, 7);
      c = _rol1((c + _f(d, a, b) + x[10]) & _mask32, 11);
      b = _rol1((b + _f(c, d, a) + x[11]) & _mask32, 19);

      a = _rol1((a + _f(b, c, d) + x[12]) & _mask32, 3);
      d = _rol1((d + _f(a, b, c) + x[13]) & _mask32, 7);
      c = _rol1((c + _f(d, a, b) + x[14]) & _mask32, 11);
      b = _rol1((b + _f(c, d, a) + x[15]) & _mask32, 19);

      // Round 2
      a = _rol1((a + _g(b, c, d) + x[0] + 0x5A827999) & _mask32, 3);
      d = _rol1((d + _g(a, b, c) + x[4] + 0x5A827999) & _mask32, 5);
      c = _rol1((c + _g(d, a, b) + x[8] + 0x5A827999) & _mask32, 9);
      b = _rol1((b + _g(c, d, a) + x[12] + 0x5A827999) & _mask32, 13);

      a = _rol1((a + _g(b, c, d) + x[1] + 0x5A827999) & _mask32, 3);
      d = _rol1((d + _g(a, b, c) + x[5] + 0x5A827999) & _mask32, 5);
      c = _rol1((c + _g(d, a, b) + x[9] + 0x5A827999) & _mask32, 9);
      b = _rol1((b + _g(c, d, a) + x[13] + 0x5A827999) & _mask32, 13);

      a = _rol1((a + _g(b, c, d) + x[2] + 0x5A827999) & _mask32, 3);
      d = _rol1((d + _g(a, b, c) + x[6] + 0x5A827999) & _mask32, 5);
      c = _rol1((c + _g(d, a, b) + x[10] + 0x5A827999) & _mask32, 9);
      b = _rol1((b + _g(c, d, a) + x[14] + 0x5A827999) & _mask32, 13);

      a = _rol1((a + _g(b, c, d) + x[3] + 0x5A827999) & _mask32, 3);
      d = _rol1((d + _g(a, b, c) + x[7] + 0x5A827999) & _mask32, 5);
      c = _rol1((c + _g(d, a, b) + x[11] + 0x5A827999) & _mask32, 9);
      b = _rol1((b + _g(c, d, a) + x[15] + 0x5A827999) & _mask32, 13);

      // Round 3
      a = _rol1((a + _h(b, c, d) + x[0] + 0x6ED9EBA1) & _mask32, 3);
      d = _rol1((d + _h(a, b, c) + x[8] + 0x6ED9EBA1) & _mask32, 9);
      c = _rol1((c + _h(d, a, b) + x[4] + 0x6ED9EBA1) & _mask32, 11);
      b = _rol1((b + _h(c, d, a) + x[12] + 0x6ED9EBA1) & _mask32, 15);

      a = _rol1((a + _h(b, c, d) + x[2] + 0x6ED9EBA1) & _mask32, 3);
      d = _rol1((d + _h(a, b, c) + x[10] + 0x6ED9EBA1) & _mask32, 9);
      c = _rol1((c + _h(d, a, b) + x[6] + 0x6ED9EBA1) & _mask32, 11);
      b = _rol1((b + _h(c, d, a) + x[14] + 0x6ED9EBA1) & _mask32, 15);

      a = _rol1((a + _h(b, c, d) + x[1] + 0x6ED9EBA1) & _mask32, 3);
      d = _rol1((d + _h(a, b, c) + x[9] + 0x6ED9EBA1) & _mask32, 9);
      c = _rol1((c + _h(d, a, b) + x[5] + 0x6ED9EBA1) & _mask32, 11);
      b = _rol1((b + _h(c, d, a) + x[13] + 0x6ED9EBA1) & _mask32, 15);

      a = _rol1((a + _h(b, c, d) + x[3] + 0x6ED9EBA1) & _mask32, 3);
      d = _rol1((d + _h(a, b, c) + x[11] + 0x6ED9EBA1) & _mask32, 9);
      c = _rol1((c + _h(d, a, b) + x[7] + 0x6ED9EBA1) & _mask32, 11);
      b = _rol1((b + _h(c, d, a) + x[15] + 0x6ED9EBA1) & _mask32, 15);

      a = (a + aa) & _mask32;
      b = (b + bb) & _mask32;
      c = (c + cc) & _mask32;
      d = (d + dd) & _mask32;
    }

    final out = Uint8List(16);
    final outBd = ByteData.sublistView(out);
    outBd.setUint32(0, a, Endian.little);
    outBd.setUint32(4, b, Endian.little);
    outBd.setUint32(8, c, Endian.little);
    outBd.setUint32(12, d, Endian.little);
    return out;
  }

  static int _f(int x, int y, int z) => (x & y) | (~x & z);
  static int _g(int x, int y, int z) => (x & y) | (x & z) | (y & z);
  static int _h(int x, int y, int z) => x ^ y ^ z;

  static int _rol1(int value, int bits) =>
      ((value << bits) | (value >>> (32 - bits))) & _mask32;
}
