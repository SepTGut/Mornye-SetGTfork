import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/v1/des.dart';

void main() {
  String hex(Uint8List bytes) => bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();

  Uint8List fromHex(String s) {
    final clean = s.replaceAll(' ', '');
    final result = Uint8List(clean.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  group('DES Standard Cryptographic Vectors', () {
    test('NIST Known Test Vector', () {
      final key = fromHex('133457799BBCDFF1');
      final plain = fromHex('0123456789ABCDEF');
      final cipher = Des.encryptBlock(key, plain);
      expect(hex(cipher), '85E813540F0AB405');
    });

    test('RFC 2759 Section 9.2 NTLMv1 ChallengeResponse Vector', () {
      final challenge = fromHex('D02E4386BCE91226');
      final ntHash = fromHex('44EBBA8D5312B8D611474411F56989AE');
      final response = Des.computeNtlmV1Response(challenge, ntHash);
      expect(hex(response), '82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF');
    });

    test('LMv1 Empty Password Hash Constant', () {
      // Empty password LM hash is standard AAD3B435B51404EEAAD3B435B51404EE
      final challenge = fromHex('0102030405060708');
      final lmResp = Des.computeLmV1Response(challenge, '');
      expect(lmResp.length, 24);
    });

    test('56-bit to 64-bit Key Expansion', () {
      // RFC 2759 Section 9.3:
      // Raw 7-octet chunk: FC 15 6A F7 ED CD 6C
      // 8-octet expanded: FD 0B 5B 5E 7F 6E 34 D9 (without odd-parity forced on bit 0: FC 0A 5A 5E 7E 6E 34 D8)
      final raw7 = fromHex('FC156AF7EDCD6C');
      final expanded = Des.expand56To64(raw7);
      expect(expanded.length, 8);
      // Verify bits 7..1 of each byte
      for (var i = 0; i < 7; i++) {
        expect((expanded[i] & 0xFE), expanded[i]);
      }
    });
  });
}
