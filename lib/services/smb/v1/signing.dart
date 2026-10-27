import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:mornye/services/smb/smb_client.dart';

/// Implements SMB1 MD5 MAC signing and sequence verification (MS-SMB §3.1.5.1).
class Smb1Signer {
  Smb1Signer({
    required this.macKey,
    this.sequenceNumber = 2,
    this.required = false,
  });

  final Uint8List macKey;
  int sequenceNumber;
  final bool required;

  void sign(Uint8List packetBytes) {
    if (packetBytes.length < 32) return;

    // Ensure SMB_FLAGS2_SMB_SECURITY_SIGNATURE (0x0004) is set in Flags2 (bytes 10..11)
    final bd = ByteData.sublistView(packetBytes);
    final flags2 = bd.getUint16(10, Endian.little);
    bd.setUint16(10, flags2 | 0x0004, Endian.little);

    // Set sequence number at bytes 14..17 (LE), zero bytes 18..21
    bd.setUint32(14, sequenceNumber, Endian.little);
    bd.setUint32(18, 0, Endian.little);

    // Compute MD5(macKey + packetBytes)
    final buffer = Uint8List(macKey.length + packetBytes.length);
    buffer.setRange(0, macKey.length, macKey);
    buffer.setRange(macKey.length, buffer.length, packetBytes);

    final hash = md5.convert(buffer).bytes;
    // Signature is first 8 bytes of MD5 digest
    packetBytes.setRange(14, 22, hash.sublist(0, 8));

    // Next expected reply will be at sequenceNumber + 1
  }

  bool verify(Uint8List packetBytes) {
    if (packetBytes.length < 32) return false;

    // Save received signature (bytes 14..21)
    final receivedSig = Uint8List.fromList(packetBytes.sublist(14, 22));

    // Put reply sequence number in bytes 14..17, zero bytes 18..21
    final bd = ByteData.sublistView(packetBytes);
    bd.setUint32(14, sequenceNumber + 1, Endian.little);
    bd.setUint32(18, 0, Endian.little);

    final buffer = Uint8List(macKey.length + packetBytes.length);
    buffer.setRange(0, macKey.length, macKey);
    buffer.setRange(macKey.length, buffer.length, packetBytes);

    final computedSig = md5.convert(buffer).bytes.sublist(0, 8);

    var valid = true;
    for (var i = 0; i < 8; i++) {
      if (receivedSig[i] != computedSig[i]) {
        valid = false;
        break;
      }
    }

    // Sequence advances by 2 for each request/response pair
    sequenceNumber += 2;

    if (!valid && required) {
      throw const SmbException(
        'SMB1 signature verification failed',
        SmbErrorType.accessDenied,
      );
    }
    return valid;
  }
}
