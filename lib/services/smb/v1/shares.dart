import 'dart:convert';
import 'dart:typed_data';

import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/status.dart';

class Smb1Shares {
  static const int stypeDiskTree = 0x0000;

  static Smb1Packet createNetShareEnumRequest({
    required int tid,
    required int uid,
  }) {
    const pipeName = '\\PIPE\\LANMAN\x00';
    const paramDesc = 'WrLeh\x00';
    const dataDesc = 'B13BWz\x00';

    final paramBuilder = BytesBuilder(copy: false);
    // MS-RAP 2.5.5.2: FunctionCode is USHORT (2 bytes) = 0x0000
    final pHeader = Uint8List(2);
    final pHBd = ByteData.sublistView(pHeader);
    pHBd.setUint16(0, 0, Endian.little); // NetShareEnum (function 0)
    paramBuilder.add(pHeader);
    paramBuilder.add(ascii.encode(paramDesc));
    paramBuilder.add(ascii.encode(dataDesc));

    final pFooter = Uint8List(4);
    final pFBd = ByteData.sublistView(pFooter);
    pFBd.setUint16(0, 1, Endian.little); // Detail level 1
    pFBd.setUint16(2, 65535, Endian.little); // Return buffer size
    paramBuilder.add(pFooter);

    final paramBytes = paramBuilder.takeBytes();
    final pipeBytes = ascii.encode(pipeName);

    // Header (32) + WordCount (1) + 14 words (28) + ByteCount (2) = 63.
    // pipeBytes length = 13.
    // 63 + 13 = 76 (even).
    const paramOffset = 76;
    // MS-CIFS 2.2.4.33.1: WordCount = 14 words (SetupCount = 0)
    final words = [
      paramBytes.length, // 0: TotalParameterCount
      0, // 1: TotalDataCount
      10, // 2: MaxParameterCount
      65535, // 3: MaxDataCount
      0, // 4: MaxSetupCount (low) | Reserved1 (high)
      0, // 5: Flags
      0, 0, // 6, 7: Timeout (ULONG: 2 words)
      0, // 8: Reserved2
      paramBytes.length, // 9: ParameterCount
      paramOffset, // 10: ParameterOffset
      0, // 11: DataCount
      paramOffset + paramBytes.length, // 12: DataOffset
      0, // 13: SetupCount (0) | Reserved3 (0)
    ];

    final bytes = Uint8List(pipeBytes.length + paramBytes.length);
    bytes.setRange(0, pipeBytes.length, pipeBytes);
    bytes.setRange(pipeBytes.length, bytes.length, paramBytes);

    return Smb1Packet(
      command: Smb1Packet.cmdTransaction,
      tid: tid,
      uid: uid,
      flags2: Smb1Packet.flag2NtStatus,
      words: words,
      bytes: bytes,
    );
  }

  static List<SmbShare> parseNetShareEnumResponse(Smb1Packet packet) {
    if (packet.status != NtStatus.success) {
      throw SmbException(
        'Share enumeration failed: ${NtStatus.describe(packet.status)}',
        NtStatus.toSmbErrorType(packet.status),
      );
    }
    if (packet.words.length < 10) return [];

    final raw = packet.raw ?? packet.encode();
    // MS-CIFS 2.2.4.33.2: words[3]=ParamCount, words[4]=ParamOffset, words[6]=DataCount, words[7]=DataOffset
    final paramCount = packet.words[3];
    final paramOffset = packet.words[4];
    final dataCount = packet.words[6];
    final dataOffset = packet.words[7];

    var entryCount = 0;
    if (paramCount >= 8 && paramOffset + 8 <= raw.length) {
      final pBd = ByteData.sublistView(raw, paramOffset, paramOffset + paramCount);
      entryCount = pBd.getUint16(4, Endian.little);
    }

    final shares = <SmbShare>[];
    if (dataCount >= 20 && dataOffset + dataCount <= raw.length) {
      for (var i = 0; i < entryCount; i++) {
        final offset = dataOffset + (i * 20);
        if (offset + 20 > raw.length) break;

        final d = ByteData.sublistView(raw, offset, offset + 20);
        final nameBytes = raw.sublist(offset, offset + 13);
        final nullIdx = nameBytes.indexOf(0);
        final cleanBytes = (nullIdx >= 0) ? nameBytes.sublist(0, nullIdx) : nameBytes;
        final name = ascii.decode(cleanBytes, allowInvalid: true).trim();

        final shareType = d.getUint16(14, Endian.little);
        final isDisk = shareType == stypeDiskTree;

        if (name.isNotEmpty && !name.endsWith('\$')) {
          shares.add(SmbShare(name: name, isDisk: isDisk));
        }
      }
    }
    return shares;
  }
}
