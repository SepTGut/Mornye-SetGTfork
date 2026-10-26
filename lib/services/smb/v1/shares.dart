import 'dart:convert';
import 'dart:typed_data';

import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/commands.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/status.dart';
import 'package:mornye/services/smb/v1/transport.dart';

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
    final pHeader = Uint8List(8);
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

    const paramOffset = 66 + pipeName.length;
    final words = [
      paramBytes.length, // TotalParameterCount
      0, // TotalDataCount
      10, // MaxParameterCount
      65535, // MaxDataCount
      0, // MaxSetupCount
      0, // Reserved
      0, // Flags
      0, 0, // Timeout
      0, // Reserved
      paramBytes.length, // ParameterCount
      paramOffset, // ParameterOffset
      0, // DataCount
      paramOffset + paramBytes.length, // DataOffset
      0, // SetupCount
    ];

    final bytes = Uint8List(pipeBytes.length + paramBytes.length);
    bytes.setRange(0, pipeBytes.length, pipeBytes);
    bytes.setRange(pipeBytes.length, bytes.length, paramBytes);

    return Smb1Packet(
      command: Smb1Packet.cmdTransaction,
      tid: tid,
      uid: uid,
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

    final raw = packet.encode();
    final paramOffset = packet.words[3];
    final paramCount = packet.words[4];
    final dataOffset = packet.words[7];
    final dataCount = packet.words[8];

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
