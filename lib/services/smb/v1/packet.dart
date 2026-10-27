import 'dart:typed_data';

import 'package:mornye/services/smb/smb_client.dart';

/// SMB1 packet structure (header + parameter words + data bytes).
class Smb1Packet {
  Smb1Packet({
    required this.command,
    this.status = 0,
    this.flags = flagCaseInsensitive | flagCanonicalizedPaths,
    this.flags2 = flag2Unicode | flag2NtStatus,
    this.pidHigh = 0,
    Uint8List? securityFeatures,
    this.reserved = 0,
    this.tid = 0,
    this.pidLow = 0xFEFF,
    this.uid = 0,
    this.mid = 0,
    List<int>? words,
    Uint8List? bytes,
    this.raw,
  })  : securityFeatures = securityFeatures ?? Uint8List(8),
        words = words != null ? Uint16List.fromList(words) : Uint16List(0),
        bytes = bytes ?? Uint8List(0);

  final Uint8List? raw;

  // Flags
  static const int flagCaseInsensitive = 0x08;
  static const int flagCanonicalizedPaths = 0x10;
  static const int flagReply = 0x80;

  // Flags2
  static const int flag2Unicode = 0x0001;
  static const int flag2NtStatus = 0x0040;
  static const int flag2SecuritySignature = 0x0004;
  static const int flag2ExtendedSecurity = 0x0800;
  static const int flag2LongNames = 0x0001;

  // Commands
  static const int cmdCreateDirectory = 0x00;
  static const int cmdClose = 0x04;
  static const int cmdFlush = 0x05;
  static const int cmdDelete = 0x06;
  static const int cmdRename = 0x07;
  static const int cmdTransaction = 0x25;
  static const int cmdReadAndX = 0x2E;
  static const int cmdWriteAndX = 0x2F;
  static const int cmdTransaction2 = 0x32;
  static const int cmdTransaction2Secondary = 0x33;
  static const int cmdTreeDisconnect = 0x71;
  static const int cmdNegotiate = 0x72;
  static const int cmdSessionSetupAndX = 0x73;
  static const int cmdLogoffAndX = 0x74;
  static const int cmdTreeConnectAndX = 0x75;
  static const int cmdNtCreateAndX = 0xA2;

  final int command;
  int status;
  int flags;
  int flags2;
  int pidHigh;
  Uint8List securityFeatures;
  int reserved;
  int tid;
  int pidLow;
  int uid;
  int mid;
  final Uint16List words;
  final Uint8List bytes;

  Uint8List encode() {
    final totalLen = 32 + 1 + (words.length * 2) + 2 + bytes.length;
    final out = Uint8List(totalLen);
    final bd = ByteData.sublistView(out);

    out[0] = 0xFF;
    out[1] = 0x53; // 'S'
    out[2] = 0x4D; // 'M'
    out[3] = 0x42; // 'B'
    out[4] = command;
    bd.setUint32(5, status, Endian.little);
    out[9] = flags;
    bd.setUint16(10, flags2, Endian.little);
    bd.setUint16(12, pidHigh, Endian.little);
    out.setRange(14, 22, securityFeatures);
    bd.setUint16(22, reserved, Endian.little);
    bd.setUint16(24, tid, Endian.little);
    bd.setUint16(26, pidLow, Endian.little);
    bd.setUint16(28, uid, Endian.little);
    bd.setUint16(30, mid, Endian.little);

    out[32] = words.length;
    for (var i = 0; i < words.length; i++) {
      bd.setUint16(33 + (i * 2), words[i], Endian.little);
    }
    final byteCountOffset = 33 + (words.length * 2);
    bd.setUint16(byteCountOffset, bytes.length, Endian.little);
    out.setRange(byteCountOffset + 2, totalLen, bytes);
    return out;
  }

  factory Smb1Packet.decode(Uint8List raw) {
    if (raw.length < 32) {
      throw const SmbException(
        'Packet too short',
        SmbErrorType.incompatible,
      );
    }
    if (raw[0] != 0xFF || raw[1] != 0x53 || raw[2] != 0x4D || raw[3] != 0x42) {
      throw const SmbException(
        'Invalid SMB1 magic header',
        SmbErrorType.incompatible,
      );
    }
    final bd = ByteData.sublistView(raw);
    final command = raw[4];
    final status = bd.getUint32(5, Endian.little);
    final flags = raw[9];
    final flags2 = bd.getUint16(10, Endian.little);
    final pidHigh = bd.getUint16(12, Endian.little);
    final securityFeatures = Uint8List.fromList(raw.sublist(14, 22));
    final reserved = bd.getUint16(22, Endian.little);
    final tid = bd.getUint16(24, Endian.little);
    final pidLow = bd.getUint16(26, Endian.little);
    final uid = bd.getUint16(28, Endian.little);
    final mid = bd.getUint16(30, Endian.little);

    if (raw.length == 32) {
      return Smb1Packet(
        command: command,
        status: status,
        flags: flags,
        flags2: flags2,
        pidHigh: pidHigh,
        securityFeatures: securityFeatures,
        reserved: reserved,
        tid: tid,
        pidLow: pidLow,
        uid: uid,
        mid: mid,
        raw: raw,
      );
    }

    final wordCount = raw[32];
    if (wordCount == 0 && raw.length <= 34) {
      return Smb1Packet(
        command: command,
        status: status,
        flags: flags,
        flags2: flags2,
        pidHigh: pidHigh,
        securityFeatures: securityFeatures,
        reserved: reserved,
        tid: tid,
        pidLow: pidLow,
        uid: uid,
        mid: mid,
        raw: raw,
      );
    }

    final wordsOffset = 33;
    final wordsEnd = wordsOffset + (wordCount * 2);
    if (raw.length < wordsEnd + 2) {
      throw const SmbException(
        'Malformed SMB1 packet parameter words',
        SmbErrorType.incompatible,
      );
    }
    final words = Uint16List(wordCount);
    for (var i = 0; i < wordCount; i++) {
      words[i] = bd.getUint16(wordsOffset + (i * 2), Endian.little);
    }
    final byteCount = bd.getUint16(wordsEnd, Endian.little);
    final bytesOffset = wordsEnd + 2;
    final bytes = (raw.length >= bytesOffset + byteCount)
        ? Uint8List.sublistView(raw, bytesOffset, bytesOffset + byteCount)
        : Uint8List.sublistView(raw, bytesOffset);

    return Smb1Packet(
      command: command,
      status: status,
      flags: flags,
      flags2: flags2,
      pidHigh: pidHigh,
      securityFeatures: securityFeatures,
      reserved: reserved,
      tid: tid,
      pidLow: pidLow,
      uid: uid,
      mid: mid,
      words: words,
      bytes: bytes,
      raw: raw,
    );
  }
}
