import 'dart:typed_data';

import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/des.dart';
import 'package:mornye/services/smb/v1/md4.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/status.dart';

class Smb1NegotiateResult {
  const Smb1NegotiateResult({
    required this.dialectIndex,
    required this.securityMode,
    required this.signingRequired,
    required this.signingEnabled,
    required this.extendedSecurity,
    required this.maxBufferSize,
    required this.securityBlob,
  });

  final int dialectIndex;
  final int securityMode;
  final bool signingRequired;
  final bool signingEnabled;
  final bool extendedSecurity;
  final int maxBufferSize;
  final Uint8List securityBlob;
}

class Smb1FileEntry {
  const Smb1FileEntry({
    required this.name,
    required this.isDirectory,
    required this.size,
    required this.modifiedTime,
  });

  final String name;
  final bool isDirectory;
  final int size;
  final int modifiedTime;
}

class Smb1Commands {
  static const int capUnicode = 0x00000004;
  static const int capLargeFiles = 0x00000008;
  static const int capNtSmbs = 0x00000010;
  static const int capStatus32 = 0x00000040;
  static const int capExtendedSecurity = 0x80000000;

  static const int trans2FindFirst2 = 0x0001;
  static const int trans2FindNext2 = 0x0002;
  static const int trans2QueryPathInfo = 0x0005;

  static Smb1Packet createNegotiateRequest() {
    // Offer strictly "NT LM 0.12"
    final dialect = Uint8List.fromList([0x02, ...'NT LM 0.12'.codeUnits, 0x00]);
    return Smb1Packet(
      command: Smb1Packet.cmdNegotiate,
      flags2: Smb1Packet.flag2Unicode |
          Smb1Packet.flag2NtStatus |
          Smb1Packet.flag2ExtendedSecurity,
      bytes: dialect,
    );
  }

  static Smb1NegotiateResult parseNegotiateResponse(Smb1Packet packet) {
    if (packet.status != NtStatus.success) {
      throw SmbException(
        'Negotiate failed: ${NtStatus.describe(packet.status)}',
        NtStatus.toSmbErrorType(packet.status),
      );
    }
    if (packet.words.length < 17) {
      throw const SmbException(
        'Server returned invalid SMB1 negotiate response',
        SmbErrorType.incompatible,
      );
    }

    final words = packet.words;
    final dialectIndex = words[0];
    if (dialectIndex == 0xFFFF) {
      throw const SmbException(
        'Server rejected NT LM 0.12 dialect',
        SmbErrorType.incompatible,
      );
    }

    final securityMode = words[1] & 0xFF;
    final userSecurity = (securityMode & 0x01) != 0;
    final encryptPasswords = (securityMode & 0x02) != 0;
    final signingEnabled = (securityMode & 0x04) != 0;
    final signingRequired = (securityMode & 0x08) != 0;

    if (!userSecurity) {
      throw const SmbException(
        'Share-level security is not supported. Use user-level authentication.',
        SmbErrorType.incompatible,
      );
    }
    if (!encryptPasswords) {
      throw const SmbException(
        'Server requested plaintext passwords, which is refused for security.',
        SmbErrorType.incompatible,
      );
    }

    final maxBufferSize = words[4] | (words[5] << 16);
    final capabilities = words[10] | (words[11] << 16);
    final extendedSecurity = (capabilities & capExtendedSecurity) != 0;

    Uint8List securityBlob = Uint8List(0);
    if (extendedSecurity) {
      // In extended security, bytes contain GUID (16 bytes) + SecurityBlob
      if (packet.bytes.length > 16) {
        securityBlob = Uint8List.sublistView(packet.bytes, 16);
      }
    } else {
      // Non-extended: bytes contain encryption challenge key (8 bytes) + domain string
      if (packet.bytes.isNotEmpty) {
        final challengeLen = packet.bytes.length >= 8 ? 8 : packet.bytes.length;
        securityBlob = Uint8List.sublistView(packet.bytes, 0, challengeLen);
      }
    }

    return Smb1NegotiateResult(
      dialectIndex: dialectIndex,
      securityMode: securityMode,
      signingRequired: signingRequired,
      signingEnabled: signingEnabled,
      extendedSecurity: extendedSecurity,
      maxBufferSize: maxBufferSize > 0 ? maxBufferSize : 65535,
      securityBlob: securityBlob,
    );
  }

  static Smb1Packet createSessionSetupRequest({
    required Uint8List securityBlob,
    int uid = 0,
    int maxBufferSize = 65535,
  }) {
    const caps = capUnicode |
        capLargeFiles |
        capNtSmbs |
        capStatus32 |
        capExtendedSecurity;

    final words = [
      0x00FF, // AndXCommand: 0xFF, AndXReserved: 0
      0x0000, // AndXOffset
      maxBufferSize & 0xFFFF,
      2, // MaxMpxCount
      1, // VcNumber
      0, // SessionKey low
      0, // SessionKey high
      securityBlob.length, // SecurityBlobLength
      0, // Reserved low
      0, // Reserved high
      caps & 0xFFFF, // Capabilities low
      (caps >> 16) & 0xFFFF, // Capabilities high
    ];

    final osBytes = _encodeUnicodeString('Dart');
    final lanmanBytes = _encodeUnicodeString('Mornye');
    final totalBytes = securityBlob.length + osBytes.length + lanmanBytes.length;
    final bytes = Uint8List(totalBytes);
    bytes.setRange(0, securityBlob.length, securityBlob);
    bytes.setRange(
      securityBlob.length,
      securityBlob.length + osBytes.length,
      osBytes,
    );
    bytes.setRange(
      securityBlob.length + osBytes.length,
      totalBytes,
      lanmanBytes,
    );

    return Smb1Packet(
      command: Smb1Packet.cmdSessionSetupAndX,
      uid: uid,
      words: words,
      bytes: bytes,
    );
  }

  /// Creates a standard SMB1 Session Setup AndX request (WordCount = 13) for servers
  /// without Extended Security (CAP_EXTENDED_SECURITY / NTLMSSP).
  static Smb1Packet createStandardSessionSetupRequest({
    required String username,
    required String password,
    required String domain,
    required Uint8List serverChallenge,
    int uid = 0,
    int maxBufferSize = 65535,
    bool unicode = true,
  }) {
    const caps = capUnicode |
        capLargeFiles |
        capNtSmbs |
        capStatus32;

    Uint8List ciPassword;
    Uint8List csPassword;

    if (username.isEmpty && password.isEmpty) {
      // Anonymous / Guest logon
      ciPassword = Uint8List(0);
      csPassword = Uint8List(0);
    } else {
      if (serverChallenge.length >= 8) {
        final challenge8 = Uint8List.sublistView(serverChallenge, 0, 8);
        ciPassword = Des.computeLmV1Response(challenge8, password);

        final pwUnits = password.codeUnits;
        final pwUtf16 = Uint8List(pwUnits.length * 2);
        final bd = ByteData.sublistView(pwUtf16);
        for (var i = 0; i < pwUnits.length; i++) {
          bd.setUint16(i * 2, pwUnits[i], Endian.little);
        }
        final ntHash = Md4.digest(pwUtf16);
        csPassword = Des.computeNtlmV1Response(challenge8, ntHash);
      } else {
        ciPassword = Uint8List(0);
        csPassword = Uint8List(0);
      }
    }

    final words = [
      0x00FF, // AndXCommand: 0xFF, AndXReserved: 0
      0x0000, // AndXOffset
      maxBufferSize & 0xFFFF,
      2, // MaxMpxCount
      1, // VcNumber
      0, // SessionKey low
      0, // SessionKey high
      ciPassword.length, // CaseInsensitivePasswordLength
      csPassword.length, // CaseSensitivePasswordLength
      0, // Reserved low
      0, // Reserved high
      caps & 0xFFFF, // Capabilities low
      (caps >> 16) & 0xFFFF, // Capabilities high
    ];

    final builder = BytesBuilder(copy: false);
    builder.add(ciPassword);
    builder.add(csPassword);

    // Padding for 2-byte alignment relative to SMB header
    // SMB header (32) + WordCount (1) + 13 words (26) + ByteCount (2) = 61
    final currentOffset = 61 + ciPassword.length + csPassword.length;
    if (unicode && (currentOffset % 2 != 0)) {
      builder.addByte(0x00);
    }

    if (unicode) {
      builder.add(_encodeUnicodeString(username));
      builder.add(_encodeUnicodeString(domain));
      builder.add(_encodeUnicodeString('Dart'));
      builder.add(_encodeUnicodeString('Mornye'));
    } else {
      builder.add(_encodeAsciiString(username));
      builder.add(_encodeAsciiString(domain));
      builder.add(_encodeAsciiString('Dart'));
      builder.add(_encodeAsciiString('Mornye'));
    }

    final bytes = builder.takeBytes();

    return Smb1Packet(
      command: Smb1Packet.cmdSessionSetupAndX,
      flags2: unicode
          ? (Smb1Packet.flag2Unicode | Smb1Packet.flag2NtStatus)
          : Smb1Packet.flag2NtStatus,
      uid: uid,
      words: words,
      bytes: bytes,
    );
  }

  static Smb1Packet createTreeConnectRequest({
    required String path,
    int uid = 0,
  }) {
    // path is e.g. \\HOST\SHARE
    final unicodePath = _encodeUnicodeString(path);
    final service = [
      ...'?????'.codeUnits,
      0x00,
    ]; // Any service (disk, print, IPC)

    final bytes = Uint8List(1 + unicodePath.length + service.length);
    bytes[0] = 0x00; // Null password byte
    bytes.setRange(1, 1 + unicodePath.length, unicodePath);
    bytes.setRange(1 + unicodePath.length, bytes.length, service);

    return Smb1Packet(
      command: Smb1Packet.cmdTreeConnectAndX,
      uid: uid,
      words: [
        0x00FF, // AndXCommand
        0x0000, // AndXOffset
        0x0008, // Flags: disconnect TID if required
        0x0001, // PasswordLength: 1
      ],
      bytes: bytes,
    );
  }

  static Smb1Packet createTreeDisconnectRequest({required int tid}) =>
      Smb1Packet(command: Smb1Packet.cmdTreeDisconnect, tid: tid);

  static Smb1Packet createLogoffRequest({required int uid}) =>
      Smb1Packet(
        command: Smb1Packet.cmdLogoffAndX,
        uid: uid,
        words: [0x00FF, 0x0000],
      );

  static Smb1Packet createNtCreateRequest({
    required String path,
    required int tid,
    required int uid,
    required bool write,
    int disposition = 1, // 1 = FILE_OPEN, 2 = FILE_CREATE, 5 = FILE_OVERWRITE_IF
    bool directory = false,
  }) {
    final cleanPath = path.replaceAll('/', '\\');
    final fullPath = cleanPath.startsWith('\\') ? cleanPath : '\\$cleanPath';
    final unicodePath = _encodeUnicodeString(fullPath);

    final desiredAccess = write ? 0x0012019F : 0x00120089;
    final createOptions = directory ? 0x00000001 : 0x00000040;

    final words = [
      0x00FF, // AndXCommand
      0x0000, // AndXOffset
      0x0000, // Reserved
      fullPath.length * 2, // NameLength in bytes
      0x0016, // Flags
      0x0000, // RootDirectoryFID low
      0x0000, // RootDirectoryFID high
      desiredAccess & 0xFFFF,
      (desiredAccess >> 16) & 0xFFFF,
      0, 0, 0, 0, // AllocationSize (8 bytes)
      0x0080, 0x0000, // FileAttributes: FILE_ATTRIBUTE_NORMAL
      0x0007, 0x0000, // ShareAccess: Read/Write/Delete
      disposition & 0xFFFF,
      (disposition >> 16) & 0xFFFF,
      createOptions & 0xFFFF,
      (createOptions >> 16) & 0xFFFF,
      0x0002, 0x0000, // SecurityFlags: Impersonation
      0x0000, // SecurityFlags
    ];

    return Smb1Packet(
      command: Smb1Packet.cmdNtCreateAndX,
      tid: tid,
      uid: uid,
      words: words,
      bytes: unicodePath,
    );
  }

  static Smb1Packet createReadRequest({
    required int fid,
    required int offset,
    required int length,
    required int tid,
    required int uid,
  }) {
    final words = [
      0x00FF, // AndXCommand
      0x0000, // AndXOffset
      fid,
      offset & 0xFFFF,
      (offset >> 16) & 0xFFFF,
      length & 0xFFFF,
      0, // MinCount
      0, // MaxCountHigh
      0, // Remaining
      (offset ~/ 0x100000000) & 0xFFFF,
      ((offset ~/ 0x100000000) >> 16) & 0xFFFF,
    ];

    return Smb1Packet(
      command: Smb1Packet.cmdReadAndX,
      tid: tid,
      uid: uid,
      words: words,
    );
  }

  static Smb1Packet createWriteRequest({
    required int fid,
    required int offset,
    required Uint8List data,
    required int tid,
    required int uid,
  }) {
    final words = [
      0x00FF, // AndXCommand
      0x0000, // AndXOffset
      fid,
      offset & 0xFFFF,
      (offset >> 16) & 0xFFFF,
      0, // Reserved
      0, // WriteMode
      0, // Remaining
      0, // DataLengthHigh
      data.length & 0xFFFF,
      0x003F, // DataOffset (header + words + byteCount)
      (offset ~/ 0x100000000) & 0xFFFF,
      ((offset ~/ 0x100000000) >> 16) & 0xFFFF,
    ];

    return Smb1Packet(
      command: Smb1Packet.cmdWriteAndX,
      tid: tid,
      uid: uid,
      words: words,
      bytes: data,
    );
  }

  static Smb1Packet createCloseRequest({
    required int fid,
    required int tid,
    required int uid,
  }) => Smb1Packet(
    command: Smb1Packet.cmdClose,
    tid: tid,
    uid: uid,
    words: [fid, 0, 0],
  );

  static Smb1Packet createFlushRequest({
    required int fid,
    required int tid,
    required int uid,
  }) => Smb1Packet(
    command: Smb1Packet.cmdFlush,
    tid: tid,
    uid: uid,
    words: [fid],
  );

  static Smb1Packet createDeleteRequest({
    required String path,
    required int tid,
    required int uid,
  }) {
    final cleanPath = path.replaceAll('/', '\\');
    final fullPath = cleanPath.startsWith('\\') ? cleanPath : '\\$cleanPath';
    final unicodePath = _encodeUnicodeString(fullPath);
    final bytes = Uint8List(1 + unicodePath.length);
    bytes[0] = 0x04; // BufferFormat: ASCII or Unicode string
    bytes.setRange(1, bytes.length, unicodePath);

    return Smb1Packet(
      command: Smb1Packet.cmdDelete,
      tid: tid,
      uid: uid,
      words: [0x0006], // SearchAttributes: Hidden | System
      bytes: bytes,
    );
  }

  static Smb1Packet createRenameRequest({
    required String from,
    required String to,
    required int tid,
    required int uid,
  }) {
    final fromPath = from.replaceAll('/', '\\');
    final toPath = to.replaceAll('/', '\\');
    final fromBytes = _encodeUnicodeString(
      fromPath.startsWith('\\') ? fromPath : '\\$fromPath',
    );
    final toBytes = _encodeUnicodeString(
      toPath.startsWith('\\') ? toPath : '\\$toPath',
    );

    final bytes = Uint8List(1 + fromBytes.length + 1 + toBytes.length);
    bytes[0] = 0x04;
    bytes.setRange(1, 1 + fromBytes.length, fromBytes);
    bytes[1 + fromBytes.length] = 0x04;
    bytes.setRange(2 + fromBytes.length, bytes.length, toBytes);

    return Smb1Packet(
      command: Smb1Packet.cmdRename,
      tid: tid,
      uid: uid,
      words: [0x0006], // SearchAttributes
      bytes: bytes,
    );
  }

  static Smb1Packet createCreateDirectoryRequest({
    required String path,
    required int tid,
    required int uid,
  }) {
    final cleanPath = path.replaceAll('/', '\\');
    final fullPath = cleanPath.startsWith('\\') ? cleanPath : '\\$cleanPath';
    final unicodePath = _encodeUnicodeString(fullPath);
    final bytes = Uint8List(1 + unicodePath.length);
    bytes[0] = 0x04;
    bytes.setRange(1, bytes.length, unicodePath);

    return Smb1Packet(
      command: Smb1Packet.cmdCreateDirectory,
      tid: tid,
      uid: uid,
      bytes: bytes,
    );
  }

  /// Create a TRANS2_FIND_FIRST2 request (SMB subcommand 0x0001)
  static Smb1Packet createFindFirst2Request({
    required String directoryPath,
    required int tid,
    required int uid,
  }) {
    final clean = directoryPath.replaceAll('/', '\\');
    final searchPattern = clean.isEmpty || clean == '\\'
        ? '\\*'
        : (clean.endsWith('\\') ? '$clean*' : '$clean\\*');
    final unicodePattern = _encodeUnicodeString(searchPattern);

    // Setup parameters for TRANS2_FIND_FIRST2
    final paramBytes = Uint8List(12 + unicodePattern.length);
    final pBd = ByteData.sublistView(paramBytes);
    pBd.setUint16(0, 0x0016, Endian.little); // SearchAttributes: Hidden | System | Directory
    pBd.setUint16(2, 256, Endian.little); // SearchCount
    pBd.setUint16(4, 0x0006, Endian.little); // Flags: CloseIfEOS | ResumeKeys
    pBd.setUint16(6, 0x0104, Endian.little); // InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
    pBd.setUint32(8, 0, Endian.little); // StorageType
    paramBytes.setRange(12, paramBytes.length, unicodePattern);

    return _createTransaction2Packet(
      subcommand: trans2FindFirst2,
      tid: tid,
      uid: uid,
      parameters: paramBytes,
    );
  }

  /// Create a TRANS2_FIND_NEXT2 request (SMB subcommand 0x0002)
  static Smb1Packet createFindNext2Request({
    required int sid,
    required int resumeKey,
    required String lastName,
    required int tid,
    required int uid,
  }) {
    final unicodeLastName = _encodeUnicodeString(lastName);
    final paramBytes = Uint8List(12 + unicodeLastName.length);
    final pBd = ByteData.sublistView(paramBytes);
    pBd.setUint16(0, sid, Endian.little);
    pBd.setUint16(2, 256, Endian.little); // SearchCount
    pBd.setUint16(4, 0x0104, Endian.little); // InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
    pBd.setUint32(6, resumeKey, Endian.little);
    pBd.setUint16(10, 0x0006, Endian.little); // Flags: CloseIfEOS
    paramBytes.setRange(12, paramBytes.length, unicodeLastName);

    return _createTransaction2Packet(
      subcommand: trans2FindNext2,
      tid: tid,
      uid: uid,
      parameters: paramBytes,
    );
  }

  static Smb1Packet _createTransaction2Packet({
    required int subcommand,
    required int tid,
    required int uid,
    required Uint8List parameters,
    Uint8List? data,
  }) {
    final d = data ?? Uint8List(0);
    const paramOffset = 68; // Standard header (32) + words (15*2+1) + byteCount (2) + padding
    final dataOffset = paramOffset + parameters.length;

    final words = [
      parameters.length, // TotalParameterCount
      d.length, // TotalDataCount
      10, // MaxParameterCount
      65535, // MaxDataCount
      0, // MaxSetupCount
      0, // Reserved
      0, // Flags
      0, // Timeout low
      0, // Timeout high
      0, // Reserved
      parameters.length, // ParameterCount
      paramOffset, // ParameterOffset
      d.length, // DataCount
      dataOffset, // DataOffset
      1, // SetupCount
      subcommand, // Setup0: Subcommand
    ];

    final bytes = Uint8List(parameters.length + d.length + 1);
    bytes[0] = 0; // Pad byte
    bytes.setRange(1, 1 + parameters.length, parameters);
    if (d.isNotEmpty) {
      bytes.setRange(1 + parameters.length, bytes.length, d);
    }

    return Smb1Packet(
      command: Smb1Packet.cmdTransaction2,
      tid: tid,
      uid: uid,
      words: words,
      bytes: bytes,
    );
  }

  static ({List<Smb1FileEntry> entries, int sid, bool endOfSearch})
      parseFindBothDirectoryInfo(Smb1Packet packet) {
    if (packet.status != NtStatus.success &&
        packet.status != NtStatus.noMoreFiles) {
      throw SmbException(
        'Listing failed: ${NtStatus.describe(packet.status)}',
        NtStatus.toSmbErrorType(packet.status),
      );
    }
    if (packet.words.length < 10) {
      return (entries: <Smb1FileEntry>[], sid: 0, endOfSearch: true);
    }

    final pWords = packet.words;
    final paramOffset = pWords[3];
    final paramCount = pWords[4];
    final dataOffset = pWords[7];
    final dataCount = pWords[8];

    var sid = 0;
    var endOfSearch = true;

    final raw = packet.encode();
    if (paramCount >= 6 && paramOffset + 6 <= raw.length) {
      final pBd = ByteData.sublistView(raw, paramOffset, paramOffset + paramCount);
      sid = pBd.getUint16(0, Endian.little);
      endOfSearch = pBd.getUint16(4, Endian.little) != 0;
    }

    final entries = <Smb1FileEntry>[];
    if (dataCount > 0 && dataOffset + dataCount <= raw.length) {
      var offset = dataOffset;
      final end = dataOffset + dataCount;
      while (offset + 94 <= end) {
        final d = ByteData.sublistView(raw, offset, end);
        final nextEntryOffset = d.getUint32(0, Endian.little);
        final lastWriteTime = d.getUint64(24, Endian.little);
        final endOfFile = d.getUint64(40, Endian.little);
        final fileAttributes = d.getUint32(56, Endian.little);
        final fileNameLen = d.getUint32(60, Endian.little);

        if (offset + 94 + fileNameLen <= end) {
          final nameBytes = raw.sublist(offset + 94, offset + 94 + fileNameLen);
          final name = _decodeUnicodeString(nameBytes);
          final isDirectory = (fileAttributes & 0x10) != 0;

          // Convert FILETIME to Unix epoch milliseconds
          final modifiedTime = (lastWriteTime > 116444736000000000)
              ? ((lastWriteTime - 116444736000000000) ~/ 10000)
              : 0;

          entries.add(
            Smb1FileEntry(
              name: name,
              isDirectory: isDirectory,
              size: endOfFile,
              modifiedTime: modifiedTime,
            ),
          );
        }

        if (nextEntryOffset == 0) break;
        offset += nextEntryOffset;
      }
    }

    return (entries: entries, sid: sid, endOfSearch: endOfSearch);
  }

  static Uint8List _encodeUnicodeString(String text) {
    final units = text.codeUnits;
    final out = Uint8List((units.length + 1) * 2);
    final bd = ByteData.sublistView(out);
    for (var i = 0; i < units.length; i++) {
      bd.setUint16(i * 2, units[i], Endian.little);
    }
    bd.setUint16(units.length * 2, 0, Endian.little);
    return out;
  }

  static Uint8List _encodeAsciiString(String text) {
    return Uint8List.fromList([...text.codeUnits, 0x00]);
  }

  static String _decodeUnicodeString(Uint8List bytes) {
    final bd = ByteData.sublistView(bytes);
    final count = bytes.length ~/ 2;
    final buffer = StringBuffer();
    for (var i = 0; i < count; i++) {
      final code = bd.getUint16(i * 2, Endian.little);
      if (code == 0) break;
      buffer.writeCharCode(code);
    }
    return buffer.toString();
  }
}
