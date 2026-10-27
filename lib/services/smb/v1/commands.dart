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

class Smb1NtCreateResult {
  const Smb1NtCreateResult({
    required this.fid,
    required this.isDirectory,
    required this.size,
    required this.lastWriteTime,
  });

  final int fid;
  final bool isDirectory;
  final int size;
  final int lastWriteTime;
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
      flags2:
          Smb1Packet.flag2Unicode |
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
    const caps =
        capUnicode |
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
    // Header (32) + WordCount (1) + 12 words (24) + ByteCount (2) = 59
    final pad = ((59 + securityBlob.length) % 2 != 0) ? 1 : 0;
    final totalBytes =
        securityBlob.length + pad + osBytes.length + lanmanBytes.length;
    final bytes = Uint8List(totalBytes);
    bytes.setRange(0, securityBlob.length, securityBlob);
    if (pad == 1) {
      bytes[securityBlob.length] = 0x00;
    }
    final osOffset = securityBlob.length + pad;
    bytes.setRange(osOffset, osOffset + osBytes.length, osBytes);
    bytes.setRange(osOffset + osBytes.length, totalBytes, lanmanBytes);

    return Smb1Packet(
      command: Smb1Packet.cmdSessionSetupAndX,
      flags2:
          Smb1Packet.flag2Unicode |
          Smb1Packet.flag2NtStatus |
          Smb1Packet.flag2ExtendedSecurity,
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
    const caps = capUnicode | capLargeFiles | capNtSmbs | capStatus32;

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
    final isIpc = path.toUpperCase().endsWith(r'\IPC$');
    final service = isIpc
        ? [...'IPC'.codeUnits, 0x00]
        : [...'?????'.codeUnits, 0x00];

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
        0x0000, // Flags: 0 (no extended response required)
        0x0001, // PasswordLength: 1
      ],
      bytes: bytes,
    );
  }

  static Smb1Packet createTreeDisconnectRequest({required int tid}) =>
      Smb1Packet(command: Smb1Packet.cmdTreeDisconnect, tid: tid);

  static Smb1Packet createLogoffRequest({required int uid}) => Smb1Packet(
    command: Smb1Packet.cmdLogoffAndX,
    uid: uid,
    words: [0x00FF, 0x0000],
  );

  static Smb1Packet createNtCreateRequest({
    required String path,
    required int tid,
    required int uid,
    required bool write,
    int disposition =
        1, // 1 = FILE_OPEN, 2 = FILE_CREATE, 5 = FILE_OVERWRITE_IF
    bool directory = false,
  }) {
    final cleanPath = path.replaceAll('/', '\\');
    final fullPath = cleanPath.startsWith('\\') ? cleanPath : '\\$cleanPath';
    final unicodePath = _encodeUnicodeString(fullPath);
    final nameByteLength = fullPath.length * 2;

    final desiredAccess = write ? 0x0012019F : 0x00120089;
    final extFileAttrs = directory ? 0x00000010 : (write ? 0x00000080 : 0);
    final createOptions = directory ? 0x00000001 : 0x00000040;

    // MS-CIFS 2.2.4.64.1: SMB_COM_NT_CREATE_ANDX Request (48 bytes = 24 words)
    final wordBytes = Uint8List(48);
    final wBd = ByteData.sublistView(wordBytes);
    wBd.setUint8(0, 0xFF); // AndXCommand
    wBd.setUint8(1, 0); // AndXReserved
    wBd.setUint16(2, 0, Endian.little); // AndXOffset
    wBd.setUint8(4, 0); // Reserved
    wBd.setUint16(
      5,
      nameByteLength,
      Endian.little,
    ); // NameLength in bytes (excluding null terminator per MS-CIFS 2.2.4.64.1)
    wBd.setUint32(7, 0x00000016, Endian.little); // Flags
    wBd.setUint32(11, 0, Endian.little); // RootDirectoryFID
    wBd.setUint32(15, desiredAccess, Endian.little); // DesiredAccess
    wBd.setUint64(19, 0, Endian.little); // AllocationSize
    wBd.setUint32(27, extFileAttrs, Endian.little); // ExtFileAttributes
    wBd.setUint32(
      31,
      0x00000007,
      Endian.little,
    ); // ShareAccess: Read/Write/Delete
    wBd.setUint32(35, disposition, Endian.little); // CreateDisposition
    wBd.setUint32(39, createOptions, Endian.little); // CreateOptions
    wBd.setUint32(43, 0x00000002, Endian.little); // ImpersonationLevel
    wBd.setUint8(47, 0); // SecurityFlags

    final words = Uint16List(24);
    for (var i = 0; i < 24; i++) {
      words[i] = wBd.getUint16(i * 2, Endian.little);
    }

    // SMB Header (32) + WordCount (1) + 24 words (48) + ByteCount (2) = 83 bytes.
    // 83 is odd; add 1 pad byte so Name begins on a 2-byte boundary (offset 84)
    final bytes = Uint8List(1 + unicodePath.length);
    bytes[0] = 0x00; // Pad byte
    bytes.setRange(1, bytes.length, unicodePath);

    return Smb1Packet(
      command: Smb1Packet.cmdNtCreateAndX,
      tid: tid,
      uid: uid,
      words: words,
      bytes: bytes,
    );
  }

  static Smb1Packet createReadRequest({
    required int fid,
    required int offset,
    required int length,
    required int tid,
    required int uid,
  }) {
    // MS-CIFS 2.2.4.42.1: WordCount = 12 (64-bit offset)
    final words = [
      0x00FF, // 0: AndXCommand
      0x0000, // 1: AndXOffset
      fid, // 2: FID
      offset & 0xFFFF, // 3: OffsetLow
      (offset >> 16) & 0xFFFF, // 4: OffsetHigh (32-bit)
      length & 0xFFFF, // 5: MaxCountOfBytesToReturn
      0, // 6: MinCountOfBytesToReturn
      0, // 7: Timeout low
      0, // 8: Timeout high
      0, // 9: Remaining
      (offset ~/ 0x100000000) & 0xFFFF, // 10: OffsetHigh64 low
      ((offset ~/ 0x100000000) >> 16) & 0xFFFF, // 11: OffsetHigh64 high
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
    // MS-CIFS 2.2.4.43.1: WordCount = 14 (64-bit offset)
    // Header (32) + WordCount (1) + 14 words (28) + ByteCount (2) = 63 bytes.
    // Pad byte at offset 63 aligns data to offset 64 (0x0040).
    final words = [
      0x00FF, // 0: AndXCommand
      0x0000, // 1: AndXOffset
      fid, // 2: FID
      offset & 0xFFFF, // 3: OffsetLow
      (offset >> 16) & 0xFFFF, // 4: OffsetHigh (32-bit)
      0, // 5: Timeout low
      0, // 6: Timeout high
      0, // 7: WriteMode
      0, // 8: Remaining
      0, // 9: DataLengthHigh
      data.length & 0xFFFF, // 10: DataLength
      0x0040, // 11: DataOffset (64)
      (offset ~/ 0x100000000) & 0xFFFF, // 12: OffsetHigh64 low
      ((offset ~/ 0x100000000) >> 16) & 0xFFFF, // 13: OffsetHigh64 high
    ];

    final bytes = Uint8List(1 + data.length);
    bytes[0] = 0; // Pad byte at offset 63
    bytes.setRange(1, bytes.length, data);

    return Smb1Packet(
      command: Smb1Packet.cmdWriteAndX,
      tid: tid,
      uid: uid,
      words: words,
      bytes: bytes,
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
    pBd.setUint16(
      0,
      0x0016,
      Endian.little,
    ); // SearchAttributes: Hidden | System | Directory
    pBd.setUint16(2, 256, Endian.little); // SearchCount
    pBd.setUint16(4, 0x0006, Endian.little); // Flags: CloseIfEOS | ResumeKeys
    pBd.setUint16(
      6,
      0x0104,
      Endian.little,
    ); // InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
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
    pBd.setUint16(
      4,
      0x0104,
      Endian.little,
    ); // InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
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
    // Header (32) + WordCount (1) + 15 words (30) + ByteCount (2) = 65 bytes.
    // bytes[0] is pad byte at offset 65 so parameters start at offset 66 (even).
    const paramOffset = 66;
    var dataOffset = paramOffset + parameters.length;
    var padData = 0;
    if (d.isNotEmpty && (dataOffset % 2 != 0)) {
      padData = 1;
      dataOffset += 1;
    }

    // MS-CIFS 2.2.4.46.1: WordCount = 14 + SetupCount = 15 words
    final words = [
      parameters.length, // 0: TotalParameterCount
      d.length, // 1: TotalDataCount
      10, // 2: MaxParameterCount
      65535, // 3: MaxDataCount
      0, // 4: MaxSetupCount (low) | Reserved1 (high)
      0, // 5: Flags
      0, 0, // 6, 7: Timeout (ULONG: 2 words)
      0, // 8: Reserved2
      parameters.length, // 9: ParameterCount
      paramOffset, // 10: ParameterOffset
      d.length, // 11: DataCount
      dataOffset, // 12: DataOffset
      1, // 13: SetupCount (1) | Reserved3 (0)
      subcommand, // 14: Setup0: Subcommand
    ];

    final totalBytes = 1 + parameters.length + padData + d.length;
    final bytes = Uint8List(totalBytes);
    bytes[0] = 0; // Pad byte at offset 65
    bytes.setRange(1, 1 + parameters.length, parameters);
    if (d.isNotEmpty) {
      bytes.setRange(1 + parameters.length + padData, totalBytes, d);
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
    // MS-CIFS 2.2.4.46.2: Response Words
    // words[3] = ParameterCount, words[4] = ParameterOffset
    // words[6] = DataCount, words[7] = DataOffset
    final paramCount = pWords[3];
    final paramOffset = pWords[4];
    final dataCount = pWords[6];
    final dataOffset = pWords[7];

    var sid = 0;
    var endOfSearch = true;

    final raw = packet.raw ?? packet.encode();
    if (paramCount >= 6 && paramOffset + 6 <= raw.length) {
      final pBd = ByteData.sublistView(
        raw,
        paramOffset,
        paramOffset + paramCount,
      );
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

  static Smb1NtCreateResult parseNtCreateResponse(Smb1Packet packet) {
    final raw = packet.raw ?? packet.encode();
    if (raw.length < 101) {
      throw SmbException(
        'Malformed SMB_COM_NT_CREATE_ANDX response: length ${raw.length} < 101',
        SmbErrorType.incompatible,
      );
    }
    final bd = ByteData.sublistView(raw);
    // MS-CIFS 2.2.4.64.2:
    // Header (32) + WordCount (1 at 32). Word block starts at byte 33.
    // Offset 4: OpLockLevel (1 byte at 37)
    // Offset 5: FID (2 bytes at 38..39)
    // Offset 27: LastWriteTime (8 bytes at 60..67, FILETIME)
    // Offset 43: ExtFileAttributes (4 bytes at 76..79)
    // Offset 55: EndOfFile (8 bytes at 88..95, uint64)
    // Offset 67: Directory (1 byte at 100, boolean)
    final fid = bd.getUint16(38, Endian.little);
    final lastWriteTime = bd.getUint64(60, Endian.little);
    final fileAttrs = bd.getUint32(76, Endian.little);
    final endOfFile = bd.getUint64(88, Endian.little);
    final isDirectory = raw[100] != 0 || (fileAttrs & 0x10) != 0;

    return Smb1NtCreateResult(
      fid: fid,
      isDirectory: isDirectory,
      size: endOfFile,
      lastWriteTime: (lastWriteTime > 116444736000000000)
          ? ((lastWriteTime - 116444736000000000) ~/ 10000)
          : 0,
    );
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
