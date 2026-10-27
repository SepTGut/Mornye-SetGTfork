import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/smb/smb_client.dart';
import 'package:mornye/services/smb/v1/commands.dart';
import 'package:mornye/services/smb/v1/packet.dart';
import 'package:mornye/services/smb/v1/shares.dart';
import 'package:mornye/services/smb/v1/status.dart';

void main() {
  group('SMB1 Commands & Shares packet structures', () {
    test('createTreeConnectRequest formats correctly for IPC and disk shares', () {
      final ipcReq = Smb1Commands.createTreeConnectRequest(path: r'\\192.168.1.1\IPC$');
      expect(ipcReq.command, Smb1Packet.cmdTreeConnectAndX);
      expect(ipcReq.words[2], 0x0000); // Flags: 0 (not 0x0008)
      expect(ipcReq.flags2 & Smb1Packet.flag2ExtendedSecurity, 0); // No extended security leak
      final ipcBytes = ipcReq.bytes;
      expect(ipcBytes[0], 0x00); // Null password
      final ipcStr = ascii.decode(ipcBytes.sublist(ipcBytes.length - 4));
      expect(ipcStr, 'IPC\x00');

      final diskReq = Smb1Commands.createTreeConnectRequest(path: r'\\192.168.1.1\Music');
      expect(diskReq.words[2], 0x0000);
      final diskBytes = diskReq.bytes;
      final diskStr = ascii.decode(diskBytes.sublist(diskBytes.length - 6));
      expect(diskStr, '?????\x00');
    });

    test('createNtCreateRequest aligns parameter block, excludes null from NameLength, and adds Unicode padding', () {
      final req = Smb1Commands.createNtCreateRequest(
        path: 'Music',
        tid: 1,
        uid: 2,
        write: false,
      );

      expect(req.command, Smb1Packet.cmdNtCreateAndX);
      expect(req.words.length, 24); // 24 words = 48 bytes
      expect(req.bytes.first, 0x00); // 1-byte padding to align Unicode Name to offset 84

      final encoded = req.encode();
      // SMB header: 32 bytes
      // WordCount: offset 32 (value 24)
      expect(encoded[32], 24);
      // ByteCount: offset 33 + 48 = 81
      final bd = ByteData.sublistView(encoded);
      final byteCount = bd.getUint16(81, Endian.little);
      expect(byteCount, req.bytes.length);
      // Unicode Name starts at offset 84 (83 is pad byte)
      expect(encoded[83], 0x00);
      // Offset 84 should be Unicode '\' (0x005C)
      expect(bd.getUint16(84, Endian.little), r'\'.codeUnitAt(0));

      // MS-CIFS 2.2.4.64.1: NameLength in word block at offset 5 is byte length of string WITHOUT null terminator
      // '\Music' is 6 characters = 12 UTF-16LE bytes
      final wordBlockBd = ByteData.sublistView(encoded, 33, 81);
      expect(wordBlockBd.getUint16(5, Endian.little), 12);
    });

    test('parseNtCreateResponse extracts fid, size, lastWriteTime, and directory flags', () {
      final raw = Uint8List(104);
      final bd = ByteData.sublistView(raw);
      // Header: 32 bytes
      raw[32] = 34; // WordCount = 34
      // Word block starts at 33
      bd.setUint16(38, 0x4321, Endian.little); // FID at byte 38
      bd.setUint64(60, 133000000000000000, Endian.little); // LastWriteTime at byte 60
      bd.setUint32(76, 0x00000020, Endian.little); // ExtFileAttributes (Archive) at byte 76
      bd.setUint64(88, 543210, Endian.little); // EndOfFile at byte 88
      raw[100] = 0; // Directory byte

      final packet = Smb1Packet(
        command: Smb1Packet.cmdNtCreateAndX,
        raw: raw,
      );

      final result = Smb1Commands.parseNtCreateResponse(packet);
      expect(result.fid, 0x4321);
      expect(result.isDirectory, isFalse);
      expect(result.size, 543210);
      expect(result.lastWriteTime, (133000000000000000 - 116444736000000000) ~/ 10000);

      // Verify directory detection via flag
      raw[100] = 1;
      final dirResult = Smb1Commands.parseNtCreateResponse(packet);
      expect(dirResult.isDirectory, isTrue);
    });

    test('RAP NetShareEnum request and response parsing', () {
      final req = Smb1Shares.createNetShareEnumRequest(tid: 1, uid: 2);
      expect(req.command, Smb1Packet.cmdTransaction);
      expect(req.flags2 & Smb1Packet.flag2Unicode, 0); // No Unicode for ASCII \PIPE\LANMAN
      expect(req.words.length, 14); // 14 words
      expect(req.words[10], 76); // ParameterOffset = 76

      // Construct a mock SMB_COM_TRANSACTION NetShareEnum response
      // Words: TotalParamCount(8), TotalDataCount(40), Reserved(0), ParamCount(8), ParamOffset, ...
      final paramBytes = Uint8List(8);
      final pBd = ByteData.sublistView(paramBytes);
      pBd.setUint16(0, 0, Endian.little); // Status: Success
      pBd.setUint16(2, 0, Endian.little); // Convert
      pBd.setUint16(4, 2, Endian.little); // EntriesReturned: 2
      pBd.setUint16(6, 2, Endian.little); // TotalEntries: 2

      // Two 20-byte share_info_1 structures
      final dataBytes = Uint8List(40);
      // Share 1: "Music" (STYPE_DISKTREE = 0)
      dataBytes.setRange(0, 5, ascii.encode('Music'));
      final d1Bd = ByteData.sublistView(dataBytes, 0, 20);
      d1Bd.setUint16(14, 0, Endian.little); // isDisk

      // Share 2: "IPC$" (STYPE_IPC = 3)
      dataBytes.setRange(20, 24, ascii.encode('IPC\$'));
      final d2Bd = ByteData.sublistView(dataBytes, 20, 40);
      d2Bd.setUint16(14, 3, Endian.little);

      // Assemble mock packet
      final mockPacket = Smb1Packet(
        command: Smb1Packet.cmdTransaction,
        status: NtStatus.success,
        words: [
          8, // 0: TotalParameterCount
          40, // 1: TotalDataCount
          0, // 2: Reserved
          8, // 3: ParameterCount
          55, // 4: ParameterOffset
          0, // 5: ParameterDisplacement
          40, // 6: DataCount
          63, // 7: DataOffset
          0, // 8: DataDisplacement
          0, // 9: SetupCount
        ],
        bytes: Uint8List.fromList([...paramBytes, ...dataBytes]),
      );

      final shares = Smb1Shares.parseNetShareEnumResponse(mockPacket);
      expect(shares.length, 1); // IPC$ filtered out, Music preserved
      expect(shares.first.name, 'Music');
      expect(shares.first.isDisk, isTrue);
    });

    test('TRANS2 FindFirst2 request structure and directory info parsing', () {
      final req = Smb1Commands.createFindFirst2Request(
        directoryPath: 'Albums',
        tid: 1,
        uid: 2,
      );
      expect(req.command, Smb1Packet.cmdTransaction2);
      expect(req.words.length, 15); // 15 words
      expect(req.words[10], 66); // ParameterOffset = 66
      expect(req.words[14], Smb1Commands.trans2FindFirst2);

      // Test response parsing
      final paramBytes = Uint8List(10);
      final pBd = ByteData.sublistView(paramBytes);
      pBd.setUint16(0, 0x1234, Endian.little); // SID: 0x1234
      pBd.setUint16(2, 1, Endian.little); // SearchCount: 1
      pBd.setUint16(4, 1, Endian.little); // EndOfSearch: true

      // One FILE_BOTH_DIR_INFO entry for "Song.flac"
      final fileNameUnicode = Uint8List(18);
      final fnBd = ByteData.sublistView(fileNameUnicode);
      const fileName = 'Song.flac';
      for (var i = 0; i < fileName.length; i++) {
        fnBd.setUint16(i * 2, fileName.codeUnitAt(i), Endian.little);
      }
      final entryLen = 94 + fileNameUnicode.length;
      final dataBytes = Uint8List(entryLen);
      final d = ByteData.sublistView(dataBytes);
      d.setUint32(0, 0, Endian.little); // NextEntryOffset = 0 (last entry)
      d.setUint64(40, 1048576, Endian.little); // EndOfFile: 1MB
      d.setUint32(56, 0x20, Endian.little); // FileAttributes: Archive (file)
      d.setUint32(60, fileNameUnicode.length, Endian.little); // FileNameLength
      dataBytes.setRange(94, entryLen, fileNameUnicode);

      final mockPacket = Smb1Packet(
        command: Smb1Packet.cmdTransaction2,
        status: NtStatus.success,
        words: [
          10, // TotalParameterCount
          dataBytes.length, // TotalDataCount
          0, // Reserved
          10, // 3: ParameterCount
          55, // 4: ParameterOffset
          0, // 5: ParameterDisplacement
          dataBytes.length, // 6: DataCount
          65, // 7: DataOffset
          0, // 8: DataDisplacement
          0, // 9: SetupCount
        ],
        bytes: Uint8List.fromList([...paramBytes, ...dataBytes]),
      );

      final result = Smb1Commands.parseFindBothDirectoryInfo(mockPacket);
      expect(result.sid, 0x1234);
      expect(result.endOfSearch, isTrue);
      expect(result.entries.length, 1);
      expect(result.entries.first.name, 'Song.flac');
      expect(result.entries.first.isDirectory, isFalse);
      expect(result.entries.first.size, 1048576);
    });
  });
}
