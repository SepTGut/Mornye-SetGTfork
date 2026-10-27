import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/services/ftp/ftp_listing.dart';

void main() {
  group('EPSV / PASV parsing', () {
    test('parses EPSV port successfully', () {
      expect(
        FtpListingParser.parseEpsv(
          '229 Entering Extended Passive Mode (|||54321|)',
        ),
        54321,
      );
      expect(
        FtpListingParser.parseEpsv(
          '229 Entering Extended Passive Mode (|||1234|)',
        ),
        1234,
      );
    });

    test('rejects malformed EPSV replies', () {
      expect(
        () => FtpListingParser.parseEpsv('229 Entering Extended Passive Mode'),
        throwsFormatException,
      );
      expect(
        () => FtpListingParser.parseEpsv('229 Mode (|||0|)'),
        throwsFormatException,
      );
      expect(
        () => FtpListingParser.parseEpsv('229 Mode (|||70000|)'),
        throwsFormatException,
      );
    });

    test('parses PASV port successfully', () {
      final port = FtpListingParser.parsePasv(
        '227 Entering Passive Mode (192,168,1,50,195,81)',
      );
      expect(port, 195 * 256 + 81);
    });

    test('rejects malformed PASV replies', () {
      expect(
        () => FtpListingParser.parsePasv('227 Entering Passive Mode'),
        throwsFormatException,
      );
      expect(
        () => FtpListingParser.parsePasv(
          '227 Entering Passive Mode (192,168,1,50,195)',
        ),
        throwsFormatException,
      );
    });
  });

  group('RFC 3659 MLSD parsing', () {
    test('parses standard MLSD entries with files, dirs and timestamps', () {
      final lines = [
        'type=dir;modify=20240115123000;size=4096; Music',
        'type=file;modify=20240115123500;size=10485760; 01 - Track.flac',
        'type=cdir;modify=20240115123000; .',
        'type=pdir;modify=20240115123000; ..',
      ];

      final entries = FtpListingParser.parseMlsd(lines);
      expect(entries.length, 2);

      final dir = entries[0];
      expect(dir.name, 'Music');
      expect(dir.isDirectory, isTrue);

      final file = entries[1];
      expect(file.name, '01 - Track.flac');
      expect(file.isDirectory, isFalse);
      expect(file.size, 10485760);

      final modified = DateTime.fromMillisecondsSinceEpoch(
        file.modifiedTime,
        isUtc: true,
      );
      expect(modified.year, 2024);
      expect(modified.month, 1);
      expect(modified.day, 15);
      expect(modified.hour, 12);
      expect(modified.minute, 35);

      final smb = file.toSmbEntry();
      expect(smb.name, '01 - Track.flac');
      expect(smb.isDirectory, isFalse);
      expect(smb.size, 10485760);
      expect(smb.modifiedTime, file.modifiedTime);
    });

    test('skips unsafe names in MLSD', () {
      final lines = [
        'type=file;size=100; ../escaped.txt',
        'type=file;size=100; nested/file.txt',
        'type=file;size=100; null\x00byte.txt',
        'type=file;size=100; valid.mp3',
      ];

      final entries = FtpListingParser.parseMlsd(lines);
      expect(entries.length, 1);
      expect(entries.first.name, 'valid.mp3');
    });
  });

  group('Unix ls -l parsing', () {
    test('parses Unix listing with standard dates and spaces', () {
      final lines = [
        'drwxr-xr-x   5 user group     4096 Jan 15 12:30 My Music',
        '-rw-r--r--   1 user group 10485760 Jan 15 12:35 01 - Intro.flac',
        'lrwxrwxrwx   1 user group       10 Jan 15 12:36 link.mp3 -> target.mp3',
        'drwxr-xr-x   2 user group     4096 Jan 15 12:30 .',
        'drwxr-xr-x   4 user group     4096 Jan 15 12:30 ..',
      ];

      final now = DateTime.utc(2024, 6, 1);
      final entries = FtpListingParser.parseList(lines, now);
      expect(entries.length, 3);

      expect(entries[0].name, 'My Music');
      expect(entries[0].isDirectory, isTrue);

      expect(entries[1].name, '01 - Intro.flac');
      expect(entries[1].isDirectory, isFalse);
      expect(entries[1].size, 10485760);

      expect(entries[2].name, 'link.mp3');
      expect(entries[2].isDirectory, isFalse);
    });

    test('parses Unix listing with year format (older files)', () {
      final lines = [
        '-rw-r--r--   1 ftp ftp  1234567 Jun 20  2023 archive.tar.gz',
      ];

      final now = DateTime.utc(2024, 1, 1);
      final entries = FtpListingParser.parseList(lines, now);
      expect(entries.length, 1);
      expect(entries.first.name, 'archive.tar.gz');
      expect(entries.first.size, 1234567);

      final modified = DateTime.fromMillisecondsSinceEpoch(
        entries.first.modifiedTime,
        isUtc: true,
      );
      expect(modified.year, 2023);
      expect(modified.month, 6);
      expect(modified.day, 20);
    });
  });

  group('DOS LIST parsing', () {
    test('parses Windows/DOS style directory listing', () {
      final lines = [
        '01-15-24  12:30PM       <DIR>          Albums',
        '01-15-24  01:45PM             25165824 Song Title.wav',
        '02-28-23  08:15AM              1048576 older.mp3',
      ];

      final entries = FtpListingParser.parseList(lines);
      expect(entries.length, 3);

      expect(entries[0].name, 'Albums');
      expect(entries[0].isDirectory, isTrue);

      expect(entries[1].name, 'Song Title.wav');
      expect(entries[1].isDirectory, isFalse);
      expect(entries[1].size, 25165824);

      expect(entries[2].name, 'older.mp3');
      expect(entries[2].size, 1048576);
    });
  });

  group('Path validation safety', () {
    test('isValidName rejects directory traversal and illegal chars', () {
      expect(FtpListingParser.isValidName(''), isFalse);
      expect(FtpListingParser.isValidName('.'), isFalse);
      expect(FtpListingParser.isValidName('..'), isFalse);
      expect(FtpListingParser.isValidName('foo/bar'), isFalse);
      expect(FtpListingParser.isValidName('foo\\bar'), isFalse);
      expect(FtpListingParser.isValidName('foo\x00bar'), isFalse);

      expect(FtpListingParser.isValidName('song.flac'), isTrue);
      expect(FtpListingParser.isValidName('01. Track #1 & 100%.mp3'), isTrue);
      expect(FtpListingParser.isValidName('日本語.m4a'), isTrue);
    });
  });
}
