import 'package:flutter_test/flutter_test.dart';
import 'package:mornye/models/download_history.dart';
import 'package:mornye/models/library_folder_node.dart';
import 'package:mornye/models/unified_library_item.dart';

UnifiedLibraryItem _makeItem({
  required String id,
  required String trackName,
  required String filePath,
  String? safRelativeDir,
  int? trackNumber,
  int? discNumber,
}) {
  return UnifiedLibraryItem(
    id: id,
    trackName: trackName,
    artistName: 'Artist',
    albumName: 'Album',
    filePath: filePath,
    addedAt: DateTime.utc(2026, 1, 1),
    source: LibraryItemSource.downloaded,
    historyItem: DownloadHistoryItem(
      id: id,
      trackName: trackName,
      artistName: 'Artist',
      albumName: 'Album',
      filePath: filePath,
      safRelativeDir: safRelativeDir,
      service: 'test',
      downloadedAt: DateTime.utc(2026, 1, 1),
      trackNumber: trackNumber,
      discNumber: discNumber,
      explicit: false,
      hasLyrics: false,
      lyricsMetadataScanVersion: 1,
      hasReplayGain: false,
      replayGainMetadataScanVersion: 1,
    ),
  );
}

void main() {
  group('LibraryFolderTree', () {
    test('empty track list yields empty tree with zero folders', () {
      final tree = LibraryFolderTree.fromTracks([]);
      expect(tree.totalFolderCount, 0);
      expect(tree.rootFolders, isEmpty);
      expect(tree.root.totalTrackCount, 0);
      expect(tree.root.subfolders, isEmpty);
      expect(tree.resolveNode(null).path, '');
      expect(tree.resolveNode('').path, '');
      expect(tree.resolveNode('nonexistent').path, '');
      expect(tree.getBreadcrumbs(null), isEmpty);
      expect(tree.getBreadcrumbs(''), isEmpty);
    });

    test(
      'builds single folder with direct tracks and sorts tracks by track number',
      () {
        final tracks = [
          _makeItem(
            id: '2',
            trackName: 'Track Two',
            filePath: '/storage/emulated/0/Music/track2.flac',
            trackNumber: 2,
          ),
          _makeItem(
            id: '1',
            trackName: 'Track One',
            filePath: '/storage/emulated/0/Music/track1.flac',
            trackNumber: 1,
          ),
        ];

        final tree = LibraryFolderTree.fromTracks(tracks);
        expect(tree.rootFolders.length, 1);
        final musicFolder = tree.rootFolders.first;
        expect(musicFolder.name, 'Music');
        expect(musicFolder.totalTrackCount, 2);
        expect(musicFolder.directTracks.length, 2);
        // Verify sorting: track 1 then track 2
        expect(musicFolder.directTracks[0].trackName, 'Track One');
        expect(musicFolder.directTracks[1].trackName, 'Track Two');
        expect(musicFolder.allTracks.length, 2);
      },
    );

    test('collapses linear ancestor paths leading to folders', () {
      final tracks = [
        _makeItem(
          id: '1',
          trackName: 'Song A',
          filePath: 'D:/Music/Rock/Queen/Bohemian Rhapsody.mp3',
        ),
        _makeItem(
          id: '2',
          trackName: 'Song B',
          filePath: 'D:/Music/Rock/Pink Floyd/Time.mp3',
        ),
      ];

      final tree = LibraryFolderTree.fromTracks(tracks);
      // Common linear path D:/Music/Rock has multiple children: Queen and Pink Floyd.
      // So root folder should collapse up to D:/Music/Rock or the split.
      expect(tree.rootFolders.length, 1);
      final rockFolder = tree.rootFolders.first;
      expect(rockFolder.name, 'Rock');
      expect(rockFolder.subfolders.length, 2);
      final subNames = rockFolder.subfolders.map((f) => f.name).toList();
      expect(subNames, containsAll(['Pink Floyd', 'Queen']));
      expect(rockFolder.totalTrackCount, 2);
    });

    test('supports breadcrumbs navigation to deeply nested folder', () {
      final tracks = [
        _makeItem(
          id: '1',
          trackName: 'Aerodynamic',
          filePath:
              '/home/user/Music/Electronic/Daft Punk/Discovery/Aerodynamic.flac',
        ),
        _makeItem(
          id: '2',
          trackName: 'The Robots',
          filePath:
              '/home/user/Music/Electronic/Kraftwerk/The Man-Machine/The Robots.flac',
        ),
      ];

      final tree = LibraryFolderTree.fromTracks(tracks);
      final leafPath = '/home/user/Music/Electronic/Daft Punk/Discovery';
      final leaf = tree.resolveNode(leafPath);
      expect(leaf.name, 'Discovery');
      expect(leaf.directTracks.length, 1);

      final breadcrumbs = tree.getBreadcrumbs(leafPath);
      expect(breadcrumbs.length, 3);
      expect(breadcrumbs[0].name, 'Electronic');
      expect(breadcrumbs[1].name, 'Daft Punk');
      expect(breadcrumbs[2].name, 'Discovery');
    });

    test('handles safRelativeDir and normalizes backslashes', () {
      final tracks = [
        _makeItem(
          id: '1',
          trackName: 'SAF Song',
          filePath: 'ignored_local_path',
          safRelativeDir: r'Lossless\Classical\Bach',
        ),
      ];

      final tree = LibraryFolderTree.fromTracks(tracks);
      expect(tree.rootFolders.length, 1);
      final rootFolder = tree.rootFolders.first;
      expect(rootFolder.name, 'Bach');
      expect(rootFolder.totalTrackCount, 1);
    });

    test('handles content:// uri decoding gracefully', () {
      final tracks = [
        _makeItem(
          id: '1',
          trackName: 'Content Track',
          filePath:
              'content://com.android.externalstorage.documents/document/primary%3AMusic%2FSoundtracks%2FOST.mp3',
        ),
      ];

      final tree = LibraryFolderTree.fromTracks(tracks);
      expect(tree.rootFolders.length, 1);
      final rootFolder = tree.rootFolders.first;
      expect(rootFolder.name, 'Soundtracks');
      expect(rootFolder.totalTrackCount, 1);
    });
  });
}
