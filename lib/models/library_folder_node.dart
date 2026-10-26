import 'package:path/path.dart' as p;
import 'package:mornye/models/unified_library_item.dart';

/// A node in the hierarchical library folder tree.
class LibraryFolderNode {
  /// Normalized full path of this folder (using '/' separators).
  final String path;

  /// Display name of this folder, e.g. "Queen", "Rock", or "Music".
  final String name;

  /// Path of parent folder, or null if this is a top-level folder.
  final String? parentPath;

  /// Child folder nodes directly inside this folder.
  final List<LibraryFolderNode> subfolders;

  /// Tracks located directly inside this folder.
  final List<UnifiedLibraryItem> directTracks;

  /// Total count of tracks in this folder and all its descendants.
  final int totalTrackCount;

  const LibraryFolderNode({
    required this.path,
    required this.name,
    this.parentPath,
    this.subfolders = const [],
    this.directTracks = const [],
    required this.totalTrackCount,
  });

  bool get isEmpty => subfolders.isEmpty && directTracks.isEmpty;

  /// All tracks in this folder and its subfolders, for bulk play/shuffle.
  List<UnifiedLibraryItem> get allTracks {
    final list = <UnifiedLibraryItem>[...directTracks];
    for (final child in subfolders) {
      list.addAll(child.allTracks);
    }
    return list;
  }
}

/// Holds the built folder tree and provides fast lookup by path.
class LibraryFolderTree {
  /// The virtual or common root node.
  final LibraryFolderNode root;

  /// Index of all nodes keyed by their normalized [LibraryFolderNode.path].
  final Map<String, LibraryFolderNode> nodesByPath;

  /// The top-level folders displayed to the user at the root of the browser.
  final List<LibraryFolderNode> rootFolders;

  /// Total number of folders in the tree.
  final int totalFolderCount;

  const LibraryFolderTree({
    required this.root,
    required this.nodesByPath,
    required this.rootFolders,
    required this.totalFolderCount,
  });

  /// Resolves the folder node for [path], falling back to [root].
  LibraryFolderNode resolveNode(String? path) {
    if (path == null || path.isEmpty) return root;
    return nodesByPath[path] ?? root;
  }

  /// Returns the breadcrumb chain of folder nodes from root to [path].
  List<LibraryFolderNode> getBreadcrumbs(String? path) {
    if (path == null || path.isEmpty) return const [];
    final crumbs = <LibraryFolderNode>[];
    String? current = path;
    while (current != null && current.isNotEmpty) {
      final node = nodesByPath[current];
      if (node != null) {
        crumbs.add(node);
        current = node.parentPath;
      } else {
        break;
      }
    }
    return crumbs.reversed.toList(growable: false);
  }

  /// Builds a [LibraryFolderTree] from a list of library tracks.
  factory LibraryFolderTree.fromTracks(List<UnifiedLibraryItem> tracks) {
    if (tracks.isEmpty) {
      const emptyRoot = LibraryFolderNode(
        path: '',
        name: 'Folders',
        totalTrackCount: 0,
      );
      return const LibraryFolderTree(
        root: emptyRoot,
        nodesByPath: {'': emptyRoot},
        rootFolders: [],
        totalFolderCount: 0,
      );
    }

    final tracksByFolder = <String, List<UnifiedLibraryItem>>{};
    for (final track in tracks) {
      final folder = _extractFolderForTrack(track);
      tracksByFolder.putIfAbsent(folder, () => []).add(track);
    }

    // Discover all ancestor folder paths.
    final allDirs = <String>{};
    for (final dir in tracksByFolder.keys) {
      var current = dir;
      allDirs.add(current);
      while (current.isNotEmpty && current != '/' && current != '.') {
        final parent = p.posix.dirname(current);
        if (parent == current || parent == '.' || parent == '/') break;
        allDirs.add(parent);
        current = parent;
      }
    }

    // Determine top-level roots (dirs with no parent in allDirs).
    final rawRoots = allDirs.where((dir) {
      final parent = p.posix.dirname(dir);
      return parent == dir ||
          parent == '.' ||
          parent == '/' ||
          !allDirs.contains(parent);
    }).toList();

    // Collapse single-child linear paths leading to music (e.g. /storage/emulated/0/Music -> Music).
    final collapsedRoots = rawRoots
        .map((r) => _collapseRoot(r, allDirs, tracksByFolder))
        .toSet()
        .toList();

    final nodesMap = <String, LibraryFolderNode>{};

    LibraryFolderNode buildNode(String dirPath, {String? parentPath}) {
      final direct = tracksByFolder[dirPath] ?? const [];
      final sortedDirect = List<UnifiedLibraryItem>.from(direct)
        ..sort((a, b) {
          final dA = a.localItem?.discNumber ?? a.historyItem?.discNumber ?? 0;
          final dB = b.localItem?.discNumber ?? b.historyItem?.discNumber ?? 0;
          if (dA != dB) return dA.compareTo(dB);
          final tA =
              a.localItem?.trackNumber ?? a.historyItem?.trackNumber ?? 0;
          final tB =
              b.localItem?.trackNumber ?? b.historyItem?.trackNumber ?? 0;
          if (tA != tB && tA > 0 && tB > 0) return tA.compareTo(tB);
          return a.trackName.toLowerCase().compareTo(b.trackName.toLowerCase());
        });

      final childDirs =
          allDirs
              .where((d) => p.posix.dirname(d) == dirPath && d != dirPath)
              .toList()
            ..sort(
              (a, b) => p.posix
                  .basename(a)
                  .toLowerCase()
                  .compareTo(p.posix.basename(b).toLowerCase()),
            );

      final subfolders = childDirs
          .map((cp) => buildNode(cp, parentPath: dirPath))
          .toList(growable: false);

      final totalCount =
          sortedDirect.length +
          subfolders.fold<int>(0, (sum, f) => sum + f.totalTrackCount);

      var displayName = p.posix.basename(dirPath);
      if (displayName.isEmpty || displayName == '.' || displayName == '/') {
        displayName = dirPath;
      }

      final node = LibraryFolderNode(
        path: dirPath,
        name: displayName,
        parentPath: parentPath,
        subfolders: subfolders,
        directTracks: sortedDirect,
        totalTrackCount: totalCount,
      );
      nodesMap[dirPath] = node;
      return node;
    }

    final rootNodes =
        collapsedRoots.map((cp) => buildNode(cp, parentPath: '')).toList()
          ..sort(
            (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
          );

    final totalTracks = rootNodes.fold<int>(
      0,
      (sum, n) => sum + n.totalTrackCount,
    );
    final root = LibraryFolderNode(
      path: '',
      name: 'Folders',
      subfolders: rootNodes,
      totalTrackCount: totalTracks,
    );
    nodesMap[''] = root;

    return LibraryFolderTree(
      root: root,
      nodesByPath: nodesMap,
      rootFolders: rootNodes,
      totalFolderCount: nodesMap.length - 1, // Exclude virtual root
    );
  }

  static String _collapseRoot(
    String rootPath,
    Set<String> allDirs,
    Map<String, List<UnifiedLibraryItem>> tracksByFolder,
  ) {
    var current = rootPath;
    while (true) {
      final direct = tracksByFolder[current];
      if (direct != null && direct.isNotEmpty) break;
      final children = allDirs
          .where((d) => p.posix.dirname(d) == current && d != current)
          .toList();
      if (children.length == 1) {
        current = children.first;
      } else {
        break;
      }
    }
    return current;
  }

  static String _extractFolderForTrack(UnifiedLibraryItem track) {
    final history = track.historyItem;
    if (history?.safRelativeDir != null &&
        history!.safRelativeDir!.trim().isNotEmpty) {
      final rel = history.safRelativeDir!.trim().replaceAll('\\', '/');
      return 'Downloads/$rel';
    }
    var raw = track.filePath.trim().replaceAll('\\', '/');
    if (raw.isEmpty) return 'Other';
    if (raw.startsWith('content://')) {
      final decoded = Uri.decodeComponent(raw);
      final docIdx = decoded.indexOf('/document/');
      if (docIdx != -1) {
        final doc = decoded.substring(docIdx + '/document/'.length);
        final colonIdx = doc.indexOf(':');
        raw = colonIdx != -1 ? doc.substring(colonIdx + 1) : doc;
      }
    }
    final dir = p.posix.dirname(raw);
    if (dir.isEmpty || dir == '.' || dir == '/') return 'Music';
    return dir;
  }
}
