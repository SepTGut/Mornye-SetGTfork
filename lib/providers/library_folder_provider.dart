import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mornye/models/library_folder_node.dart';
import 'package:mornye/providers/download_history_provider.dart';
import 'package:mornye/providers/local_library_provider.dart';
import 'package:mornye/providers/settings_provider.dart';
import 'package:mornye/services/library_database.dart';

export 'package:mornye/models/library_folder_node.dart';

final libraryFolderTreeProvider = FutureProvider.autoDispose<LibraryFolderTree>(
  (ref) async {
    final includeLocal = ref.watch(
      settingsProvider.select((s) => s.localLibraryEnabled),
    );
    ref.watch(downloadHistoryProvider.select((s) => s.loadedIndexVersion));
    if (includeLocal) {
      ref.watch(localLibraryProvider.select((s) => s.loadedIndexVersion));
    }

    final tracks = await LibraryDatabase.instance.getQueueAllTracksForFolders(
      includeLocal: includeLocal,
    );
    return LibraryFolderTree.fromTracks(tracks);
  },
);
