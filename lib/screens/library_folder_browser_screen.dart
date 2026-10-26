import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mornye/l10n/l10n.dart';
import 'package:mornye/models/unified_library_item.dart';
import 'package:mornye/providers/library_folder_provider.dart';
import 'package:mornye/providers/music_player_provider.dart';
import 'package:mornye/providers/playback_provider.dart';
import 'package:mornye/services/playable_media.dart';
import 'package:mornye/screens/track_metadata_screen.dart';
import 'package:mornye/theme/mornye_theme.dart';
import 'package:mornye/utils/adaptive_layout.dart';
import 'package:mornye/utils/desktop_platform.dart';
import 'package:mornye/utils/file_access.dart';
import 'package:mornye/utils/nav_bar_inset.dart';
import 'package:mornye/widgets/animation_utils.dart';
import 'package:mornye/widgets/app_bottom_sheet.dart';
import 'package:mornye/widgets/app_icon.dart';
import 'package:mornye/widgets/app_icon_button.dart';
import 'package:mornye/widgets/app_loading_indicator.dart';
import 'package:mornye/widgets/app_search_field.dart';
import 'package:mornye/widgets/app_snack_bar.dart';
import 'package:mornye/widgets/cached_cover_image.dart';
import 'package:mornye/widgets/desktop/context_menu.dart';
import 'package:mornye/widgets/expressive_button.dart';
import 'package:mornye/widgets/playlist_picker_sheet.dart';
import 'package:mornye/widgets/settings_group.dart';
import 'package:mornye/widgets/track_card.dart';

/// Standalone screen for browsing library folders.
class LibraryFolderBrowserScreen extends StatelessWidget {
  final String? initialPath;

  const LibraryFolderBrowserScreen({super.key, this.initialPath});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(context.l10n.libraryFolders)),
      body: LibraryFolderBrowserWidget(initialPath: initialPath, isTab: false),
    );
  }
}

/// Reusable folder browser widget used in both QueueTab (Folders tab) and
/// standalone [LibraryFolderBrowserScreen].
class LibraryFolderBrowserWidget extends ConsumerStatefulWidget {
  final String? initialPath;
  final ValueChanged<String>? onPathChanged;
  final bool isTab;
  final VoidCallback? onBackToLibrary;

  const LibraryFolderBrowserWidget({
    super.key,
    this.initialPath,
    this.onPathChanged,
    this.isTab = true,
    this.onBackToLibrary,
  });

  @override
  ConsumerState<LibraryFolderBrowserWidget> createState() =>
      _LibraryFolderBrowserWidgetState();
}

class _LibraryFolderBrowserWidgetState
    extends ConsumerState<LibraryFolderBrowserWidget> {
  late String? _currentPath;
  final List<String> _pathHistory = [];
  final TextEditingController _searchController = TextEditingController();
  final FocusNode _searchFocusNode = FocusNode();
  String _searchQuery = '';
  bool _isSearching = false;

  @override
  void initState() {
    super.initState();
    _currentPath = widget.initialPath;
  }

  @override
  void didUpdateWidget(covariant LibraryFolderBrowserWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.initialPath != oldWidget.initialPath &&
        widget.initialPath != _currentPath) {
      _currentPath = widget.initialPath;
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    _searchFocusNode.dispose();
    super.dispose();
  }

  void _navigateTo(String path) {
    _pathHistory.add(_currentPath ?? '');
    setState(() {
      _currentPath = path;
      _searchQuery = '';
      _searchController.clear();
      _isSearching = false;
    });
    widget.onPathChanged?.call(path);
  }

  void _navigateUp(LibraryFolderTree tree) {
    if (_pathHistory.isNotEmpty) {
      final prev = _pathHistory.removeLast();
      setState(() {
        _currentPath = prev;
        _searchQuery = '';
        _searchController.clear();
        _isSearching = false;
      });
      widget.onPathChanged?.call(prev);
    } else if (_currentPath != null && _currentPath!.isNotEmpty) {
      final node = tree.resolveNode(_currentPath);
      final parent = node.parentPath ?? '';
      setState(() {
        _currentPath = parent;
        _searchQuery = '';
        _searchController.clear();
        _isSearching = false;
      });
      widget.onPathChanged?.call(parent);
    } else {
      widget.onBackToLibrary?.call();
    }
  }

  void _jumpToBreadcrumb(LibraryFolderNode target) {
    if (target.path == (_currentPath ?? '')) return;
    _pathHistory.add(_currentPath ?? '');
    setState(() {
      _currentPath = target.path;
      _searchQuery = '';
      _searchController.clear();
      _isSearching = false;
    });
    widget.onPathChanged?.call(target.path);
  }

  PlayableMedia _toPlayableMedia(UnifiedLibraryItem item) {
    final history = item.historyItem;
    if (history != null) return playableFromHistory(history);
    final local = item.localItem;
    if (local != null) return playableFromLocal(local);

    final cover = item.coverUrl ?? item.localCoverPath ?? '';
    String? art;
    if (cover.isNotEmpty) {
      art =
          (cover.startsWith('http') ||
              cover.startsWith('content://') ||
              cover.startsWith('file://'))
          ? cover
          : Uri.file(cover).toString();
    }
    return PlayableMedia(
      id: item.id,
      source: item.filePath,
      title: item.trackName,
      artist: item.artistName,
      album: item.albumName,
      artUri: art,
    );
  }

  Future<void> _playAll(
    List<UnifiedLibraryItem> tracks, {
    bool shuffle = false,
  }) async {
    final playable = tracks
        .where(
          (t) => t.filePath.trim().isNotEmpty && !isCueVirtualPath(t.filePath),
        )
        .toList();
    if (playable.isEmpty) return;

    final queue = shuffle
        ? (List<UnifiedLibraryItem>.from(playable)..shuffle())
        : playable;

    try {
      await ref
          .read(playbackProvider.notifier)
          .playMediaQueue(
            queue.map(_toPlayableMedia),
            startIndex: 0,
            externalPath: queue.first.filePath,
          );
    } catch (e) {
      if (mounted) showCannotOpenFileSnackBar(context, e);
    }
  }

  Future<void> _playTrack(
    UnifiedLibraryItem track,
    List<UnifiedLibraryItem> trackList,
  ) async {
    final playable = trackList
        .where(
          (t) => t.filePath.trim().isNotEmpty && !isCueVirtualPath(t.filePath),
        )
        .toList();
    if (playable.isEmpty) return;

    var start = playable.indexWhere((t) => t.id == track.id);
    if (start < 0) start = 0;

    try {
      await ref
          .read(playbackProvider.notifier)
          .playMediaQueue(
            playable.map(_toPlayableMedia),
            startIndex: start,
            externalPath: track.filePath,
          );
    } catch (e) {
      if (mounted) showCannotOpenFileSnackBar(context, e);
    }
  }

  void _showTrackMenu(
    BuildContext context,
    UnifiedLibraryItem track,
    List<UnifiedLibraryItem> trackList,
    Offset? position,
  ) {
    if (isDesktopPlatform && position != null) {
      showContextMenu(
        context,
        position: position,
        groups: [
          [
            ContextMenuAction(
              icon: Icons.play_arrow,
              label: context.l10n.tooltipPlay,
              onSelected: () => _playTrack(track, trackList),
            ),
            ContextMenuAction(
              icon: Icons.playlist_add,
              label: context.l10n.trackPlayNext,
              onSelected: () => ref
                  .read(musicPlayerControllerProvider)
                  .playNext(_toPlayableMedia(track)),
            ),
            ContextMenuAction(
              icon: Icons.queue_music,
              label: context.l10n.trackAddToQueue,
              onSelected: () => ref
                  .read(musicPlayerControllerProvider)
                  .addToQueue(_toPlayableMedia(track)),
            ),
          ],
          [
            ContextMenuAction(
              icon: Icons.playlist_add,
              label: context.l10n.collectionAddToPlaylist,
              onSelected: () =>
                  showAddTracksToPlaylistSheet(context, ref, [track.toTrack()]),
            ),
            ContextMenuAction(
              icon: Icons.info_outline,
              label: context.l10n.desktopMenuShowDetails,
              onSelected: () => Navigator.of(context).push(
                slidePageRoute<void>(
                  page: TrackMetadataScreen(
                    item: track.historyItem,
                    localItem: track.localItem,
                  ),
                ),
              ),
            ),
          ],
        ],
      );
      return;
    }

    showAppModalBottomSheet<void>(
      context: context,
      useRootNavigator: true,
      builder: (sheetContext) => AppBottomSheet(
        title: track.trackName,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const AppIcon(Icons.play_arrow),
              title: Text(sheetContext.l10n.tooltipPlay),
              onTap: () {
                Navigator.pop(sheetContext);
                _playTrack(track, trackList);
              },
            ),
            ListTile(
              leading: const AppIcon(Icons.playlist_add),
              title: Text(sheetContext.l10n.trackPlayNext),
              onTap: () {
                Navigator.pop(sheetContext);
                ref
                    .read(musicPlayerControllerProvider)
                    .playNext(_toPlayableMedia(track));
              },
            ),
            ListTile(
              leading: const AppIcon(Icons.queue_music),
              title: Text(sheetContext.l10n.trackAddToQueue),
              onTap: () {
                Navigator.pop(sheetContext);
                ref
                    .read(musicPlayerControllerProvider)
                    .addToQueue(_toPlayableMedia(track));
              },
            ),
            ListTile(
              leading: const AppIcon(Icons.playlist_add),
              title: Text(sheetContext.l10n.collectionAddToPlaylist),
              onTap: () {
                Navigator.pop(sheetContext);
                showAddTracksToPlaylistSheet(context, ref, [track.toTrack()]);
              },
            ),
            ListTile(
              leading: const AppIcon(Icons.info_outline),
              title: Text(sheetContext.l10n.desktopMenuShowDetails),
              onTap: () {
                Navigator.pop(sheetContext);
                Navigator.of(context).push(
                  slidePageRoute<void>(
                    page: TrackMetadataScreen(
                      item: track.historyItem,
                      localItem: track.localItem,
                    ),
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCoverArtwork(
    UnifiedLibraryItem item,
    ColorScheme colorScheme,
    double size,
  ) {
    final fallback = SizedBox.square(
      dimension: size,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(size * 0.2),
        child: ColoredBox(
          color: colorScheme.surfaceContainerHighest,
          child: Icon(
            Icons.music_note,
            size: size * 0.5,
            color: colorScheme.onSurfaceVariant,
          ),
        ),
      ),
    );

    final coverUrl = item.coverUrl?.trim();
    if (coverUrl != null && coverUrl.isNotEmpty) {
      return SizedBox.square(
        dimension: size,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(size * 0.2),
          child: CachedCoverImage(
            imageUrl: coverUrl,
            width: size,
            height: size,
            errorWidget: (_, _, _) => fallback,
          ),
        ),
      );
    }

    final localCover = item.localCoverPath?.trim();
    if (localCover != null && localCover.isNotEmpty) {
      final file = File(localCover);
      return SizedBox.square(
        dimension: size,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(size * 0.2),
          child: Image.file(
            file,
            width: size,
            height: size,
            fit: BoxFit.cover,
            errorBuilder: (_, _, _) => fallback,
          ),
        ),
      );
    }

    return fallback;
  }

  @override
  Widget build(BuildContext context) {
    final treeAsync = ref.watch(libraryFolderTreeProvider);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final isRoot = _currentPath == null || _currentPath!.isEmpty;

    return PopScope(
      canPop: isRoot && _pathHistory.isEmpty,
      onPopInvokedWithResult: (didPop, result) {
        if (!didPop) {
          final tree = treeAsync.asData?.value;
          if (tree != null) {
            _navigateUp(tree);
          }
        }
      },
      child: treeAsync.when(
        loading: () => const Center(child: AppLoadingIndicator()),
        error: (err, stack) => Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.folder_off_outlined,
                  size: 48,
                  color: colorScheme.error,
                ),
                const SizedBox(height: 16),
                Text(
                  err.toString(),
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: colorScheme.error,
                  ),
                ),
                const SizedBox(height: 16),
                ExpressiveButton(
                  onPressed: () => ref.invalidate(libraryFolderTreeProvider),
                  child: Text(context.l10n.dialogRetry),
                ),
              ],
            ),
          ),
        ),
        data: (tree) => _buildFolderView(context, tree, theme, colorScheme),
      ),
    );
  }

  Widget _buildFolderView(
    BuildContext context,
    LibraryFolderTree tree,
    ThemeData theme,
    ColorScheme colorScheme,
  ) {
    final l10n = context.l10n;
    final isRoot = _currentPath == null || _currentPath!.isEmpty;
    final currentNode = tree.resolveNode(_currentPath);
    final breadcrumbs = tree.getBreadcrumbs(_currentPath);
    final listInset = wideListInset(context);

    // Filter subfolders and direct tracks if search query active
    final query = _searchQuery.toLowerCase().trim();
    final List<LibraryFolderNode> subfolders;
    final List<UnifiedLibraryItem> directTracks;

    if (query.isEmpty) {
      subfolders = isRoot ? tree.rootFolders : currentNode.subfolders;
      directTracks = isRoot ? const [] : currentNode.directTracks;
    } else {
      final rawFolders = isRoot ? tree.rootFolders : currentNode.subfolders;
      subfolders = rawFolders
          .where((f) => f.name.toLowerCase().contains(query))
          .toList(growable: false);
      final rawTracks = isRoot
          ? const <UnifiedLibraryItem>[]
          : currentNode.directTracks;
      directTracks = rawTracks
          .where(
            (t) =>
                t.trackName.toLowerCase().contains(query) ||
                t.artistName.toLowerCase().contains(query) ||
                t.albumName.toLowerCase().contains(query),
          )
          .toList(growable: false);
    }

    final totalFolderTracks = isRoot
        ? tree.root.totalTrackCount
        : currentNode.totalTrackCount;

    return CustomScrollView(
      slivers: [
        // Navigation header / Breadcrumbs & Search
        SliverToBoxAdapter(
          child: Padding(
            padding: EdgeInsets.fromLTRB(16 + listInset, 8, 16 + listInset, 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (!isRoot) ...[
                  // Back button and current folder name
                  Row(
                    children: [
                      AppIconButton(
                        icon: const Icon(Icons.arrow_back),
                        onPressed: () => _navigateUp(tree),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          currentNode.name,
                          style: theme.textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      IconButton(
                        icon: Icon(_isSearching ? Icons.close : Icons.search),
                        tooltip: l10n.librarySearchHint,
                        onPressed: () {
                          setState(() {
                            _isSearching = !_isSearching;
                            if (!_isSearching) {
                              _searchQuery = '';
                              _searchController.clear();
                            }
                          });
                        },
                      ),
                    ],
                  ),
                  // Breadcrumb trail
                  if (breadcrumbs.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4, bottom: 4),
                      child: SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: Row(
                          children: [
                            InkWell(
                              borderRadius: BorderRadius.circular(8),
                              onTap: () => _jumpToBreadcrumb(tree.root),
                              child: Padding(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 6,
                                  vertical: 4,
                                ),
                                child: Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Icon(
                                      Icons.home_outlined,
                                      size: 16,
                                      color: colorScheme.primary,
                                    ),
                                    const SizedBox(width: 4),
                                    Text(
                                      l10n.libraryFolders,
                                      style: theme.textTheme.bodySmall
                                          ?.copyWith(
                                            color: colorScheme.primary,
                                            fontWeight: FontWeight.w600,
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                            for (var i = 0; i < breadcrumbs.length; i++) ...[
                              Icon(
                                Icons.chevron_right,
                                size: 16,
                                color: colorScheme.onSurfaceVariant.withValues(
                                  alpha: 0.6,
                                ),
                              ),
                              InkWell(
                                borderRadius: BorderRadius.circular(8),
                                onTap: i == breadcrumbs.length - 1
                                    ? null
                                    : () => _jumpToBreadcrumb(breadcrumbs[i]),
                                child: Padding(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 6,
                                    vertical: 4,
                                  ),
                                  child: Text(
                                    breadcrumbs[i].name,
                                    style: theme.textTheme.bodySmall?.copyWith(
                                      color: i == breadcrumbs.length - 1
                                          ? colorScheme.onSurface
                                          : colorScheme.primary,
                                      fontWeight: i == breadcrumbs.length - 1
                                          ? FontWeight.bold
                                          : FontWeight.w500,
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                ] else ...[
                  // Root header row
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        l10n.libraryFolders,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                          color: colorScheme.onSurfaceVariant,
                        ),
                      ),
                      IconButton(
                        icon: Icon(_isSearching ? Icons.close : Icons.search),
                        tooltip: l10n.librarySearchHint,
                        onPressed: () {
                          setState(() {
                            _isSearching = !_isSearching;
                            if (!_isSearching) {
                              _searchQuery = '';
                              _searchController.clear();
                            }
                          });
                        },
                      ),
                    ],
                  ),
                ],

                // Search field (if expanded)
                if (_isSearching)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: AppSearchField(
                      controller: _searchController,
                      focusNode: _searchFocusNode,
                      autofocus: true,
                      hintText: l10n.searchFolders,
                      clearTooltip: l10n.dialogClear,
                      onChanged: (val) {
                        setState(() {
                          _searchQuery = val;
                        });
                      },
                      onClear: () {
                        setState(() {
                          _searchQuery = '';
                          _searchController.clear();
                        });
                      },
                    ),
                  ),

                // Action buttons: Play All / Shuffle & Track count
                if (totalFolderTracks > 0)
                  Padding(
                    padding: const EdgeInsets.only(top: 8, bottom: 4),
                    child: Row(
                      children: [
                        FilledButton.tonalIcon(
                          icon: const Icon(Icons.play_arrow_rounded, size: 20),
                          label: Text(l10n.tooltipPlay),
                          onPressed: () => _playAll(currentNode.allTracks),
                        ),
                        const SizedBox(width: 8),
                        OutlinedButton.icon(
                          icon: const Icon(Icons.shuffle_rounded, size: 18),
                          label: Text(l10n.actionShuffle),
                          onPressed: () =>
                              _playAll(currentNode.allTracks, shuffle: true),
                        ),
                        const Spacer(),
                        Text(
                          l10n.libraryFolderSongsCount(totalFolderTracks),
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ),

        // Empty state
        if (subfolders.isEmpty && directTracks.isEmpty)
          SliverFillRemaining(
            hasScrollBody: false,
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      _searchQuery.isNotEmpty
                          ? Icons.search_off
                          : Icons.folder_open_outlined,
                      size: 64,
                      color: colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.5,
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      _searchQuery.isNotEmpty
                          ? l10n.searchEmptyResultSubtitle
                          : l10n.libraryNoFolders,
                      textAlign: TextAlign.center,
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          )
        else ...[
          // Subfolders Section
          if (subfolders.isNotEmpty) ...[
            if (directTracks.isNotEmpty)
              SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.fromLTRB(
                    20 + listInset,
                    12,
                    20 + listInset,
                    6,
                  ),
                  child: Text(
                    l10n.libraryFolderSubfoldersCount(subfolders.length),
                    style: theme.textTheme.labelLarge?.copyWith(
                      color: colorScheme.primary,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
            SliverPadding(
              padding: EdgeInsets.symmetric(horizontal: 16 + listInset),
              sliver: SliverList.builder(
                itemCount: subfolders.length,
                itemBuilder: (context, index) {
                  final folder = subfolders[index];
                  final isFirst = index == 0;
                  final isLast = index == subfolders.length - 1;

                  return Padding(
                    padding: EdgeInsets.only(
                      bottom: isLast ? 8 : 4,
                      top: isFirst ? 4 : 0,
                    ),
                    child: Material(
                      color: context.isMornye
                          ? settingsGroupColor(context)
                          : colorScheme.surfaceContainerLow,
                      borderRadius: BorderRadius.circular(12),
                      clipBehavior: Clip.antiAlias,
                      child: InkWell(
                        onTap: () => _navigateTo(folder.path),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 16,
                            vertical: 12,
                          ),
                          child: Row(
                            children: [
                              Container(
                                width: 44,
                                height: 44,
                                decoration: BoxDecoration(
                                  color: colorScheme.primaryContainer
                                      .withValues(alpha: 0.7),
                                  borderRadius: BorderRadius.circular(10),
                                ),
                                child: Icon(
                                  folder.subfolders.isNotEmpty
                                      ? Icons.folder_copy_outlined
                                      : Icons.folder_outlined,
                                  color: colorScheme.primary,
                                  size: 24,
                                ),
                              ),
                              const SizedBox(width: 16),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      folder.name,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: theme.textTheme.bodyLarge
                                          ?.copyWith(
                                            fontWeight: FontWeight.w600,
                                          ),
                                    ),
                                    const SizedBox(height: 2),
                                    Text(
                                      folder.subfolders.isNotEmpty &&
                                              folder.directTracks.isNotEmpty
                                          ? '${l10n.libraryFolderSubfoldersCount(folder.subfolders.length)}, ${l10n.libraryFolderSongsCount(folder.totalTrackCount)}'
                                          : l10n.libraryFolderSongsCount(
                                              folder.totalTrackCount,
                                            ),
                                      style: theme.textTheme.bodySmall
                                          ?.copyWith(
                                            color: colorScheme.onSurfaceVariant,
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                              if (folder.totalTrackCount > 0)
                                IconButton(
                                  icon: const Icon(Icons.play_circle_outline),
                                  tooltip: l10n.tooltipPlay,
                                  color: colorScheme.primary,
                                  onPressed: () => _playAll(folder.allTracks),
                                ),
                              Icon(
                                Icons.chevron_right,
                                color: colorScheme.onSurfaceVariant,
                                size: 20,
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
          ],

          // Direct Tracks Section
          if (directTracks.isNotEmpty) ...[
            if (subfolders.isNotEmpty)
              SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.fromLTRB(
                    20 + listInset,
                    16,
                    20 + listInset,
                    6,
                  ),
                  child: Text(
                    l10n.libraryFolderSongsCount(directTracks.length),
                    style: theme.textTheme.labelLarge?.copyWith(
                      color: colorScheme.primary,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
            SliverPadding(
              padding: EdgeInsets.symmetric(horizontal: 16 + listInset),
              sliver: SliverList.builder(
                itemCount: directTracks.length,
                itemBuilder: (context, index) {
                  final track = directTracks[index];
                  final playbackKey = (id: track.id, path: track.filePath);

                  return Consumer(
                    builder: (context, ref, _) {
                      final playback = ref.watch(
                        mediaItemPlaybackUiProvider(playbackKey),
                      );

                      return TrackCard(
                        style: TrackCardStyle.filled,
                        isCurrent: playback.isCurrent,
                        isPlaying: playback.isPlaying,
                        leadingArtwork: true,
                        leading: _buildCoverArtwork(track, colorScheme, 48),
                        title: track.trackName,
                        subtitle: Row(
                          children: [
                            Expanded(
                              child: Text(
                                track.artistName.isNotEmpty
                                    ? '${track.artistName} • ${track.albumName}'
                                    : track.albumName,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ),
                          ],
                        ),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              icon: Icon(
                                playback.isPlaying
                                    ? Icons.pause_circle_filled
                                    : playback.isCurrent
                                    ? Icons.play_circle_filled
                                    : Icons.play_circle_outline,
                                color: playback.isCurrent
                                    ? colorScheme.primary
                                    : colorScheme.onSurfaceVariant,
                              ),
                              tooltip: l10n.tooltipPlay,
                              onPressed: () => _playTrack(track, directTracks),
                            ),
                            IconButton(
                              icon: const Icon(Icons.more_vert, size: 20),
                              color: colorScheme.onSurfaceVariant,
                              onPressed: () => _showTrackMenu(
                                context,
                                track,
                                directTracks,
                                null,
                              ),
                            ),
                          ],
                        ),
                        onTap: () => _playTrack(track, directTracks),
                        onContextMenu: (pos) =>
                            _showTrackMenu(context, track, directTracks, pos),
                      );
                    },
                  );
                },
              ),
            ),
          ],
        ],

        const NavBarSliverSpacer(),
      ],
    );
  }
}
