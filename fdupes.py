#!/usr/bin/env python3
"""
fdupes - Find duplicate files in a directory tree.

Uses a multi-phase approach:
1. Group files by size (drop unique sizes)
2. Within same-size groups: hash first 4KB (drop unique partial hashes)
3. Within same partial-hash groups: hash entire file (drop unique full hashes)
4. Output groups of duplicate files
"""

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Size of initial chunk to hash (4KB)
PARTIAL_HASH_SIZE = 4 * 1024

# Size unit multipliers
SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def _parse_size(s: str) -> int:
    """Parse human-readable size (e.g. 1K, 10M, 1G) to bytes."""
    s = s.strip().lower().rstrip("b")
    if not s:
        raise ValueError("Empty size")
    # Find trailing unit
    for unit in ("k", "m", "g", "t"):
        if s.endswith(unit):
            try:
                return int(float(s[:-1]) * SIZE_UNITS[unit])
            except ValueError:
                raise ValueError(f"Invalid size: {s}")
    try:
        return int(float(s))
    except ValueError:
        raise ValueError(f"Invalid size: {s}")


def _matches_any(name: str, patterns: list[str]) -> bool:
    """Return True if name matches any fnmatch pattern."""
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def _load_exclude_file(filepath: Path) -> list[str]:
    """Load exclude patterns from file (one per line, # for comments)."""
    patterns = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    patterns.append(line)
    except OSError as e:
        print(f"Warning: Cannot read exclude file '{filepath}': {e}", file=sys.stderr)
    return patterns


def walk_files(
    root: Path,
    exclude_patterns: list[str] | None = None,
    ignore_empty: bool = False,
    min_depth: int | None = None,
    max_depth: int | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
):
    """Yield (path, size) for each regular file under root."""
    root = root.resolve()
    exclude_patterns = exclude_patterns or []
    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirpath_resolved = Path(dirpath).resolve()
            if dirpath_resolved == root:
                depth = 0
            else:
                try:
                    depth = len(dirpath_resolved.relative_to(root).parts)
                except ValueError:
                    depth = 0

            # Respect max_depth: don't descend past it
            if max_depth is not None and depth >= max_depth:
                dirnames.clear()
                dirnames[:] = []

            # Don't descend into excluded directories
            dirnames[:] = [
                d for d in dirnames
                if not _matches_any(d, exclude_patterns)
            ]

            # File depth is same as parent dir (or depth+1 depending on definition)
            # We use: root=depth 0, files in root=depth 0, subdir=depth 1, files in subdir=depth 1
            file_depth = depth

            for name in filenames:
                if exclude_patterns and _matches_any(name, exclude_patterns):
                    continue
                if min_depth is not None and file_depth < min_depth:
                    continue
                if max_depth is not None and file_depth > max_depth:
                    continue
                path = Path(dirpath) / name
                if path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                    if stat.st_mode & 0o170000 == 0o100000:  # S_ISREG
                        size = stat.st_size
                        if ignore_empty and size == 0:
                            continue
                        if min_size is not None and size < min_size:
                            continue
                        if max_size is not None and size > max_size:
                            continue
                        yield path, size
                except OSError:
                    pass  # Skip files we can't stat
    except OSError as e:
        print(f"Error walking directory: {e}", file=sys.stderr)
        sys.exit(1)


def partial_hash(path: Path, size: int) -> str | None:
    """Hash first 4KB of file. Returns None on read error."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(min(PARTIAL_HASH_SIZE, size))
        return hashlib.sha256(chunk).hexdigest()
    except OSError:
        return None


def full_hash(path: Path, size: int) -> str | None:
    """Hash entire file in chunks. Returns None on read error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(64 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def find_duplicates(
    root: Path,
    exclude_patterns: list[str] | None = None,
    ignore_empty: bool = False,
    min_depth: int | None = None,
    max_depth: int | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    jobs: int = 1,
) -> list[list[Path]]:
    """Find groups of duplicate files under root."""
    # Phase 1: Collect files by size
    size_to_paths: dict[int, list[Path]] = defaultdict(list)
    for path, size in walk_files(
        root,
        exclude_patterns=exclude_patterns,
        ignore_empty=ignore_empty,
        min_depth=min_depth,
        max_depth=max_depth,
        min_size=min_size,
        max_size=max_size,
    ):
        size_to_paths[size].append(path)

    # Drop sizes with only one file
    size_groups = [
        (size, paths)
        for size, paths in size_to_paths.items()
        if len(paths) > 1
    ]

    duplicate_groups: list[list[Path]] = []
    use_parallel = jobs > 1

    for size, paths in size_groups:
        # Phase 2: Hash first 4KB, group by partial hash
        partial_to_paths: dict[str, list[Path]] = defaultdict(list)
        if use_parallel:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {executor.submit(partial_hash, p, size): p for p in paths}
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        ph = future.result()
                        if ph is not None:
                            partial_to_paths[ph].append(path)
                    except Exception:
                        pass
        else:
            for path in paths:
                ph = partial_hash(path, size)
                if ph is not None:
                    partial_to_paths[ph].append(path)

        for partial_paths in partial_to_paths.values():
            if len(partial_paths) < 2:
                continue

            # Phase 3: Full file hash for candidates with same first 4KB
            full_to_paths: dict[str, list[Path]] = defaultdict(list)
            if use_parallel:
                with ThreadPoolExecutor(max_workers=jobs) as executor:
                    futures = {executor.submit(full_hash, p, size): p for p in partial_paths}
                    for future in as_completed(futures):
                        path = futures[future]
                        try:
                            fh = future.result()
                            if fh is not None:
                                full_to_paths[fh].append(path)
                        except Exception:
                            pass
            else:
                for path in partial_paths:
                    fh = full_hash(path, size)
                    if fh is not None:
                        full_to_paths[fh].append(path)

            for full_paths in full_to_paths.values():
                if len(full_paths) > 1:
                    duplicate_groups.append(sorted(full_paths))

    return duplicate_groups


def compute_stats(groups: list[list[Path]]) -> dict:
    """Compute statistics for duplicate groups."""
    total_groups = len(groups)
    total_duplicate_files = sum(len(g) for g in groups)
    # Wasted space = for each group, (count-1) * size (we keep one copy)
    total_wasted_bytes = 0
    for group in groups:
        try:
            size = group[0].stat().st_size
            total_wasted_bytes += (len(group) - 1) * size
        except OSError:
            pass
    return {
        "duplicate_groups": total_groups,
        "duplicate_files": total_duplicate_files,
        "wasted_bytes": total_wasted_bytes,
    }


def _format_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def main():
    parser = argparse.ArgumentParser(
        description="Find duplicate files in a directory tree.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=Path("."),
        help="Directory to search (default: current directory)",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Exclude files and directories matching pattern (shell-style: *, ?, []; can be specified multiple times)",
    )
    parser.add_argument(
        "--exclude-from",
        type=Path,
        metavar="FILE",
        help="Read exclude patterns from file (one per line, # for comments)",
    )
    parser.add_argument(
        "-z",
        "--ignore-empty",
        action="store_true",
        help="Ignore zero-length (empty) files",
    )
    parser.add_argument(
        "--min-depth",
        type=int,
        default=None,
        metavar="N",
        help="Do not consider files at depth less than N (0 = root)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        metavar="N",
        help="Do not descend past depth N (0 = root only)",
    )
    parser.add_argument(
        "--min-size",
        type=str,
        default=None,
        metavar="SIZE",
        help="Exclude files smaller than SIZE (e.g. 1K, 10M, 1G)",
    )
    parser.add_argument(
        "--max-size",
        type=str,
        default=None,
        metavar="SIZE",
        help="Exclude files larger than SIZE (e.g. 1K, 10M, 1G)",
    )
    parser.add_argument(
        "--no-recurse",
        action="store_true",
        help="Do not recurse into subdirectories",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel hashing jobs (default: 1)",
    )
    parser.add_argument(
        "-s",
        "--stats",
        action="store_true",
        help="Print statistics after listing duplicates",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: text or json (default: text)",
    )
    args = parser.parse_args()

    root = args.directory.resolve()
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory", file=sys.stderr)
        sys.exit(1)

    # Combine exclude patterns from -x and --exclude-from
    exclude_patterns = list(args.exclude)
    if args.exclude_from:
        exclude_patterns.extend(_load_exclude_file(args.exclude_from))

    # Parse size arguments
    min_size = None
    max_size = None
    if args.min_size:
        try:
            min_size = _parse_size(args.min_size)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    if args.max_size:
        try:
            max_size = _parse_size(args.max_size)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    max_depth = args.max_depth
    if args.no_recurse:
        max_depth = 0

    groups = find_duplicates(
        root,
        exclude_patterns=exclude_patterns,
        ignore_empty=args.ignore_empty,
        min_depth=args.min_depth,
        max_depth=max_depth,
        min_size=min_size,
        max_size=max_size,
        jobs=max(1, args.jobs),
    )

    if args.format == "json":
        stats = compute_stats(groups)
        output = {
            "duplicates": [[str(p) for p in group] for group in groups],
            "stats": stats,
        }
        print(json.dumps(output, indent=2))
    else:
        for group in groups:
            for path in group:
                print(path)
            print()

        if args.stats:
            stats = compute_stats(groups)
            print(f"Duplicate groups: {stats['duplicate_groups']}")
            print(f"Duplicate files: {stats['duplicate_files']}")
            print(f"Wasted space: {_format_bytes(stats['wasted_bytes'])}")


if __name__ == "__main__":
    main()
