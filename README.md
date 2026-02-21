# fdupes

## Overview

Find duplicate files in a directory tree (Python 3 and C++17 implementations).

I wrote a simler version of this in C many years ago. I turned it over to Cursor to update it to Python and modern C++. I also had Cursor add some additional features. So, I can't take credit for all of the code, just the basic algorithm.

## Algorithm

1. Group files by size (drop unique sizes)
2. Within same-size groups: hash first 4KB with SHA-256 (drop unique partial hashes)
3. Within same partial-hash groups: hash entire file with SHA-256
4. Output groups of duplicate files

## Python version

```bash
python3 fdupes.py [options]
```

Requires Python 3.9+ (for `list[...]` type hints; works with 3.7+ if you change those to `List` from `typing`).

## C++ version

### Build

Requires C++17, CMake 3.16+, and OpenSSL (libcrypto).

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
./fdupes [options]
```

On macOS with Homebrew: `brew install openssl` (usually already present). On Linux install `libssl-dev` (or equivalent).

### Platform

The C++ implementation uses `std::filesystem` and POSIX `fnmatch()` for pattern matching. On Windows, a minimal glob matcher is used (no `fnmatch`); full Windows support may require path and API adjustments.

## Options (both versions)

| Option                    | Description                                        |
| ------------------------- | -------------------------------------------------- |
| `-d`, `--directory DIR`   | Directory to search (default: current)             |
| `-x`, `--exclude PATTERN` | Exclude files/dirs matching pattern (repeatable)   |
| `--exclude-from FILE`     | Read exclude patterns from file (`#` = comment)    |
| `-z`, `--ignore-empty`    | Ignore zero-length files                           |
| `--min-depth N`           | Do not consider files at depth &lt; N              |
| `--max-depth N`           | Do not descend past depth N (0 = root only)        |
| `--min-size SIZE`         | Exclude files smaller than SIZE (e.g. 1K, 10M, 1G) |
| `--max-size SIZE`         | Exclude files larger than SIZE                     |
| `--no-recurse`            | Do not recurse into subdirectories                 |
| `-j`, `--jobs N`          | Parallel hashing jobs (default: 1)                 |
| `-s`, `--stats`           | Print duplicate counts and wasted space            |
| `-f`, `--format FORMAT`   | Output: `text` or `json` (default: text)           |
