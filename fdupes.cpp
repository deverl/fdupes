// fdupes - Find duplicate files in a directory tree (C++17)
// Same functionality as the Python version: size -> partial hash (4KB) -> full SHA-256.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef __has_include
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif
#else
#include <filesystem>
namespace fs = std::filesystem;
#endif

#if defined(_WIN32) || defined(_WIN64)
// Minimal glob match for Windows (no fnmatch)
static bool fnmatch(const char* pattern, const char* name) {
  while (*pattern && *name) {
    if (*pattern == '*') {
      if (fnmatch(pattern + 1, name)) return true;
      ++name;
      continue;
    }
    if (*pattern == '?' || *pattern == *name) {
      ++pattern;
      ++name;
      continue;
    }
    return false;
  }
  while (*pattern == '*') ++pattern;
  return !*pattern && !*name;
}
#else
#include <fnmatch.h>
static bool fnmatch(const char* pattern, const char* name) {
  return ::fnmatch(pattern, name, FNM_PATHNAME) == 0;
}
#endif

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace {

constexpr size_t kPartialHashSize = 4 * 1024;
constexpr size_t kChunkSize = 64 * 1024;

// --- Size parsing (1K, 10M, 1G) ---
std::optional<int64_t> parse_size(const std::string& s) {
  if (s.empty()) return std::nullopt;
  std::string t;
  for (char c : s) {
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    t += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  if (t.empty()) return std::nullopt;
  while (!t.empty() && t.back() == 'b') t.pop_back();
  if (t.empty()) return std::nullopt;

  int64_t mult = 1;
  if (t.size() >= 1) {
    switch (t.back()) {
      case 'k': mult = 1024; t.pop_back(); break;
      case 'm': mult = 1024LL * 1024; t.pop_back(); break;
      case 'g': mult = 1024LL * 1024 * 1024; t.pop_back(); break;
      case 't': mult = 1024LL * 1024 * 1024 * 1024; t.pop_back(); break;
      default: break;
    }
  }
  double num = 0;
  try {
    num = std::stod(t);
  } catch (...) {
    return std::nullopt;
  }
  return static_cast<int64_t>(num * mult);
}

// --- Pattern matching ---
bool matches_any(const std::string& name, const std::vector<std::string>& patterns) {
  for (const auto& p : patterns) {
    if (fnmatch(p.c_str(), name.c_str())) return true;
  }
  return false;
}

// --- Load exclude-from file ---
std::vector<std::string> load_exclude_file(const fs::path& filepath) {
  std::vector<std::string> patterns;
  std::ifstream f(filepath);
  if (!f) {
    std::cerr << "Warning: Cannot read exclude file '" << filepath.string() << "'\n";
    return patterns;
  }
  std::string line;
  while (std::getline(f, line)) {
    auto pos = line.find('#');
    if (pos != std::string::npos) line.resize(pos);
    // trim
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) continue;
    size_t end = line.find_last_not_of(" \t\r\n");
    line = line.substr(start, end == std::string::npos ? std::string::npos : end - start + 1);
    if (!line.empty()) patterns.push_back(std::move(line));
  }
  return patterns;
}

// --- SHA-256 helpers ---
std::string sha256_hex(const void* data, size_t len) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(static_cast<const unsigned char*>(data), len, hash);
  std::string result;
  result.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char c : hash) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", c);
    result += buf;
  }
  return result;
}

std::optional<std::string> partial_hash(const fs::path& path, int64_t size) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;
  size_t to_read = static_cast<size_t>(std::min(static_cast<int64_t>(kPartialHashSize), size));
  std::vector<char> buf(to_read);
  if (!f.read(buf.data(), static_cast<std::streamsize>(to_read))) return std::nullopt;
  return sha256_hex(buf.data(), f.gcount() > 0 ? static_cast<size_t>(f.gcount()) : to_read);
}

std::optional<std::string> full_hash(const fs::path& path, int64_t /*size*/) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return std::nullopt;
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }
  std::vector<char> buf(kChunkSize);
  while (f.read(buf.data(), static_cast<std::streamsize>(buf.size())) || f.gcount() > 0) {
    auto n = static_cast<size_t>(f.gcount());
    if (EVP_DigestUpdate(ctx, buf.data(), n) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::nullopt;
    }
    if (f.gcount() < static_cast<std::streamsize>(buf.size())) break;
  }
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }
  EVP_MD_CTX_free(ctx);
  std::string result;
  result.reserve(hash_len * 2);
  for (unsigned int i = 0; i < hash_len; ++i) {
    char b[3];
    std::snprintf(b, sizeof(b), "%02x", hash[i]);
    result += b;
  }
  return result;
}

// --- Directory walk ---
struct FileEntry {
  fs::path path;
  int64_t size;
};

void walk_files_manual(
    const fs::path& root,
    const fs::path& dir,
    int depth,
    const std::vector<std::string>& exclude_patterns,
    bool ignore_empty,
    std::optional<int> min_depth,
    std::optional<int> max_depth,
    std::optional<int64_t> min_size,
    std::optional<int64_t> max_size,
    std::vector<FileEntry>& out) {
  std::error_code ec;
  for (auto& e : fs::directory_iterator(dir, ec)) {
    if (ec) continue;
    fs::path p = e.path();
    std::string name = p.filename().string();

    if (e.is_directory(ec) && !e.is_symlink(ec)) {
      if (matches_any(name, exclude_patterns)) continue;
      if (max_depth.has_value() && depth >= *max_depth) continue;
      walk_files_manual(root, p, depth + 1, exclude_patterns, ignore_empty,
                        min_depth, max_depth, min_size, max_size, out);
      continue;
    }

    if (e.is_symlink(ec)) continue;
    if (!e.is_regular_file(ec)) continue;
    if (matches_any(name, exclude_patterns)) continue;
    if (min_depth.has_value() && depth < *min_depth) continue;
    if (max_depth.has_value() && depth > *max_depth) continue;

    int64_t size = static_cast<int64_t>(fs::file_size(p, ec));
    if (ec) continue;
    if (ignore_empty && size == 0) continue;
    if (min_size.has_value() && size < *min_size) continue;
    if (max_size.has_value() && size > *max_size) continue;

    out.push_back({fs::absolute(p), size});
  }
}

std::vector<FileEntry> walk_files_with_depth(
    const fs::path& root,
    const std::vector<std::string>& exclude_patterns,
    bool ignore_empty,
    std::optional<int> min_depth,
    std::optional<int> max_depth,
    std::optional<int64_t> min_size,
    std::optional<int64_t> max_size) {
  std::vector<FileEntry> out;
  fs::path root_abs = fs::absolute(root);
  walk_files_manual(root_abs, root_abs, 0, exclude_patterns, ignore_empty,
                    min_depth, max_depth, min_size, max_size, out);
  return out;
}

// --- Find duplicates ---
using Group = std::vector<fs::path>;

std::vector<Group> find_duplicates(
    const fs::path& root,
    const std::vector<std::string>& exclude_patterns,
    bool ignore_empty,
    std::optional<int> min_depth,
    std::optional<int> max_depth,
    std::optional<int64_t> min_size,
    std::optional<int64_t> max_size,
    int jobs) {
  std::vector<FileEntry> entries = walk_files_with_depth(
      root, exclude_patterns, ignore_empty, min_depth, max_depth, min_size, max_size);

  std::unordered_map<int64_t, std::vector<fs::path>> by_size;
  for (auto& e : entries) {
    by_size[e.size].push_back(std::move(e.path));
  }

  std::vector<Group> result;
  const bool use_parallel = jobs > 1;

  for (auto& size_paths : by_size) {
    int64_t file_size = size_paths.first;
    auto& paths = size_paths.second;
    if (paths.size() < 2) continue;

    std::unordered_map<std::string, std::vector<fs::path>> by_partial;
    if (use_parallel) {
      std::vector<std::future<std::pair<fs::path, std::optional<std::string>>>> futures;
      for (const auto& path : paths) {
        int64_t sz = file_size;
        futures.push_back(std::async(std::launch::async, [path, sz]() {
          return std::make_pair(path, partial_hash(path, sz));
        }));
      }
      for (auto& fut : futures) {
        auto [path, ph] = fut.get();
        if (ph) by_partial[*ph].push_back(path);
      }
    } else {
      for (const auto& path : paths) {
        auto ph = partial_hash(path, file_size);
        if (ph) by_partial[*ph].push_back(path);
      }
    }

    for (auto& kv : by_partial) {
      auto& partial_paths = kv.second;
      if (partial_paths.size() < 2) continue;

      std::unordered_map<std::string, std::vector<fs::path>> by_full;
      if (use_parallel) {
        std::vector<std::future<std::pair<fs::path, std::optional<std::string>>>> futures;
        int64_t sz = file_size;
        for (const auto& path : partial_paths) {
          futures.push_back(std::async(std::launch::async, [path, sz]() {
            return std::make_pair(path, full_hash(path, sz));
          }));
        }
        for (auto& fut : futures) {
          auto [path, fh] = fut.get();
          if (fh) by_full[*fh].push_back(path);
        }
      } else {
        for (const auto& path : partial_paths) {
          auto fh = full_hash(path, file_size);
          if (fh) by_full[*fh].push_back(path);
        }
      }

      for (auto& kv : by_full) {
        auto& full_paths = kv.second;
        if (full_paths.size() > 1) {
          std::sort(full_paths.begin(), full_paths.end());
          result.push_back(std::move(full_paths));
        }
      }
    }
  }

  return result;
}

struct Stats {
  size_t duplicate_groups = 0;
  size_t duplicate_files = 0;
  int64_t wasted_bytes = 0;
};

Stats compute_stats(const std::vector<Group>& groups) {
  Stats s;
  s.duplicate_groups = groups.size();
  for (const auto& g : groups) {
    s.duplicate_files += g.size();
    if (!g.empty()) {
      std::error_code ec;
      auto sz = fs::file_size(g[0], ec);
      if (!ec) s.wasted_bytes += static_cast<int64_t>((g.size() - 1) * sz);
    }
  }
  return s;
}

std::string format_bytes(int64_t n) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  int u = 0;
  double v = static_cast<double>(n);
  while (v >= 1024 && u < 4) {
    v /= 1024;
    ++u;
  }
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(1) << v << ' ' << units[u];
  return oss.str();
}

void json_escape(std::ostream& out, const std::string& s) {
  out << '"';
  for (char c : s) {
    if (c == '"') out << "\\\"";
    else if (c == '\\') out << "\\\\";
    else if (c == '\n') out << "\\n";
    else if (c == '\r') out << "\\r";
    else if (c == '\t') out << "\\t";
    else if (static_cast<unsigned char>(c) < 32) out << "\\u" << std::hex << std::setfill('0') << std::setw(4) << static_cast<unsigned>(c) << std::dec;
    else out << c;
  }
  out << '"';
}

}  // namespace

int main(int argc, char* argv[]) {
  std::string directory = ".";
  std::vector<std::string> exclude;
  std::string exclude_from;
  bool ignore_empty = false;
  std::optional<int> min_depth, max_depth;
  std::optional<int64_t> min_size, max_size;
  bool no_recurse = false;
  int jobs = 1;
  bool stats = false;
  std::string format = "text";

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      std::cout << R"(usage: fdupes [-h] [-d DIRECTORY] [-x PATTERN] [--exclude-from FILE] [-z]
                 [--min-depth N] [--max-depth N] [--min-size SIZE]
                 [--max-size SIZE] [--no-recurse] [-j N] [-s] [-f {text,json}]

Find duplicate files in a directory tree.

options:
  -h, --help            show this help message
  -d, --directory DIR   Directory to search (default: current directory)
  -x, --exclude PATTERN Exclude files/dirs matching pattern (can be repeated)
  --exclude-from FILE   Read exclude patterns from file (# = comment)
  -z, --ignore-empty    Ignore zero-length files
  --min-depth N         Do not consider files at depth less than N
  --max-depth N         Do not descend past depth N (0 = root only)
  --min-size SIZE       Exclude files smaller than SIZE (e.g. 1K, 10M, 1G)
  --max-size SIZE       Exclude files larger than SIZE
  --no-recurse          Do not recurse into subdirectories
  -j, --jobs N          Parallel hashing jobs (default: 1)
  -s, --stats           Print statistics after listing
  -f, --format FORMAT   Output format: text or json (default: text)
)";
      return 0;
    }
    if (arg == "-d" || arg == "--directory") {
      if (i + 1 >= argc) { std::cerr << "Error: -d requires an argument\n"; return 1; }
      directory = argv[++i];
      continue;
    }
    if (arg == "-x" || arg == "--exclude") {
      if (i + 1 >= argc) { std::cerr << "Error: -x requires an argument\n"; return 1; }
      exclude.push_back(argv[++i]);
      continue;
    }
    if (arg == "--exclude-from") {
      if (i + 1 >= argc) { std::cerr << "Error: --exclude-from requires an argument\n"; return 1; }
      exclude_from = argv[++i];
      continue;
    }
    if (arg == "-z" || arg == "--ignore-empty") { ignore_empty = true; continue; }
    if (arg == "--min-depth") {
      if (i + 1 >= argc) { std::cerr << "Error: --min-depth requires an argument\n"; return 1; }
      min_depth = std::stoi(argv[++i]);
      continue;
    }
    if (arg == "--max-depth") {
      if (i + 1 >= argc) { std::cerr << "Error: --max-depth requires an argument\n"; return 1; }
      max_depth = std::stoi(argv[++i]);
      continue;
    }
    if (arg == "--min-size") {
      if (i + 1 >= argc) { std::cerr << "Error: --min-size requires an argument\n"; return 1; }
      auto v = parse_size(argv[++i]);
      if (!v) { std::cerr << "Error: Invalid size\n"; return 1; }
      min_size = *v;
      continue;
    }
    if (arg == "--max-size") {
      if (i + 1 >= argc) { std::cerr << "Error: --max-size requires an argument\n"; return 1; }
      auto v = parse_size(argv[++i]);
      if (!v) { std::cerr << "Error: Invalid size\n"; return 1; }
      max_size = *v;
      continue;
    }
    if (arg == "--no-recurse") { no_recurse = true; max_depth = 0; continue; }
    if (arg == "-j" || arg == "--jobs") {
      if (i + 1 >= argc) { std::cerr << "Error: -j requires an argument\n"; return 1; }
      jobs = std::max(1, std::stoi(argv[++i]));
      continue;
    }
    if (arg == "-s" || arg == "--stats") { stats = true; continue; }
    if (arg == "-f" || arg == "--format") {
      if (i + 1 >= argc) { std::cerr << "Error: -f requires an argument\n"; return 1; }
      format = argv[++i];
      if (format != "text" && format != "json") {
        std::cerr << "Error: format must be text or json\n";
        return 1;
      }
      continue;
    }
    std::cerr << "Unknown option: " << arg << '\n';
    return 1;
  }

  fs::path root = fs::absolute(fs::path(directory));
  if (!fs::is_directory(root)) {
    std::cerr << "Error: '" << root.string() << "' is not a directory\n";
    return 1;
  }

  if (!exclude_from.empty()) {
    auto from_file = load_exclude_file(exclude_from);
    exclude.insert(exclude.end(), from_file.begin(), from_file.end());
  }

  auto groups = find_duplicates(root, exclude, ignore_empty, min_depth, max_depth, min_size, max_size, jobs);

  if (format == "json") {
    Stats s = compute_stats(groups);
    std::cout << "{\n  \"duplicates\": [\n";
    for (size_t i = 0; i < groups.size(); ++i) {
      std::cout << "    [";
      for (size_t j = 0; j < groups[i].size(); ++j) {
        json_escape(std::cout, groups[i][j].string());
        if (j + 1 < groups[i].size()) std::cout << ", ";
      }
      std::cout << "]";
      if (i + 1 < groups.size()) std::cout << ",";
      std::cout << "\n";
    }
    std::cout << "  ],\n  \"stats\": {\n"
              << "    \"duplicate_groups\": " << s.duplicate_groups << ",\n"
              << "    \"duplicate_files\": " << s.duplicate_files << ",\n"
              << "    \"wasted_bytes\": " << s.wasted_bytes << "\n  }\n}\n";
    return 0;
  }

  for (const auto& group : groups) {
    for (const auto& p : group) {
      std::cout << p.string() << '\n';
    }
    std::cout << '\n';
  }

  if (stats) {
    Stats s = compute_stats(groups);
    std::cout << "Duplicate groups: " << s.duplicate_groups << '\n'
              << "Duplicate files: " << s.duplicate_files << '\n'
              << "Wasted space: " << format_bytes(s.wasted_bytes) << '\n';
  }

  return 0;
}
