# Baksmali C++

A C++17 implementation of the baksmali Dalvik disassembler. 
The project mirrors the behaviour of the original Java tool.
The formatting won’t always be perfect, but it should still work in most contexts.

## Requirements

- CMake 3.20 or newer
- A C++17-capable compiler (Clang, GCC, or MSVC)
- POSIX threads (linked automatically through CMake on Unix-like systems)
- Optional: a reference copy of `baksmali.jar` when you want to diff output against the upstream Java implementation

## Building

```bash
# Configure (out-of-tree builds are recommended)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Compile
cmake --build build

# Optionally install the binary
cmake --install build --prefix /desired/prefix
```

The resulting executable is emitted as `build/baksmali` (or `baksmali.exe` on Windows).

## Usage

```bash
./build/baksmali [options] <classes.dex>
```

Useful flags exposed by `src/cli/command_line_parser.cpp`:
- `-h, --help` shows the embedded help text
- `-v, --version` prints the current version string
- `-o, --output <dir>` writes smali files under the given directory (default: `out`)
- `--api-level <level>` adjusts decoding to a specific Android API level (default: 15)
- `-j, --jobs <count>` controls how many classes are disassembled in parallel (0 = auto)
- `--debug-info`, `--register-info`, `--parameter-registers`, `--code-offsets` toggle formatting details
- `--sequential-labels` emits numbered labels instead of absolute addresses
- `--verbose` enables progress logging

Example session:

```bash
./build/baksmali classes.dex -o output/smali --jobs 8 --verbose
```

Each Dalvik class is written to a `.smali` file whose path mirrors the class descriptor. Collisions that only differ by case are de-duplicated automatically.

## Project Layout

```
src/
├── main.cpp                 # CLI entry point
├── baksmali.cpp/.hpp        # High-level disassembler orchestration
├── baksmali_options.hpp     # Runtime configuration shared across components
├── cli/                     # Command-line parsing and help text
├── dex/                     # DEX file reader and instruction decoding
├── adaptors/                # Smali class writer and metadata adaptors
└── formatter/               # Low-level smali output helpers
```

The implementation loads the target DEX file, creates the output directory, and then disassembles classes concurrently (unless `--jobs 1` is specified). Formatting logic lives under `src/adaptors` and `src/formatter` so it can be reused by other front-ends in the future.

## Testing

Use the integration harness in `tests/integration_test.sh` to compare the native disassembler against the Java reference on the bundled APK (`tests/apks/FD59E9F940121A08AE9AA71E1EE77EDC4C86914066FF16ACB77CE1083A328765`).

```bash
./tests/integration_test.sh
```

The script expects:
- `java` available on the PATH
- `baksmali.jar` staged in the repository root
- the native binary built in `build/baksmali` (`cmake --build build`)
- `unzip` and `diff` utilities

It extracts every `classes*.dex` file from the APK, disassembles each with both implementations, and runs a recursive diff on the resulting Smali trees. A non-zero exit status indicates output differences, and each run persists its artifacts under `tests/output/<timestamp>-<pid>/` with `java/`, `native/`, and `dex/` subdirectories so you can revisit the generated files or share diffs. Clean up old run directories as needed.

## License

This repository intends to follow the licensing model of the original smali/baksmali project. Ensure that redistribution complies with the upstream licence terms.
