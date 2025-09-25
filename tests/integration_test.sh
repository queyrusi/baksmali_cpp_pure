#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK_PATH="$REPO_ROOT/tests/apks/FD59E9F940121A08AE9AA71E1EE77EDC4C86914066FF16ACB77CE1083A328765"
JAR_PATH="$REPO_ROOT/baksmali.jar"
NATIVE_BIN="$REPO_ROOT/build/baksmali"

if [[ ! -f "$APK_PATH" ]]; then
    echo "[error] Test APK not found at $APK_PATH" >&2
    exit 1
fi

if [[ ! -f "$JAR_PATH" ]]; then
    echo "[error] Missing baksmali.jar. Please place it at $JAR_PATH" >&2
    exit 1
fi

if [[ ! -x "$NATIVE_BIN" ]]; then
    echo "[error] Native baksmali binary is missing. Build it with: cmake --build build" >&2
    exit 1
fi

RESULT_ROOT="$REPO_ROOT/tests/output"
RUN_ID="$(date +%Y%m%d_%H%M%S)"-$$
WORK_DIR="$RESULT_ROOT/$RUN_ID"
JAVA_OUT="$WORK_DIR/java"
NATIVE_OUT="$WORK_DIR/native"
DEX_DIR="$WORK_DIR/dex"
mkdir -p "$JAVA_OUT" "$NATIVE_OUT" "$DEX_DIR"

DEX_FILES=()
while IFS= read -r dex_name; do
    if [[ -n "$dex_name" ]]; then
        DEX_FILES+=("$dex_name")
    fi
done < <(unzip -Z1 "$APK_PATH" "classes*.dex" 2>/dev/null || true)

if [[ "${#DEX_FILES[@]}" -eq 0 ]]; then
    echo "[error] No classes*.dex files found inside APK" >&2
    exit 1
fi

status=0
for dex in "${DEX_FILES[@]}"; do
    dex_basename="${dex%%.dex}"
    dex_path="$DEX_DIR/$dex"
    unzip -p "$APK_PATH" "$dex" > "$dex_path"

    java_dir="$JAVA_OUT/$dex_basename"
    native_dir="$NATIVE_OUT/$dex_basename"
    mkdir -p "$java_dir" "$native_dir"

    echo "[info] Disassembling $dex via Java baksmali" >&2
    java -jar "$JAR_PATH" d "$dex_path" -o "$java_dir"

    echo "[info] Disassembling $dex via native baksmali" >&2
    "$NATIVE_BIN" "$dex_path" -o "$native_dir"

    echo "[info] Comparing outputs for $dex" >&2
    set +e
    diff -ru "$java_dir" "$native_dir"
    diff_status=$?
    set -e

    if [[ $diff_status -ne 0 ]]; then
        echo "[warn] Differences detected for $dex" >&2
        status=1
    else
        echo "[info] Outputs match for $dex" >&2
    fi

done

echo "[info] Artifacts stored under $WORK_DIR" >&2

if [[ $status -ne 0 ]]; then
    echo "[warn] Integration test detected differences. Inspect $WORK_DIR for details." >&2
else
    echo "[info] Integration test passed." >&2
fi

exit $status
