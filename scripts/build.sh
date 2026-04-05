#!/usr/bin/env bash
# Generate into ./ND-100/ then run Gradle buildExtension (needs GHIDRA_INSTALL_DIR).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

SRC="$REPO/src/NDGen.Generators.Ghidra/Ghidra/ND-100"
OUT="$REPO/ND-100"

if [[ "${1:-}" != "gradle-only" ]]; then
  echo "=== [1/2] Generate SLEIGH, Java glue, manual into ND-100/ ==="
  command -v dotnet >/dev/null || { echo "ERROR: dotnet not in PATH"; exit 1; }
  if [[ ! -f "$REPO/nd100-definitions/specs/cpu.yaml" ]]; then
    git -C "$REPO" submodule update --init --recursive
  fi
  dotnet build "$REPO/ND100.Ghidra.sln" -c Release
  dotnet run --project "$REPO/src/ND100.Ghidra.Tool/ND100.Ghidra.Tool.csproj" -c Release --no-build
fi

echo "=== [2/2] Copy Gradle scaffold + buildExtension ==="
[[ -f "$SRC/build.gradle" ]] || { echo "ERROR: Missing $SRC"; exit 1; }
mkdir -p "$OUT"
cp -f "$SRC/build.gradle" "$SRC/settings.gradle" "$SRC/extension.properties" "$SRC/Module.manifest" "$OUT/"
cp -rf "$SRC/gradle" "$OUT/"
cp -rf "$SRC/src" "$OUT/"
cp -f "$SRC/gradlew.bat" "$OUT/"

: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to your Ghidra installation root}"

cd "$OUT"
if command -v gradle >/dev/null 2>&1; then
  gradle --no-daemon buildExtension
else
  echo "ERROR: Install Gradle (matching your Ghidra version) or use build.bat on Windows with Ghidra's layout."
  exit 1
fi

echo "=== Done. Extension ZIP under: $OUT/dist/ ==="
ls -la "$OUT/dist/"ghidra_*_ND-100.zip 2>/dev/null || true
