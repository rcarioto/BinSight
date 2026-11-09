#!/usr/bin/env bash
# Build a single self-contained win-x64 zip + SHA-256 for BinSight (GUI + CLI).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-1.3.0}"
OUT="$ROOT/publish/release"
CFG=Release
RID=win-x64

export PATH="${DOTNET_ROOT:-$HOME/.dotnet}:$PATH"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"

rm -rf "$OUT"
mkdir -p "$OUT/app"

echo "==> Publishing BinSight (GUI + CLI, self-contained single-file)"
dotnet publish "$ROOT/src/BinSight/BinSight.csproj" -c "$CFG" -r "$RID" --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -o "$OUT/app" --nologo

cp "$ROOT/README.md" "$OUT/app/"
cat > "$OUT/app/QUICKSTART.txt" <<EOF
BinSight ${VERSION} — GUI + CLI in one EXE
Copyright (C) 2026 Ray Carioto <raymond.carioto@gmail.com>
License: GNU GPL v3.0 or later — see LICENSE / README.md

GUI:  double-click BinSight.exe
      or: BinSight.exe /gui
      or: BinSight.exe /gui /Target C:\\path\\to\\app.exe

CLI:  BinSight.exe /Target C:\\path\\to\\app.exe /Verbose
      BinSight.exe /ListChecks
      BinSight.exe /Target C:\\folder /Recurse /Html /OutDir .\\reports

Verify this zip:
  certutil -hashfile BinSight-${VERSION}-${RID}.zip SHA256
EOF

cp "$ROOT/LICENSE" "$OUT/app/"

ZIP="$OUT/BinSight-${VERSION}-${RID}.zip"

echo "==> Zipping"
python3 - "$ZIP" "$OUT/app/BinSight.exe" "$OUT/app/README.md" "$OUT/app/QUICKSTART.txt" "$OUT/app/LICENSE" <<'PY'
import sys, zipfile, os
zpath, files = sys.argv[1], sys.argv[2:]
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
    for f in files:
        z.write(f, arcname=os.path.basename(f))
print("wrote", zpath)
PY

echo "==> Checksum"
(
  cd "$OUT"
  sha256sum "BinSight-${VERSION}-${RID}.zip" | tee "BinSight-${VERSION}-${RID}.zip.sha256"
)

echo
echo "Artifact:"
ls -lah "$OUT"/BinSight-${VERSION}-${RID}.zip*
