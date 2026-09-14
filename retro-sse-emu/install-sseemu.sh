#!/bin/sh
set -eu

ROOT=${1:-/mnt/roota}
LIB=${2:-./libretro_sse.so}
DEST="$ROOT/lib64/libretro_sse.so"
PRELOAD="$ROOT/etc/ld.so.preload"

if [ ! -d "$ROOT/lib64" ] || [ ! -d "$ROOT/etc" ]; then
    echo "Not a ChromeOS root: $ROOT" >&2
    exit 1
fi
if [ ! -f "$LIB" ]; then
    echo "Missing emulator library: $LIB" >&2
    exit 1
fi

if [ -e "$DEST" ] && [ ! -e "$DEST.chromeos-original" ]; then
    cp -a "$DEST" "$DEST.chromeos-original"
fi
cp "$LIB" "$DEST"
chmod 0755 "$DEST"
chown 0:0 "$DEST" 2>/dev/null || true

if [ -f "$PRELOAD" ] && [ ! -f "$PRELOAD.retro-sse-backup" ]; then
    cp -a "$PRELOAD" "$PRELOAD.retro-sse-backup"
fi

touch "$PRELOAD"
if ! grep -qxF '/lib64/libretro_sse.so' "$PRELOAD"; then
    printf '%s\n' '/lib64/libretro_sse.so' >> "$PRELOAD"
fi

echo "Installed: $DEST"
echo "Enabled through: $PRELOAD"
