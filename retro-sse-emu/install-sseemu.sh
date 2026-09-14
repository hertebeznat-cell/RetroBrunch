#!/bin/sh
set -eu

ROOT=${1:-/mnt/roota}
LIB=${2:-./libretro_sse.so}
DEST="$ROOT/lib64/libretro_sse.so"
PRELOAD="$ROOT/etc/ld.so.preload"

[ -d "$ROOT/lib64" ] && [ -d "$ROOT/etc" ] || { echo "Not a ChromeOS root: $ROOT" >&2; exit 1; }
[ -f "$LIB" ] || { echo "Missing emulator library: $LIB" >&2; exit 1; }

# Backup old preload once.
if [ -f "$PRELOAD" ] && [ ! -f "$PRELOAD.retro-sse-backup" ]; then
    cp -a "$PRELOAD" "$PRELOAD.retro-sse-backup"
fi

cp "$LIB" "$DEST"
chown 0:0 "$DEST" 2>/dev/null || true
# Important: secure-execution mode only accepts preloads from standard dirs
# with the set-user-ID bit. This is why v0.2 uses /lib64 + basename below.
chmod 4755 "$DEST"

# Remove v0.1 paths and duplicate entries, preserve unrelated preloads.
tmp="$PRELOAD.retro-sse-tmp.$$"
touch "$PRELOAD"
grep -vxF '/usr/lib64/retrobrunch/libretro_sse.so' "$PRELOAD" 2>/dev/null |
  grep -vxF '/lib64/libretro_sse.so' |
  grep -vxF 'libretro_sse.so' > "$tmp" || true
printf '%s\n' 'libretro_sse.so' >> "$tmp"
cat "$tmp" > "$PRELOAD"
rm -f "$tmp"

# Remove old experimental copy only after the new one is in place.
rm -f "$ROOT/usr/lib64/retrobrunch/libretro_sse.so" 2>/dev/null || true

echo "Retro SSE v0.2 installed: $DEST"
echo "Mode: $(stat -c '%a' "$DEST" 2>/dev/null || ls -l "$DEST")"
echo "Preload entry: libretro_sse.so"
echo "Persistent unknown-opcode log targets:"
echo "  /mnt/stateful_partition/unencrypted/retro-sse.log"
echo "  /var/log/retro-sse.log"
echo "  /tmp/retro-sse.log (fallback)"
