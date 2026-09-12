#!/usr/bin/env bash
set -e

BRUNCH_DIR="$1"
LEGACY_DIR="$2"

ROOTC="$BRUNCH_DIR/rootc.img"
BIOS_IMG="$BRUNCH_DIR/bios_boot.img"

[ -f "$ROOTC" ] || {
    echo "RetroBrunch: rootc.img not found"
    exit 1
}

[ -f "$LEGACY_DIR/payload/syslinux.cfg" ] || {
    echo "RetroBrunch: Legacy BIOS payload not found"
    exit 1
}

echo "RetroBrunch: creating Legacy BIOS boot image..."

rm -f "$BIOS_IMG"

dd if=/dev/zero of="$BIOS_IMG" bs=1M count=64 status=progress
mkfs.fat -F 16 -n RETROBIOS "$BIOS_IMG"

TMP_ROOTC=$(mktemp -d)
TMP_BIOS=$(mktemp -d)

cleanup()
{
    sudo umount "$TMP_ROOTC" 2>/dev/null || true
    sudo umount "$TMP_BIOS" 2>/dev/null || true
    rmdir "$TMP_ROOTC" "$TMP_BIOS" 2>/dev/null || true
}
trap cleanup EXIT

sudo mount -o loop,ro "$ROOTC" "$TMP_ROOTC"
sudo mount -o loop "$BIOS_IMG" "$TMP_BIOS"

sudo cp "$LEGACY_DIR/payload/syslinux.cfg" "$TMP_BIOS/"
sudo cp "$LEGACY_DIR/payload/ldlinux.c32" "$TMP_BIOS/"
sudo cp "$LEGACY_DIR/payload/menu.c32" "$TMP_BIOS/"

sudo cp "$TMP_ROOTC/kernel" "$TMP_BIOS/kernel"
sudo cp "$TMP_ROOTC/initramfs.img" "$TMP_BIOS/initramfs.img"

if [ -f "$TMP_ROOTC/lib/firmware/intel-ucode.img" ]; then
    sudo cp "$TMP_ROOTC/lib/firmware/intel-ucode.img" "$TMP_BIOS/intel-ucode.img"
fi

sync
sudo umount "$TMP_BIOS"
sudo umount "$TMP_ROOTC"

syslinux --install "$BIOS_IMG"

echo "RetroBrunch: bios_boot.img created successfully"
