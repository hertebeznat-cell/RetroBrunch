#!/bin/sh
set -eu

ALPINE_VER="${ALPINE_VER:-v3.24}"
VENTOY_MNT="${VENTOY_MNT:-/mnt/ventoy}"
OFFLINE_DIR="${OFFLINE_DIR:-$VENTOY_MNT/alpine-offline-apks}"
PACKAGES="${PACKAGES:-wpa_supplicant openssh util-linux unzip curl ca-certificates}"

say() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

# Mount Ventoy automatically by label if possible
mkdir -p "$VENTOY_MNT"
if ! mountpoint -q "$VENTOY_MNT" 2>/dev/null; then
    VENTOY_DEV="$(blkid -L Ventoy 2>/dev/null || true)"
    if [ -n "$VENTOY_DEV" ]; then
        mount "$VENTOY_DEV" "$VENTOY_MNT" 2>/dev/null || true
    fi
fi

# Friendly path for SCP/SFTP
if mountpoint -q "$VENTOY_MNT" 2>/dev/null; then
    ln -snf "$VENTOY_MNT" /ventoy
fi

# Install offline APK bundle FIRST, so Wi-Fi tools work without Internet
if [ -d "$OFFLINE_DIR" ]; then
    set -- "$OFFLINE_DIR"/*.apk
    if [ -e "$1" ]; then
        say "Installing offline packages from Ventoy"
        apk add --allow-untrusted "$OFFLINE_DIR"/*.apk || true
    fi
fi

# Ensure Wi-Fi utilities exist
if ! command -v wpa_supplicant >/dev/null 2>&1 || ! command -v wpa_passphrase >/dev/null 2>&1; then
    echo
    echo "ERROR: wpa_supplicant/wpa_passphrase are not available."
    echo "Create the offline APK bundle once while Internet is available:"
    echo "  mkdir -p /ventoy/alpine-offline-apks"
    echo "  apk fetch --recursive -o /ventoy/alpine-offline-apks $PACKAGES"
    exit 1
fi

# Find Wi-Fi interface
WIFI_IF=""
for n in /sys/class/net/wlan* /sys/class/net/wlp*; do
    [ -e "$n" ] || continue
    WIFI_IF="$(basename "$n")"
    break
done
[ -n "$WIFI_IF" ] || { echo "Wi-Fi interface not found"; exit 1; }

say "Wi-Fi interface: $WIFI_IF"
ip link set "$WIFI_IF" up 2>/dev/null || true

CONF="/etc/wpa_supplicant.conf"
if [ ! -s "$CONF" ]; then
    printf "Wi-Fi SSID: "
    read -r WIFI_SSID
    printf "Wi-Fi password: "
    stty -echo
    read -r WIFI_PASS
    stty echo
    printf '\n'
    wpa_passphrase "$WIFI_SSID" "$WIFI_PASS" > "$CONF"
    chmod 600 "$CONF"
fi

say "Connecting Wi-Fi"
killall wpa_supplicant 2>/dev/null || true
wpa_supplicant -B -i "$WIFI_IF" -c "$CONF"
udhcpc -i "$WIFI_IF" -q -n || udhcpc -i "$WIFI_IF"

# Online repos, then ensure all tools are installed/up to date
cat > /etc/apk/repositories <<EOF
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VER}/main
https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VER}/community
EOF

apk update || true
apk add $PACKAGES || true

# SSH
say "Configuring SSH"
ssh-keygen -A
sed -i \
  -e '/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]]/d' \
  -e '/^[[:space:]]*PermitLoginRoot[[:space:]]/d' \
  -e '/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]]/d' \
  /etc/ssh/sshd_config

cat >> /etc/ssh/sshd_config <<EOF

PermitRootLogin yes
PasswordAuthentication yes
EOF

sshd -t
rc-update add sshd default >/dev/null 2>&1 || true

echo
echo "Set/confirm root password for SSH:"
passwd

rc-service sshd restart 2>/dev/null || rc-service sshd start

# Persistence if present
PERSIST_DEV="$(blkid -L persistence 2>/dev/null || true)"
if [ -n "$PERSIST_DEV" ]; then
    mkdir -p /media/persist
    if ! mountpoint -q /media/persist 2>/dev/null; then
        mount "$PERSIST_DEV" /media/persist 2>/dev/null || true
    fi

    if mountpoint -q /media/persist 2>/dev/null; then
        mkdir -p /media/persist/lbu /media/persist/cache /etc/lbu
        echo 'LBU_BACKUPDIR=/media/persist/lbu' > /etc/lbu/lbu.conf
        setup-apkcache /media/persist/cache >/dev/null 2>&1 || true
        lbu commit >/dev/null 2>&1 || true
    fi
fi

IP_ADDR="$(ip -4 -o addr show dev "$WIFI_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"

say "READY"
echo "IP: ${IP_ADDR:-unknown}"
echo "SSH: ssh root@${IP_ADDR:-<IP>}"
echo "Ventoy: /ventoy"
echo
echo "From Windows upload directly to the flash drive:"
echo "  scp FILE root@${IP_ADDR:-<IP>}:/ventoy/"
echo
echo "To prepare/refresh the offline package bundle while Internet works:"
echo "  mkdir -p /ventoy/alpine-offline-apks"
echo "  apk fetch --recursive -o /ventoy/alpine-offline-apks $PACKAGES"
