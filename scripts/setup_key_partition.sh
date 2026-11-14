#!/usr/bin/env bash
# Create a second LUKS partition (STMLKEY) on the Tails USB, without Tails
# persistence. Run from Ubuntu Live (not from Tails itself).
#
# Usage:
#   sudo bash setup_key_partition.sh /dev/sdd
#
# The script preserves the existing Tails partition and only uses free space.
set -euo pipefail

DISK="${1:-}"
if [[ -z "$DISK" || ! -b "$DISK" ]]; then
  echo "usage: sudo bash $0 /dev/sdX   (whole disk, not a partition)" >&2
  exit 2
fi
if [[ "$DISK" =~ [0-9]$ ]]; then
  echo "refusing: $DISK looks like a partition; pass the whole disk" >&2
  exit 2
fi

SIZE="$(lsblk -b -dn -o SIZE "$DISK")"
MODEL="$(lsblk -dn -o MODEL "$DISK" | xargs)"
if (( SIZE < 8 * 1024 * 1024 * 1024 )); then
  echo "refusing: $DISK is only $((SIZE/1024/1024/1024)) GiB (< 8 GiB)" >&2
  exit 2
fi

echo "Target disk: $DISK"
echo "Model:       ${MODEL:-unknown}"
echo "Size:        $((SIZE/1024/1024/1024)) GiB"
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL "$DISK"
echo
if lsblk -no MOUNTPOINT "$DISK" | grep -qv '^$'; then
  echo "refusing: something from $DISK is mounted. Unmount it first." >&2
  lsblk -o NAME,SIZE,MOUNTPOINT "$DISK" >&2
  exit 2
fi
PARTS="$(lsblk -ln -o NAME,TYPE "$DISK" | awk '$2=="part"{print $1}')"
if [[ "$(wc -l <<<"$PARTS")" -ne 1 ]]; then
  echo "refusing: expected exactly one partition (Tails), found:" >&2
  echo "$PARTS" >&2
  exit 2
fi

echo "This will add partition 2 (LUKS) in the free space."
echo "Existing Tails partition is preserved."
read -r -p "Type ERASE to continue: " answer
[[ "$answer" == "ERASE" ]] || { echo "aborted"; exit 1; }

if ! command -v sgdisk >/dev/null || ! command -v cryptsetup >/dev/null; then
  echo "install tools first: sudo apt update && sudo apt install -y gdisk cryptsetup" >&2
  exit 2
fi

BACKUP="/root/$(basename "$DISK")-gpt-$(date -u +%Y%m%d-%H%M%S).bin"
echo "backup GPT -> $BACKUP"
sgdisk --backup="$BACKUP" "$DISK" || true

echo "creating partition 2..."
sgdisk -n 2:0:0 -t 2:8309 -c 2:STMLKEY "$DISK"
partprobe "$DISK" || true
udevadm settle || true

for _ in $(seq 1 20); do
  [[ -b "${DISK}2" ]] && break
  sleep 0.5
done
if [[ ! -b "${DISK}2" ]]; then
  echo "partition ${DISK}2 did not appear; check lsblk" >&2
  exit 3
fi

echo "formatting ${DISK}2 as LUKS2 (you will set the passphrase)..."
cryptsetup luksFormat --type luks2 --pbkdf argon2id "${DISK}2"
cryptsetup open "${DISK}2" stmlkey
mkfs.ext4 -L STMLKEYS /dev/mapper/stmlkey
mkdir -p /mnt/stmlkey
mount /dev/mapper/stmlkey /mnt/stmlkey
mkdir -p /mnt/stmlkey/keys
openssl genpkey -algorithm ED25519 -out /mnt/stmlkey/keys/policy.key
openssl pkey -in /mnt/stmlkey/keys/policy.key -pubout -out /mnt/stmlkey/keys/policy.pub
chmod 600 /mnt/stmlkey/keys/policy.key
chown -R "${SUDO_USER:-root}": /mnt/stmlkey/keys

echo
echo "done."
echo "key:    /mnt/stmlkey/keys/policy.key (inside LUKS)"
echo "public: /mnt/stmlkey/keys/policy.pub"
echo
echo "Before reboot:"
echo "  umount /mnt/stmlkey"
echo "  cryptsetup close stmlkey"
echo
echo "In Tails (no persistence needed):"
echo "  sudo cryptsetup open ${DISK}2 stmlkey"
echo "  sudo mount /dev/mapper/stmlkey /mnt"
echo "  # sign from /mnt/keys"
echo "  sudo umount /mnt && sudo cryptsetup close stmlkey"
