# Tails without persistence: LUKS key partition

Use when Tails Persistent Storage fails after writing the `.img` to a larger USB.

The script adds **partition 2** (`STMLKEY`) in the free space, leaving the Tails
partition intact. Key lives inside LUKS; no Tails persistence is needed.

## Run from Ubuntu Live (not Tails)

1. Boot Ubuntu 21.04 from the 4-GB USB.
2. Identify the Tails disk:

```bash
lsblk -o NAME,SIZE,MODEL,MOUNTPOINTS
```

Tails is the ~59-GB USB disk (usually `/dev/sdd`). Do not use the Ubuntu disk.

3. Find and run the script:

```bash
sudo find /media -name setup_key_partition.sh 2>/dev/null
sudo bash /path/to/setup_key_partition.sh /dev/sdd
```

The script:

- checks it is a whole disk ≥ 8 GiB;
- refuses if anything is mounted;
- backs up GPT to `/root`;
- creates partition 2 type `8309` (`STMLKEY`);
- runs `cryptsetup luksFormat` (you enter the passphrase);
- creates `/keys/policy.key` and `policy.pub` inside LUKS.

4. Unmount/close before reboot:

```bash
sudo umount /mnt/stmlkey
sudo cryptsetup close stmlkey
```

## In Tails

```bash
sudo cryptsetup open /dev/sdd2 stmlkey
sudo mkdir -p /mnt/stmlkey
sudo mount /dev/mapper/stmlkey /mnt/stmlkey
ls /mnt/stmlkey/keys
```

Sign:

```bash
./scripts/stml_offline_sign.sh policy.json \
  /mnt/stmlkey/keys/policy.key /mnt/stmlkey/keys/policy.pub policy.signed.json
```

After signing:

```bash
sudo umount /mnt/stmlkey
sudo cryptsetup close stmlkey
```

## Transfer

The 4-GB Ubuntu USB has a writable FAT partition (`I:`). After signing, mount it
from Tails and copy only `policy.signed.json` + `policy.pub`.

## Quorum

The LUKS passphrase can be split 2-of-3 with `ssss`; keep shares on paper, never
on the same USB. This is an operational quorum, not a threshold HSM.

## Fallback

If the script refuses because the GPT is hybrid/too damaged, stop fighting it:
install Tails with **Tails Installer** on a USB ≥ 8 GB.
