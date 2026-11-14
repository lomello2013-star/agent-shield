"""Repair a GPT backup header/table after writing a small image to a larger disk.

Run elevated on Windows, with the target volume dismounted. Backs up the first
and last 34 sectors to artifacts/gpt-backup-<disk>.bin before writing.
"""

from __future__ import annotations

import argparse
import os
import struct
import zlib
from pathlib import Path

SECTOR = 512
GPT_SIG = b"EFI PART"


def read_at(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise RuntimeError(f"short read at {offset}: {len(data)} != {size}")
    return data


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--drive", required=True, help=r"e.g. \\.\PhysicalDrive3")
    ap.add_argument("--last-lba", type=int, required=True)
    ap.add_argument("--out", default="artifacts/gpt-backup.bin")
    args = ap.parse_args()

    with open(args.drive, "r+b", buffering=0) as f:
        first = read_at(f, 0, 34 * SECTOR)
        last_off = (args.last_lba - 33) * SECTOR
        last = read_at(f, last_off, 34 * SECTOR)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes(first + last)

        mbr = bytearray(first[:SECTOR])
        if mbr[510:512] != b"\x55\xaa":
            raise RuntimeError("not an MBR/GPT disk (missing 55AA)")
        header = bytearray(read_at(f, SECTOR, SECTOR))
        if header[:8] != GPT_SIG:
            raise RuntimeError("GPT header signature missing")
        (header_size,) = struct.unpack_from("<I", header, 12)
        if header_size < 92 or header_size > SECTOR:
            raise RuntimeError(f"bad GPT header size {header_size}")
        (entry_lba,) = struct.unpack_from("<Q", header, 72)
        (num_entries,) = struct.unpack_from("<I", header, 80)
        (entry_size,) = struct.unpack_from("<I", header, 84)
        entries = read_at(f, entry_lba * SECTOR, num_entries * entry_size)
        entry_sectors = (len(entries) + SECTOR - 1) // SECTOR
        backup_entries_lba = args.last_lba - entry_sectors
        if backup_entries_lba <= 34:
            raise RuntimeError("disk too small / bad last LBA")
        last_usable = backup_entries_lba - 1

        # Backup partition entry array.
        f.seek(backup_entries_lba * SECTOR)
        f.write(entries)
        # Backup header.
        backup = bytearray(header)
        struct.pack_into("<Q", backup, 24, args.last_lba)       # my_lba
        struct.pack_into("<Q", backup, 32, 1)                  # alternate_lba
        struct.pack_into("<Q", backup, 48, last_usable)         # last usable
        struct.pack_into("<Q", backup, 72, backup_entries_lba)  # entries lba
        struct.pack_into("<I", backup, 16, 0)
        struct.pack_into("<I", backup, 16, crc32(backup[:header_size]))
        f.seek(args.last_lba * SECTOR)
        f.write(backup)
        # Main header: alternate_lba + last_usable -> full disk.
        struct.pack_into("<Q", header, 32, args.last_lba)
        struct.pack_into("<Q", header, 48, last_usable)
        struct.pack_into("<I", header, 16, 0)
        struct.pack_into("<I", header, 16, crc32(header[:header_size]))
        f.seek(SECTOR)
        f.write(header)
        f.flush()
        os.fsync(f.fileno())

        # Verify read-back.
        check = read_at(f, SECTOR, SECTOR)
        (alt,) = struct.unpack_from("<Q", check, 32)
        (usable,) = struct.unpack_from("<Q", check, 48)
        (crc,) = struct.unpack_from("<I", check, 16)
        check2 = bytearray(check)
        struct.pack_into("<I", check2, 16, 0)
        if alt != args.last_lba or usable != last_usable or crc32(check2[:header_size]) != crc:
            raise RuntimeError("verification failed")
        print(f"ok disk={args.drive} last_lba={args.last_lba} "
              f"last_usable={last_usable} backup_entries_lba={backup_entries_lba} "
              f"backup={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
