#!/usr/bin/env python3
"""
craft_vhd_empty.py

Creates a minimal, standard, empty fixed-size VHD with a valid GPT layout
and no partitions.

Disk layout (sector size = 512 bytes, 68 sectors total = 34816 bytes):
  Sector 0       : Protective MBR (partition type 0xEE)
  Sector 1       : Primary GPT Header
  Sectors 2-33   : GPT Partition Entry Array (all zeros — no partitions)
  Sector 34      : (single usable sector, zeros)
  Sectors 35-66  : Backup GPT Partition Entry Array
  Sector 67      : Backup GPT Header
  +512 bytes     : VHD Footer ("conectix")

Usage:
  python craft_vhd_empty.py [output.vhd]
"""

import struct
import uuid
import zlib
import os
import sys
from datetime import datetime, timezone

SECTOR_SIZE = 512
NUM_PARTITION_ENTRIES = 128
PARTITION_ENTRY_SIZE = 128
PARTITION_ARRAY_SECTORS = (NUM_PARTITION_ENTRIES * PARTITION_ENTRY_SIZE) // SECTOR_SIZE  # 32
GPT_HEADER_SIZE = 92

# Minimum valid GPT disk: MBR(1) + GPT hdr(1) + entries(32) + usable(1) + backup entries(32) + backup hdr(1) = 68
TOTAL_SECTORS = 68
DISK_SIZE = TOTAL_SECTORS * SECTOR_SIZE

PRIMARY_GPT_HEADER_LBA = 1
PRIMARY_GPT_ENTRIES_LBA = 2
FIRST_USABLE_LBA = PRIMARY_GPT_ENTRIES_LBA + PARTITION_ARRAY_SECTORS  # 34
BACKUP_GPT_HEADER_LBA = TOTAL_SECTORS - 1                             # 67
BACKUP_GPT_ENTRIES_LBA = BACKUP_GPT_HEADER_LBA - PARTITION_ARRAY_SECTORS  # 35
LAST_USABLE_LBA = BACKUP_GPT_ENTRIES_LBA - 1                          # 34


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def make_protective_mbr() -> bytearray:
    mbr = bytearray(SECTOR_SIZE)
    entry = bytearray(16)
    entry[0] = 0x00
    entry[1] = 0x00
    entry[2] = 0x02
    entry[3] = 0x00
    entry[4] = 0xEE
    entry[5] = 0xFF
    entry[6] = 0xFF
    entry[7] = 0xFF
    struct.pack_into("<I", entry, 8, 1)
    struct.pack_into("<I", entry, 12, min(TOTAL_SECTORS - 1, 0xFFFFFFFF))
    mbr[0x1BE:0x1CE] = entry
    mbr[0x1FE] = 0x55
    mbr[0x1FF] = 0xAA
    return mbr


def make_gpt_entries() -> bytearray:
    """Empty partition entry array (no partitions)."""
    return bytearray(NUM_PARTITION_ENTRIES * PARTITION_ENTRY_SIZE)


def make_gpt_header(is_backup: bool, entries_crc: int, disk_guid: bytes) -> bytearray:
    hdr = bytearray(SECTOR_SIZE)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)   # Revision 1.0
    struct.pack_into("<I", hdr, 12, GPT_HEADER_SIZE)
    struct.pack_into("<I", hdr, 16, 0)            # CRC placeholder
    struct.pack_into("<I", hdr, 20, 0)            # Reserved

    if not is_backup:
        struct.pack_into("<Q", hdr, 24, PRIMARY_GPT_HEADER_LBA)
        struct.pack_into("<Q", hdr, 32, BACKUP_GPT_HEADER_LBA)
    else:
        struct.pack_into("<Q", hdr, 24, BACKUP_GPT_HEADER_LBA)
        struct.pack_into("<Q", hdr, 32, PRIMARY_GPT_HEADER_LBA)

    struct.pack_into("<Q", hdr, 40, FIRST_USABLE_LBA)
    struct.pack_into("<Q", hdr, 48, LAST_USABLE_LBA)
    hdr[56:72] = disk_guid

    if not is_backup:
        struct.pack_into("<Q", hdr, 72, PRIMARY_GPT_ENTRIES_LBA)
    else:
        struct.pack_into("<Q", hdr, 72, BACKUP_GPT_ENTRIES_LBA)

    struct.pack_into("<I", hdr, 80, NUM_PARTITION_ENTRIES)
    struct.pack_into("<I", hdr, 84, PARTITION_ENTRY_SIZE)
    struct.pack_into("<I", hdr, 88, entries_crc)

    header_crc = crc32(bytes(hdr[:GPT_HEADER_SIZE]))
    struct.pack_into("<I", hdr, 16, header_crc)
    return hdr


def make_vhd_footer(disk_size: int) -> bytearray:
    footer = bytearray(SECTOR_SIZE)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 0x00000002)            # Features
    struct.pack_into(">I", footer, 12, 0x00010000)           # Format version 1.0
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)   # Data offset (fixed disk)

    epoch_2000 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    ts = int((datetime.now(timezone.utc) - epoch_2000).total_seconds())
    struct.pack_into(">I", footer, 24, ts)

    footer[28:32] = b"pyth"                                  # Creator app
    struct.pack_into(">I", footer, 32, 0x00010000)           # Creator version
    footer[36:40] = b"Wi2k"                                  # Creator host OS
    struct.pack_into(">Q", footer, 40, disk_size)            # Original size
    struct.pack_into(">Q", footer, 48, disk_size)            # Current size

    # CHS geometry per VHD spec
    total_sec = disk_size // SECTOR_SIZE
    if total_sec > 65535 * 16 * 255:
        total_sec = 65535 * 16 * 255
    if total_sec >= 65535 * 16 * 63:
        spt = 255
        heads = 16
    else:
        spt = 17
        cth = total_sec // spt
        heads = (cth + 1023) // 1024
        if heads < 4:
            heads = 4
        if cth >= heads * 1024 or heads > 16:
            spt = 31
            heads = 16
            cth = total_sec // spt
        if cth >= heads * 1024:
            spt = 63
            heads = 16
            cth = total_sec // spt
    cth = total_sec // spt
    cylinders = min(cth // heads, 65535)

    struct.pack_into(">H", footer, 56, cylinders)
    footer[58] = heads
    footer[59] = spt
    struct.pack_into(">I", footer, 60, 2)                    # Disk type: fixed
    struct.pack_into(">I", footer, 64, 0)                    # Checksum placeholder
    footer[68:84] = uuid.uuid4().bytes                       # Unique ID
    footer[84] = 0                                           # Saved state

    # Checksum: one's complement of sum of all bytes (excluding checksum field)
    total = sum(b for i, b in enumerate(footer) if not (64 <= i < 68))
    struct.pack_into(">I", footer, 64, (~total) & 0xFFFFFFFF)
    return footer


def create_vhd(output_path: str):
    disk_guid = uuid.uuid4().bytes_le
    entries = make_gpt_entries()
    entries_crc = crc32(entries)
    primary_hdr = make_gpt_header(False, entries_crc, disk_guid)
    backup_hdr = make_gpt_header(True, entries_crc, disk_guid)
    vhd_footer = make_vhd_footer(DISK_SIZE)

    with open(output_path, "wb") as f:
        f.write(make_protective_mbr())       # Sector 0
        f.write(primary_hdr)                 # Sector 1
        f.write(entries)                     # Sectors 2-33
        # Sector 34: single usable sector (zeros)
        f.write(b'\x00' * SECTOR_SIZE)
        f.write(entries)                     # Sectors 35-66: backup entries
        f.write(backup_hdr)                  # Sector 67: backup GPT header
        f.write(vhd_footer)                  # VHD footer

    file_size = os.path.getsize(output_path)
    expected = DISK_SIZE + SECTOR_SIZE
    status = "OK" if file_size == expected else f"expected {expected:,}"
    print(f"Created {output_path}: {file_size:,} bytes ({status})")
    print(f"  Disk: {TOTAL_SECTORS} sectors, {DISK_SIZE:,} bytes")
    print(f"  GPT: empty (no partitions)")


if __name__ == "__main__":
    output = "empty.vhd"
    if len(sys.argv) > 1:
        output = sys.argv[1]
    create_vhd(output)
