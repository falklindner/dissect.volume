from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct

from dissect.volume.disk.partition import Partition
from dissect.volume.exceptions import DiskError

if TYPE_CHECKING:
    from collections.abc import Iterator

mbr_def = """
typedef struct part_s {
    uint8   bootable;       // +0: 0x80/0x00 - bootable/not bootable
    uint8   start_head;     // +1: head (start)
    uint16  start_cyl_sec;  // +2: cyl+sect (start)
    uint8   type;           // +4: type
    uint8   end_head;       // +5: head (end)
    uint16  end_cyl_sec;    // +6: cyl+sec (end)
    uint32  sector_ofs;     // +8: offset in sectors
    uint32  sector_size;    // +12: size in sectors
} part;

typedef struct mbr_s {
    char    bootcode[0x1b8];
    uint32  vol_no;
    uint16  pad1;
    part    part[4];
    uint16  bootsig;
} mbr;

typedef struct fat_bpb_s {
    uint8   jump[3];                // +0: jump to the boot code
    char    oem_id[8];              // +3: OEM ID
    uint16  bytes_per_sector;       // +11: bytes per sector
    uint8   sectors_per_cluster;    // +13: sectors per cluster
    uint16  reserved_sectors;       // +14: reserved sectors
    uint8   fat_count;              // +16: number of FATs
    uint16  root_entries;           // +17: root directory entries (0 for FAT32)
    uint16  total_sectors_16;       // +19: total sectors (0 if it does not fit)
    uint8   media;                  // +21: media descriptor
    uint16  fat_size_16;            // +22: sectors per FAT (0 for FAT32)
    uint16  sectors_per_track;      // +24: sectors per track
    uint16  heads;                  // +26: number of heads
    uint32  hidden_sectors;         // +28: sectors before the volume
    uint32  total_sectors_32;       // +32: total sectors
} fat_bpb;
"""

c_mbr = cstruct().load(mbr_def)


class MBR:
    """Master Boot Record."""

    def __init__(self, fh: BinaryIO, sector_size: int = 512):
        self.fh = fh
        self.sector_size = sector_size
        self.offset = fh.tell()
        self.mbr = c_mbr.mbr_s(fh)

        if self.mbr.bootsig != 0xAA55:
            raise DiskError(f"Invalid MBR boot signature. Expected 0xaa55, got 0x{self.mbr.bootsig:x}.")

        # This sucks but don't have a better way atm
        sig = self.mbr.bootcode[3:11]
        if any(v in sig for v in [b"MSDOS", b"MSWIN", b"NTFS", b"FAT", b"EXFAT", b"-FVE-FS-", b"SYSLINUX"]):
            raise DiskError("Sector is a filesystem VBR, not an MBR")

        if _is_fat_boot_sector(self.mbr.bootcode):
            raise DiskError("Sector is a FAT filesystem VBR, not an MBR")

        if self.mbr.bootcode[18:38] == b"Hit Esc for .altboot" or self.mbr.bootcode[168:174] == b"\r\nQNX ":
            raise DiskError("Sector is a QNX Boot Sector, not an MBR")

        self.partitions: list[Partition] = list(self._partitions(self.mbr, self.offset))

    def _partitions(
        self, mbr: c_mbr.mbr_s, offset: int, num_start: int = 0, ebr_offset: int | None = None
    ) -> Iterator[Partition]:
        for num, partition in enumerate(mbr.part):
            if partition.type == 0x00:
                continue

            part_offset = offset + partition.sector_ofs * self.sector_size

            if partition.type in (0x05, 0x0F, 0x85):  # Extended
                if not ebr_offset:
                    ebr_offset = part_offset
                else:
                    # Chained extended MBRs are relative to the first one
                    part_offset = ebr_offset + partition.sector_ofs * self.sector_size

                self.fh.seek(part_offset)
                e_mbr = c_mbr.mbr_s(self.fh)
                yield from self._partitions(e_mbr, part_offset, num_start + num, ebr_offset=ebr_offset)

                continue

            yield Partition(
                disk=self,
                number=num_start + num + 1,  # partitions are 1-indexed
                offset=part_offset,
                size=partition.sector_size * self.sector_size,
                type=partition.type,
                flags=partition.bootable,
                raw=partition,
            )


def _is_fat_boot_sector(sector: bytes) -> bool:
    """Return whether ``sector`` starts with a FAT boot sector, whatever its OEM ID.

    A FAT volume without a partition table starts with a boot sector that has the same boot signature as an MBR,
    and its boot code takes up the space of the MBR partition table. Its OEM ID can be anything, such as
    ``mkfs.fat`` or a vendor's own, so check its BIOS parameter block instead, with the rules ``dissect.fat`` uses
    to accept a FAT boot sector.
    """
    bpb = c_mbr.fat_bpb(sector)
    return (
        # A jump to the boot code: EB xx 90 or E9 xx xx
        ((bpb.jump[0] == 0xEB and bpb.jump[2] == 0x90) or bpb.jump[0] == 0xE9)
        and bpb.bytes_per_sector in (512, 1024, 2048, 4096)
        and bpb.sectors_per_cluster in (1, 2, 4, 8, 16, 32, 64, 128)
        and bpb.reserved_sectors != 0
        and bpb.fat_count != 0
        and bpb.media in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF)
        and (bpb.root_entries * 32) % bpb.bytes_per_sector == 0
        and (bpb.total_sectors_16 != 0 or bpb.total_sectors_32 != 0)
    )
