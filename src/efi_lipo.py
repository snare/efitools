#!/usr/bin/env python
"""
fatsplit.py - split Apple's EFI fat binaries into PE files that IDA Pro understands

the EFI fat header looks something like this:

0000000 b9 fa f1 0e 02 00 00 00 07 00 00 01 03 00 00 00
0000010 30 00 00 00 40 ca 06 00 00 00 00 00 07 00 00 00
0000020 03 00 00 00 70 ca 06 00 40 50 06 00 00 00 00 00

which breaks down to:

typedef struct {
    UINT32 magic;                   // Apple EFI fat binary magic number (0x0ef1fab9)
    UINT32 num_archs;               // number of architectures
    EFIFatArchHeader archs[];       // architecture headers
} EFIFatHeader;

the architecture header sections look something like:

typedef struct {
    UINT32 cpu_type;                // probably 0x07 (CPU_TYPE_X86) or 0x01000007 (CPU_TYPE_X86_64)
    UINT32 cpu_subtype;             // probably 3 (CPU_SUBTYPE_I386_ALL)
    UINT32 offset;                  // offset to beginning of architecture section
    UINT32 size;                    // size of arch section
    UINT32 align;                   // alignment
} EFIFatArchHeader;

sections are PE/PE+ binaries and will start with 'MZ' (4d 5a)
"""

import argparse
import struct
import logging
import logging.config
import os.path

EFI_FAT_MAGIC       = 0x0ef1fab9

# from mach/machine.h
CPU_ARCH_ABI64      = 0x01000000
CPU_TYPE_X86        = 7
CPU_TYPE_X86_64     = (CPU_TYPE_X86 | CPU_ARCH_ABI64)


# configure logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
log.addHandler(ch)


def main():
    # parse command line args
    parser = argparse.ArgumentParser(description="split up Apple EFI fat binaries")
    parser.add_argument('file', metavar='file', type=argparse.FileType('rb'), help="EFI fat binary to split.")
    args = parser.parse_args()
    f = args.file

    # read fat header
    log.info("processing '%s'" % f.name)
    (magic, num_archs) = struct.unpack("<LL", f.read(8))
    if magic != EFI_FAT_MAGIC:
        log.error("[~] this is not an EFI fat binary")
        sys.exit(2)
    log.info("this is an EFI fat binary with %d architectures" % num_archs)

    # process architectures
    archs = []
    for i in range(num_archs):
        # read arch header
        (cpu_type, cpu_subtype, offset, size, align) = struct.unpack("<5L", f.read(4*5))
        if cpu_type == CPU_TYPE_X86:
            arch = "X86"
        elif cpu_type == CPU_TYPE_X86_64:
            arch = "X64"
        else:
            log.error('[~] unknown CPU type: 0x%l' % cpu_type)
            return
        log.info("architecture %d (%s):" % (i, arch))
        log.info("  offset: 0x%x" % offset)
        log.info("  size:   0x%x" % size)
        archs.append((arch, offset, size))
    
    # read and write sections
    for (arch, offset, size) in archs:
        # read in section
        f.seek(offset)
        data = f.read(size)

        # write out section
        filename = os.path.basename(f.name) + "." + arch
        log.info("saving %s section to '%s'" % (arch, filename))
        of = open(filename, 'wb')
        of.write(data)
        of.close()
    
    # close input
    f.close()

 
if __name__ == "__main__":
    main()
