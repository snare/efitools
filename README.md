efitools
========

A few tools for doing stuff to EFI-related things. Well, eventually it will be a few. For now it's just one.


fatsplit.py
-----------

A quick script for splitting up Apple EFI fat binaries into their individual per-architecture binary sections.

### Usage

    $ ./efi_lipo.py /System/Library/CoreServices/boot.efi 
    processing 'SmcFlasher.efi'
    this is an EFI fat binary with 2 architectures
    architecture 0 (X86):
      offset: 0x30
      size:   0x8bd0
    architecture 1 (X64):
      offset: 0x8c00
      size:   0x9e70
    saving X86 section to 'SmcFlasher.efi.X86'
    saving X64 section to 'SmcFlasher.efi.X64'