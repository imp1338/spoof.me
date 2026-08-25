# Impala

> Windows kernel-mode hardware ID spoofer driver

Impala is a kernel-mode driver (WDM/KMDF) that intercepts and modifies hardware identifiers at the IRP level. It operates through physical memory manipulation and inline hooking to transparently spoof disk serial numbers, WWNs, GUIDs, NVMe identifiers, MAC addresses, and CPUID responses — all with deterministic, seed-based generation for consistent output across queries.

## Architecture

```
spoof.me/
├── src/
│   ├── entry.cxx                          # Driver entry — sequential initialization pipeline
│   ├── includes/
│   │   ├── includes/includes.hxx          # Base headers (ntifs.h, cstdint)
│   │   ├── definitions/definitions.hxx    # Structures, IOCTL codes, PE types, page table defs
│   │   └── logging/print.hxx              # Logging macros (info/error/success/warning)
│   ├── handlers/
│   │   ├── export/exports.hxx             # Dynamic ntoskrnl export resolution + pattern scanning
│   │   ├── generative/gen.hxx            # Deterministic PRNG-based ID generation
│   │   ├── io/io.hxx                      # Device object + symbolic link setup
│   │   └── memory/
│   │       ├── manipulation/(REMOVED)    # Physical memory R/W via PTE remapping
│   │       └── trampoline/trampoline.hxx  # Inline hooking engine + IRP completion swapping
│   └── execute/
│       ├── io/io_functionare.h            # IRP dispatch routines (create/close/device_control)
│       ├── handlers/
│       │   ├── cpu/control_handler.hxx    # CPUID framework, CET/CR0.WP toggling
│       │   └── unload/unload_handler.hxx  # Clean driver unload + hook restoration
│       └── spoofer/
│           ├── devices/device_handler.hxx  # Module resolution + IRP hook orchestration
│           └── disk/
│               ├── disk_handler.hxx        # Legacy SCSI miniport handlers
│               ├── caller/                 # IOCTL dispatch + IOC_REQUEST completion swap
│               ├── handlers/               # Per-protocol IOC completion callbacks
│               │   ├── ata/                # ATA_PASS_THROUGH / ATA_PASS_THROUGH_DIRECT
│               │   ├── scsi/               # SCSI_PASS_THROUGH (DIRECT/EX) + VPD pages
│               │   ├── storage/            # STORAGE_QUERY_PROPERTY + NVMe protocol data
│               │   └── rcv/                # SMART_RCV_DRIVE_DATA
│               └── irps/                   # IRP hook entry points per driver
│                   ├── mountmgr/           # mountmgr.sys DeviceControl hook
│                   ├── partmgr/            # partmgr.sys (stub)
│                   ├── storport/           # storport.sys (stub)
│                   ├── stornvme/           # stornvme.sys (stub)
│                   └── ...
```

## Core Systems

### Dynamic Export Resolution

All kernel API calls are resolved at runtime by parsing the ntoskrnl PE export table directly — no static imports. This avoids IAT-based detection.

- `ZwQuerySystemInformation` (class 11) to locate the ntoskrnl base address
- PE export directory walking for name-to-address resolution
- IDA-style pattern scanning in `.text` sections for unexported functions
- Cached resolution — each export is looked up once and reused

### Page Hiding

Allocated trampoline pages are hidden from detection:

- `MiMakePageBad` + `MiIsPageOnBadList` to move pages to the bad page list
- `MmMarkPhysicalMemoryAsBad` for PFN-level quarantine
- Optional page table page locking via `MiLockPageTablePage`
- `parity_error` flag set in PFN entries to mark pages as defective

### Inline Hooking Engine

Hooks are installed via physical memory writes, bypassing virtual-layer protections:

1. Translate target VA → PA via custom page table walk
2. Read original bytes from physical address
3. HDE64 disassembly to calculate instruction-aligned hook size
4. Allocate and hide a trampoline page (original bytes + absolute jmp back)
5. Write detour shellcode (`FF 25` relative jmp) to target PA
6. NOP-pad any remaining bytes if hook size > detour size
7. Flush TLB, translation buffer, and CPU caches

Clean unhooking restores original bytes and zeroes the trampoline.

### IRP Completion Swapping

Disk query interception uses `PIO_COMPLETION_ROUTINE` swapping:

- Original `IoCompletionRoutine` and `Context` are saved in a heap-allocated `IOC_REQUEST`
- The IRP's completion routine is replaced with a custom handler
- When the IRP completes, the custom handler modifies the response buffer in-place
- The original completion routine is then called to continue the chain

### Deterministic ID Generation

All spoofed identifiers are generated deterministically from a global seed (`0x50A400`):

- **LCG PRNG** (`a=1664525, c=1013904223`) for character substitution maps
- **Xorshift32** for GUID generation with RFC 4122 v4 compliance bits
- **FNV-1a** seeded hashing for MAC address generation with locally-administered bit set
- **Consistency tables** (128 entries each) ensure the same original serial always maps to the same spoofed serial — original ↔ modified pairs are cached and reused

### CPUID Framework

Full CPUID query system with typed layouts for both Intel and AMD:

- Templated leaf/subleaf queries via `__cpuidex`
- Structured bitfield layouts for Feature Information, Extended Features, Brand String, etc.
- CET (Control-flow Enforcement Technology) detection via CR4
- CR0.WP toggling for safe kernel memory writes
- Interrupt disable/enable wrappers

## Intercepted IOCTLs

| IOCTL | Handler | Spoofed Data |
|---|---|---|
| `IOCTL_ATA_PASS_THROUGH_DIRECT` | ATA IOC completion | Serial number, WWN |
| `IOCTL_ATA_PASS_THROUGH` | ATA IOC completion | Serial number, WWN |
| `IOCTL_STORAGE_QUERY_PROPERTY` | Storage IOC completion | Device serial, product ID, WWN, NVMe NGUID/EUI64 |
| `IOCTL_SCSI_PASS_THROUGH_DIRECT` | SCSI IOC completion | VPD page 0x80 (serial), VPD page 0x83 (device ID) |
| `IOCTL_SCSI_PASS_THROUGH_DIRECT_EX` | SCSI IOC completion | VPD pages |
| `IOCTL_SCSI_PASS_THROUGH` | SCSI IOC completion | VPD pages |
| `IOCTL_SCSI_PASS_THROUGH_EX` | SCSI IOC completion | VPD pages |
| `SMART_RCV_DRIVE_DATA` | SMART IOC completion | Serial number, WWN |

## IOCTL Interface

The driver exposes a device at `\Device\iamsour` with symbolic link `\DosDevices\iamsour`:

| Code | Purpose |
|---|---|
| `0x800` | `SPOOF_DISK` — Disk identifier spoofing |
| `0x801` | `SPOOF_BIOS` — BIOS identifier spoofing |
| `0x802` | `SPOOF_NETWORK` — Network MAC spoofing |
| `0x803` | `SPOOF_BOARD` — Board/motherboard spoofing |
| `0x804` | `UNLOAD_DEVICE` — Trigger driver unload |

## Initialization Sequence

```
DriverEntry
  ├─ setup_unload()         Register DriverUnload routine
  ├─ get_ntos_base()        Locate ntoskrnl via ZwQuerySystemInformation(11)
  ├─ setup_cpu()            Detect Intel/AMD, query CPUID features, check CET
  ├─ initialize()           Init physical memory engine (CR3, PFN ranges, PTE slots)
  ├─ setup_io()             Create device object + symbolic link + dispatch routines
  └─ device_handler::initialize()
       └─ hit_mountmgr()    Locate mountmgr.sys, hook DeviceControl IRP
```

## Build

Visual Studio 2022 (v17) with WDK. Target configurations:

- `Debug|x64`
- `Release|x64`
- `Debug|ARM64`
- `Release|ARM64`

Output: `spoof.me.sys` (KMDF kernel-mode driver)

## Requirements

- Windows 10 build 16299+ (RS4)
- x64 or ARM64
- Test signing enabled or valid code signing certificate
- KMDF library

## Disclaimer

This project is for educational and research purposes only. Hardware ID spoofing may violate terms of service of software platforms and game anti-cheat systems. Use responsibly and in compliance with all applicable laws.
This project is UNFINISHED, and missing some files, this project will not be updated and will not be added upon, this is simply a pos i had laying around and never finished.

## Credits

Credits on this project are given to Oracl & SoarCheats
Find soar here = https://github.com/imp1338
Find oracl here = https://github.com/roomyoni
