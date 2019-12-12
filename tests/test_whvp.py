
import os
import json
import base64

import pytest

import whvp


def test_register():
    emulator = whvp.Emulator()
    rax = emulator.get_reg("rax")

    assert rax == 0


def test_physical_memory():
    emulator = whvp.Emulator()
    emulator.allocate_physical_memory(0x1000, 0x1000)
    emulator.write_physical_memory(0x1000, b"\x01\x02\x03\x04")

    data = emulator.read_physical_memory(0x1000, 4)
    assert data == b"\x01\x02\x03\x04"

    emulator.write_physical_memory(0x1400, b"\xAA\xBB\xCC\xDD")
    data = emulator.read_physical_memory(0x1400, 4)
    assert data == b"\xAA\xBB\xCC\xDD"


def test_allocate():
    emulator = whvp.Emulator()
    addr = emulator.allocate_physical_memory(0x1000, 0x1000)
    assert addr != 0


def test_allocate2():
    emulator = whvp.Emulator()
    addr = emulator.allocate_physical_memory(0x1000, 0x1000)
    assert addr != 0
    addr2 = emulator.allocate_physical_memory(0x2000, 0x1000)
    assert addr2 != 0

    emulator.write_physical_memory(0x1000, b"\x01\x02\x03\x04")

    emulator.write_physical_memory(0x2000, b"\xAA\xBB\xCC\xDD")

    data = emulator.read_physical_memory(0x1000, 4)
    assert data == b"\x01\x02\x03\x04"

    data = emulator.read_physical_memory(0x2000, 4)
    assert data == b"\xAA\xBB\xCC\xDD"


def test_invalid_read():
    emulator = whvp.Emulator()

    with pytest.raises(ValueError):
        emulator.read_physical_memory(0x1000, 4)


def test_invalid_write():
    emulator = whvp.Emulator()

    with pytest.raises(ValueError):
        emulator.write_physical_memory(0x1000, b"\x01\x02\x03\x04")


def test_basic_emulation():
    RAM_BASE = 0
    RAM_SIZE = 0x1000 * 240
    ROM_BASE = 0xf0000
    ROM_SIZE = 0x1000 * 16

    emulator = whvp.Emulator()

    emulator.allocate_physical_memory(ROM_BASE, ROM_SIZE)
    emulator.allocate_physical_memory(RAM_BASE, RAM_SIZE)

    emulator.write_physical_memory(ROM_BASE, b"\x00\x00\x00\x00\x00\x00\x00\x00")  # [0x0000] GDT entry 0: null
    emulator.write_physical_memory(ROM_BASE + 8, b"\xff\xff\x00\x00\x00\x9b\xcf\x00")  # [0x0008] GDT entry 1: code (full access to 4 GB linear space)
    emulator.write_physical_memory(ROM_BASE + 0x10, b"\xff\xff\x00\x00\x00\x93\xcf\x00")  # [0x0010] GDT entry 2: data (full access to 4 GB linear space)    

    # IDT table (system)
    # All entries are present, 80386 32-bit trap gates, privilege level 0, use selector 0x8 and offset 0x10001005
    emulator.write_physical_memory(ROM_BASE + 0x18, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0018] Vector 0x00: Divide by zero
    emulator.write_physical_memory(ROM_BASE + 0x20, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0020] Vector 0x01: Reserved
    emulator.write_physical_memory(ROM_BASE + 0x28, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0028] Vector 0x02: Non-maskable interrupt
    emulator.write_physical_memory(ROM_BASE + 0x30, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0030] Vector 0x03: Breakpoint (INT3)
    emulator.write_physical_memory(ROM_BASE + 0x38, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0038] Vector 0x04: Overflow (INTO)
    emulator.write_physical_memory(ROM_BASE + 0x40, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0040] Vector 0x05: Bounds range exceeded (BOUND)
    emulator.write_physical_memory(ROM_BASE + 0x48, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0048] Vector 0x06: Invalid opcode (UD2)
    emulator.write_physical_memory(ROM_BASE + 0x50, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0050] Vector 0x07: Device not available (WAIT/FWAIT)
    emulator.write_physical_memory(ROM_BASE + 0x58, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0058] Vector 0x08: Double fault
    emulator.write_physical_memory(ROM_BASE + 0x60, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0060] Vector 0x09: Coprocessor segment overrun
    emulator.write_physical_memory(ROM_BASE + 0x68, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0068] Vector 0x0A: Invalid TSS
    emulator.write_physical_memory(ROM_BASE + 0x70, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0070] Vector 0x0B: Segment not present
    emulator.write_physical_memory(ROM_BASE + 0x78, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0078] Vector 0x0C: Stack-segment fault
    emulator.write_physical_memory(ROM_BASE + 0x80, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0080] Vector 0x0D: General protection fault
    emulator.write_physical_memory(ROM_BASE + 0x88, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0088] Vector 0x0E: Page fault
    emulator.write_physical_memory(ROM_BASE + 0x90, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0090] Vector 0x0F: Reserved
    emulator.write_physical_memory(ROM_BASE + 0x98, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x0098] Vector 0x10: x87 FPU error
    emulator.write_physical_memory(ROM_BASE + 0xa0, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x00a0] Vector 0x11: Alignment check
    emulator.write_physical_memory(ROM_BASE + 0xa8, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x00a8] Vector 0x12: Machine check
    emulator.write_physical_memory(ROM_BASE + 0xb0, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x00b0] Vector 0x13: SIMD Floating-Point Exception

    for i in range(0x14, 0x20):
        emulator.write_physical_memory(ROM_BASE + 0xb8 + i * 8, b"\x05\x10\x08\x00\x00\x8f\x00\x10")  # [0x00b8..0x0110] Vector 0x14..0x1F: Reserved

    # IDT table (user defined)
    # All entries are present, 80386 32-bit trap gates, privilege level 0 and use selector 0x8
    emulator.write_physical_memory(ROM_BASE + 0x118, b"\x00\x10\x08\x00\x00\x8f\x00\x10")  # [0x0118] Vector 0x20: Just IRET       (offset 0x10001000)
    emulator.write_physical_memory(ROM_BASE + 0x120, b"\x02\x10\x08\x00\x00\x8f\x00\x10")  # [0x0120] Vector 0x21: HLT, then IRET  (offset 0x10001002)

    # entry point
    emulator.write_physical_memory(ROM_BASE + 0xff00, b"\x33\xc0")                         # [0xff00] xor    eax, eax
    emulator.write_physical_memory(ROM_BASE + 0xff02, b"\xb0\x10")                         # [0xff02] mov     al, 0x10
    emulator.write_physical_memory(ROM_BASE + 0xff04, b"\x8e\xd8")                         # [0xff04] mov     ds, eax
    emulator.write_physical_memory(ROM_BASE + 0xff06, b"\x8e\xc0")                         # [0xff06] mov     es, eax
    emulator.write_physical_memory(ROM_BASE + 0xff08, b"\x8e\xd0")                         # [0xff08] mov     ss, eax

    # Clear page directory
    emulator.write_physical_memory(ROM_BASE + 0xff0a, b"\xbf\x00\x10\x00\x00")             # [0xff0a] mov    edi, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xff0f, b"\xb9\x00\x10\x00\x00")             # [0xff0f] mov    ecx, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xff14, b"\x31\xc0")                         # [0xff14] xor    eax, eax
    emulator.write_physical_memory(ROM_BASE + 0xff16, b"\xf3\xab")                         # [0xff16] rep    stosd

    # Write 0xdeadbeef at physical memory address 0x5000
    emulator.write_physical_memory(ROM_BASE + 0xff18, b"\xbf\x00\x50\x00\x00")             # [0xff18] mov    edi, 0x5000
    emulator.write_physical_memory(ROM_BASE + 0xff1d, b"\xb8\xef\xbe\xad\xde")             # [0xff1d] mov    eax, 0xdeadbeef
    emulator.write_physical_memory(ROM_BASE + 0xff22, b"\x89\x07")                         # [0xff22] mov    [edi], eax

    # Identity map the RAM to 0x00000000
    emulator.write_physical_memory(ROM_BASE + 0xff24, b"\xb9\x00\x01\x00\x00")             # [0xff24] mov    ecx, 0xf0
    emulator.write_physical_memory(ROM_BASE + 0xff29, b"\xbf\x00\x20\x00\x00")             # [0xff29] mov    edi, 0x2000
    emulator.write_physical_memory(ROM_BASE + 0xff2e, b"\xb8\x03\x00\x00\x00")             # [0xff2e] mov    eax, 0x0003

    emulator.write_physical_memory(ROM_BASE + 0xff33, b"\xab")                             # [0xff33] stosd
    emulator.write_physical_memory(ROM_BASE + 0xff34, b"\x05\x00\x10\x00\x00")             # [0xff34] add    eax, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xff39, b"\xe2\xf8")                         # [0xff39] loop   aLoop

    # Identity map the ROM
    emulator.write_physical_memory(ROM_BASE + 0xff3b, b"\xb9\x10\x00\x00\x00")             # [0xff3b] mov    ecx, 0x10
    emulator.write_physical_memory(ROM_BASE + 0xff40, b"\xbf\xc0\x3f\x00\x00")             # [0xff40] mov    edi, 0x3fc0
    emulator.write_physical_memory(ROM_BASE + 0xff45, b"\xb8\x03\x00\x0f\x00")             # [0xff45] mov    eax, 0xf0003

    emulator.write_physical_memory(ROM_BASE + 0xff4a, b"\xab")                             # [0xff4a] stosd
    emulator.write_physical_memory(ROM_BASE + 0xff4b, b"\x05\x00\x10\x00\x00")             # [0xff4b] add    eax, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xff50, b"\xe2\xf8")                         # [0xff50] loop   bLoop

    # Map physical address 0x5000 to virtual address 0x10000000
    emulator.write_physical_memory(ROM_BASE + 0xff52, b"\xbf\x00\x40\x00\x00")             # [0xff52] mov    edi, 0x4000
    emulator.write_physical_memory(ROM_BASE + 0xff57, b"\xb8\x03\x50\x00\x00")             # [0xff57] mov    eax, 0x5003
    emulator.write_physical_memory(ROM_BASE + 0xff5c, b"\x89\x07")                         # [0xff5c] mov    [edi], eax

    # Map physical address 0x6000 to virtual address 0x10001000
    emulator.write_physical_memory(ROM_BASE + 0xff5e, b"\xbf\x04\x40\x00\x00")             # [0xff5e] mov    edi, 0x4004
    emulator.write_physical_memory(ROM_BASE + 0xff63, b"\xb8\x03\x60\x00\x00")             # [0xff63] mov    eax, 0x6003
    emulator.write_physical_memory(ROM_BASE + 0xff68, b"\x89\x07")                         # [0xff68] mov    [edi], eax

    # Map physical address 0xe0000000 to virtual address 0xe0000000 (for MMIO)
    emulator.write_physical_memory(ROM_BASE + 0xff6a, b"\xbf\x00\xe0\x00\x00")             # [0xff6a] mov    edi, 0xe000
    emulator.write_physical_memory(ROM_BASE + 0xff6f, b"\xb8\x03\x00\x00\xe0")             # [0xff6f] mov    eax, 0xe0000003
    emulator.write_physical_memory(ROM_BASE + 0xff74, b"\x89\x07")                         # [0xff74] mov    [edi], eax

    # Add page tables into page directory
    emulator.write_physical_memory(ROM_BASE + 0xff76, b"\xbf\x00\x10\x00\x00")             # [0xff76] mov    edi, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xff7b, b"\xb8\x03\x20\x00\x00")             # [0xff7b] mov    eax, 0x2003
    emulator.write_physical_memory(ROM_BASE + 0xff80, b"\x89\x07")                         # [0xff80] mov    [edi], eax
    emulator.write_physical_memory(ROM_BASE + 0xff82, b"\xbf\xfc\x1f\x00\x00")             # [0xff82] mov    edi, 0x1ffc
    emulator.write_physical_memory(ROM_BASE + 0xff87, b"\xb8\x03\x30\x00\x00")             # [0xff87] mov    eax, 0x3003
    emulator.write_physical_memory(ROM_BASE + 0xff8c, b"\x89\x07")                         # [0xff8c] mov    [edi], eax
    emulator.write_physical_memory(ROM_BASE + 0xff8e, b"\xbf\x00\x11\x00\x00")             # [0xff8e] mov    edi, 0x1100
    emulator.write_physical_memory(ROM_BASE + 0xff93, b"\xb8\x03\x40\x00\x00")             # [0xff93] mov    eax, 0x4003
    emulator.write_physical_memory(ROM_BASE + 0xff98, b"\x89\x07")                         # [0xff98] mov    [edi], eax
    emulator.write_physical_memory(ROM_BASE + 0xff9a, b"\xbf\x00\x1e\x00\x00")             # [0xff9a] mov    edi, 0x1e00
    emulator.write_physical_memory(ROM_BASE + 0xff9f, b"\xb8\x03\xe0\x00\x00")             # [0xff9f] mov    eax, 0xe003
    emulator.write_physical_memory(ROM_BASE + 0xffa4, b"\x89\x07")                         # [0xffa4] mov    [edi], eax

    # Load the page directory register
    emulator.write_physical_memory(ROM_BASE + 0xffa6, b"\xb8\x00\x10\x00\x00")             # [0xffa6] mov    eax, 0x1000
    emulator.write_physical_memory(ROM_BASE + 0xffab, b"\x0f\x22\xd8")                     # [0xffab] mov    cr3, eax

    # Enable paging
    emulator.write_physical_memory(ROM_BASE + 0xffae, b"\x0f\x20\xc0")                     # [0xffae] mov    eax, cr0
    emulator.write_physical_memory(ROM_BASE + 0xffb1, b"\x0d\x00\x00\x00\x80")             # [0xffb1] or     eax, 0x80000000
    emulator.write_physical_memory(ROM_BASE + 0xffb6, b"\x0f\x22\xc0")                     # [0xffb6] mov    cr0, eax

    # Clear EAX
    emulator.write_physical_memory(ROM_BASE + 0xffb9, b"\x31\xc0")                         # [0xffb9] xor    eax, eax

    # Load using virtual memory address EAX = 0xdeadbeef
    emulator.write_physical_memory(ROM_BASE + 0xffbb, b"\xbe\x00\x00\x00\x10")             # [0xffbb] mov    esi, 0x10000000
    emulator.write_physical_memory(ROM_BASE + 0xffc0, b"\x8b\x06")                         # [0xffc0] mov    eax, [esi]

    # First stop
    emulator.write_physical_memory(ROM_BASE + 0xffc2, b"\xf4")                             # [0xffc2] hlt

    # Jump to RAM
    emulator.write_physical_memory(ROM_BASE + 0xffc3, b"\xe9\x3c\x00\xf0\x0f")             # [0xffc3] jmp    0x10000004

    # Load GDT and IDT tables
    emulator.write_physical_memory(ROM_BASE + 0xffd0, b"\x66\x2e\x0f\x01\x16\xf2\xff")     # [0xffd0] lgdt   [cs:0xfff2]
    emulator.write_physical_memory(ROM_BASE + 0xffd7, b"\x66\x2e\x0f\x01\x1e\xf8\xff")     # [0xffd7] lidt   [cs:0xfff8]

    # Enter protected mode
    emulator.write_physical_memory(ROM_BASE + 0xffde, b"\x0f\x20\xc0")                     # [0xffde] mov    eax, cr0
    emulator.write_physical_memory(ROM_BASE + 0xffe1, b"\x0c\x01")                         # [0xffe1] or      al, 1
    emulator.write_physical_memory(ROM_BASE + 0xffe3, b"\x0f\x22\xc0")                     # [0xffe3] mov    cr0, eax
    emulator.write_physical_memory(ROM_BASE + 0xffe6, b"\x66\xea\x00\xff\x0f\x00\x08\x00")  # [0xffe6] jmp    dword 0x8:0x000fff00
    emulator.write_physical_memory(ROM_BASE + 0xffef, b"\xf4")                             # [0xffef] hlt

    # 16-bit real mode start -----------------------------------------------------------------------------------------

    # Jump to initialization code and define GDT/IDT table pointer

    emulator.write_physical_memory(ROM_BASE + 0xfff0, b"\xeb\xde")                         # [0xfff0] jmp    short 0x1d0
    emulator.write_physical_memory(ROM_BASE + 0xfff2, b"\x18\x00\x00\x00\x0f\x00")         # [0xfff2] GDT pointer: 0x000f0000:0x0018
    emulator.write_physical_memory(ROM_BASE + 0xfff8, b"\x10\x01\x18\x00\x0f\x00")         # [0xfff8] IDT pointer: 0x000f0018:0x0110

    # There's room for two bytes at the end, so let's fill it up with HLTs
    emulator.write_physical_memory(ROM_BASE + 0xfffe, b"\xf4")                             # [0xfffe] hlt
    emulator.write_physical_memory(ROM_BASE + 0xffff, b"\xf4")                             # [0xffff] hlt

    # Addresses 0x5000..0x5003 are reserved for 0xdeadbeef
    # Note that these addresses are mapped to virtual addresses 0x10000000 through 0x10000fff

    # Do some basic stuff
    emulator.write_physical_memory(RAM_BASE + 0x5004, b"\xba\x78\x56\x34\x12")             # [0x5004] mov    edx, 0x12345678
    emulator.write_physical_memory(RAM_BASE + 0x5009, b"\xbf\x00\x00\x00\x10")             # [0x5009] mov    edi, 0x10000000
    emulator.write_physical_memory(RAM_BASE + 0x500e, b"\x31\xd0")                         # [0x500e] xor    eax, edx
    emulator.write_physical_memory(RAM_BASE + 0x5010, b"\x89\x07")                         # [0x5010] mov    [edi], eax
    emulator.write_physical_memory(RAM_BASE + 0x5012, b"\xf4")                             # [0x5012] hlt

    # Setup a proper stack
    emulator.write_physical_memory(RAM_BASE + 0x5013, b"\x31\xed")                         # [0x5013] xor    ebp, ebp
    emulator.write_physical_memory(RAM_BASE + 0x5015, b"\xbc\x00\x00\x0f\x00")             # [0x5015] mov    esp, 0xf0000

    # Test the stack
    emulator.write_physical_memory(RAM_BASE + 0x501a, b"\x68\xfe\xca\x0d\xf0")             # [0x501a] push   0xf00dcafe
    emulator.write_physical_memory(RAM_BASE + 0x501f, b"\x5a")                             # [0x501f] pop    edx
    emulator.write_physical_memory(RAM_BASE + 0x5020, b"\xf4")                             # [0x5020] hlt

    # Call interrupts
    emulator.write_physical_memory(RAM_BASE + 0x5021, b"\xcd\x20")                         # [0x5021] int    0x20
    emulator.write_physical_memory(RAM_BASE + 0x5023, b"\xcd\x21")                         # [0x5023] int    0x21
    emulator.write_physical_memory(RAM_BASE + 0x5025, b"\xf4")                             # [0x5025] hlt

    # Basic PMIO
    emulator.write_physical_memory(RAM_BASE + 0x5026, b"\x66\xba\x00\x10")                 # [0x5026] mov     dx, 0x1000
    emulator.write_physical_memory(RAM_BASE + 0x502a, b"\xec")                             # [0x502a] in      al, dx
    emulator.write_physical_memory(RAM_BASE + 0x502b, b"\x66\x42")                         # [0x502b] inc     dx
    emulator.write_physical_memory(RAM_BASE + 0x502d, b"\x34\xff")                         # [0x502d] xor     al, 0xff
    emulator.write_physical_memory(RAM_BASE + 0x502f, b"\xee")                             # [0x502f] out     dx, al
    emulator.write_physical_memory(RAM_BASE + 0x5030, b"\x66\x42")                         # [0x5030] inc     dx
    emulator.write_physical_memory(RAM_BASE + 0x5032, b"\x66\xed")                         # [0x5032] in      ax, dx
    emulator.write_physical_memory(RAM_BASE + 0x5034, b"\x66\x42")                         # [0x5034] inc     dx
    emulator.write_physical_memory(RAM_BASE + 0x5036, b"\x66\x83\xf0\xff")                 # [0x5036] xor     ax, 0xffff
    emulator.write_physical_memory(RAM_BASE + 0x503a, b"\x66\xef")                         # [0x503a] out     dx, ax
    emulator.write_physical_memory(RAM_BASE + 0x503c, b"\x66\x42")                         # [0x503c] inc     dx
    emulator.write_physical_memory(RAM_BASE + 0x503e, b"\xed")                             # [0x503e] in     eax, dx
    emulator.write_physical_memory(RAM_BASE + 0x503f, b"\x66\x42")                         # [0x503f] inc     dx
    emulator.write_physical_memory(RAM_BASE + 0x5041, b"\x83\xf0\xff")                     # [0x5041] xor    eax, 0xffffffff
    emulator.write_physical_memory(RAM_BASE + 0x5044, b"\xef")                             # [0x5044] out     dx, eax

    # Basic MMIO
    emulator.write_physical_memory(RAM_BASE + 0x5045, b"\xbf\x00\x00\x00\xe0")             # [0x5045] mov    edi, 0xe0000000
    emulator.write_physical_memory(RAM_BASE + 0x504a, b"\x8b\x1f")                         # [0x504a] mov    ebx, [edi]
    emulator.write_physical_memory(RAM_BASE + 0x504c, b"\x83\xc7\x04")                     # [0x504c] add    edi, 4
    emulator.write_physical_memory(RAM_BASE + 0x504f, b"\x89\x1f")                         # [0x504f] mov    [edi], ebx

    # Advanced MMIO
    emulator.write_physical_memory(RAM_BASE + 0x5051, b"\xb9\x00\x00\x00\x10")             # [0x5051] mov    ecx, 0x10000000
    emulator.write_physical_memory(RAM_BASE + 0x5056, b"\x85\x0f")                         # [0x5056] test   [edi], ecx

    # End
    emulator.write_physical_memory(RAM_BASE + 0x5058, b"\xf4")                             # [0x5058] hlt

    # Interrupt handlers
    # Note that these addresses are mapped to virtual addresses 0x10001000 through 0x10001fff
    # 0x20: Just IRET
    emulator.write_physical_memory(RAM_BASE + 0x6000, b"\xfb")                             # [0x6000] sti
    emulator.write_physical_memory(RAM_BASE + 0x6001, b"\xcf")                             # [0x6001] iretd

    # 0x21: HLT, then IRET
    emulator.write_physical_memory(RAM_BASE + 0x6002, b"\xf4")                             # [0x6002] hlt
    emulator.write_physical_memory(RAM_BASE + 0x6003, b"\xfb")                             # [0x6003] sti
    emulator.write_physical_memory(RAM_BASE + 0x6004, b"\xcf")                             # [0x6004] iretd

    # 0x00 .. 0x1F: Clear stack then IRET
    emulator.write_physical_memory(RAM_BASE + 0x6005, b"\x83\xc4\x04")                     # [0x6005] add    esp, 4
    emulator.write_physical_memory(RAM_BASE + 0x6008, b"\xfb")                             # [0x6008] sti
    emulator.write_physical_memory(RAM_BASE + 0x6009, b"\xcf")                             # [0x6009] iretd

    exit = emulator.run()

    assert exit.rip == 0xfffc3
    rax = emulator.get_reg("rax")

    assert rax == 0xdeadbeef
    # FIXME: test exit reason is halt

    exit = emulator.run()

    assert exit.rip == 0x10000013
    # FIXME: test exit reason is halt
    # FIXME: test rdx == 0x12345678

    exit = emulator.run()

    assert exit.rip == 0x10000021

    exit = emulator.run()

    assert exit.rip == 0x10001003

    exit = emulator.run()

    assert exit.rip == 0x10000026

    exit = emulator.run()

    assert exit.rip == 0x1000002a

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 1)

    exit = emulator.run()

    assert exit.rip == 0x1000002f

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 1)

    exit = emulator.run()

    assert exit.rip == 0x10000032

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x1000003a

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x1000003e

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x10000044

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 1)

    exit = emulator.run()

    assert exit.rip == 0x1000004a

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x1000004f

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x10000056

    # emulating instruction
    emulator.set_reg("rip", exit.rip + 2)

    exit = emulator.run()

    assert exit.rip == 0x10000059

    # exit = emulator.run()

    # assert exit.rip != 0x0


def test_kernel_emulation():
    with open(os.path.join("tests", "RtlInitUnicodeString.json"), "r") as fp:
        context = json.load(fp)

    emulator = whvp.Emulator()

    # GDT
    emulator.set_table_reg("gdt", context["regs"]["gdtr"], context["regs"]["gdtl"])

    # IDT
    emulator.set_table_reg("idt", context["regs"]["idtr"], context["regs"]["idtl"])

    # CR0
    emulator.set_reg("cr0", context["regs"]["cr0"])

    # CR3
    emulator.set_reg("cr3", context["regs"]["cr3"])

    # CR4
    emulator.set_reg("cr4", context["regs"]["cr4"])

    # IA32 EFER
    emulator.set_reg("efer", context["efer"])

    emulator.set_segment_reg("cs", 0, 0, 1, 0, context["regs"]["cs"])
    emulator.set_segment_reg("ss", 0, 0, 0, 0, context["regs"]["ss"])
    emulator.set_segment_reg("ds", 0, 0, 0, 0, context["regs"]["ds"])
    emulator.set_segment_reg("es", 0, 0, 0, 0, context["regs"]["es"])

    emulator.set_segment_reg("fs", 0x40000, 0, 0, 0, context["regs"]["fs"])
    emulator.set_segment_reg("gs", context["kpcr"], 0, 0, 0, context["regs"]["gs"])

    emulator.set_reg("rax", context["regs"]["rax"])
    emulator.set_reg("rbx", context["regs"]["rbx"])
    emulator.set_reg("rcx", context["regs"]["rcx"])
    emulator.set_reg("rdx", context["regs"]["rdx"])
    emulator.set_reg("rsi", context["regs"]["rsi"])
    emulator.set_reg("rdi", context["regs"]["rdi"])
    emulator.set_reg("r8", context["regs"]["r8"])
    emulator.set_reg("r9", context["regs"]["r9"])
    emulator.set_reg("r10", context["regs"]["r10"])
    emulator.set_reg("r11", context["regs"]["r11"])
    emulator.set_reg("r12", context["regs"]["r12"])
    emulator.set_reg("r13", context["regs"]["r13"])
    emulator.set_reg("r14", context["regs"]["r14"])
    emulator.set_reg("r15", context["regs"]["r15"])

    emulator.set_reg("rbp", context["regs"]["rbp"])
    emulator.set_reg("rsp", context["regs"]["rsp"])

    emulator.set_reg("rip", context["regs"]["rip"])

    emulator.set_reg("rflags", 0x202 | 0x100)
    return_address = context["return_address"]

    max_exits = 25

    exits = []
    exit = emulator.run()

    for i in range(max_exits):
        exit = emulator.run()
        exits.append(exit)
        print(exit)

        if exit.reason == whvp.WHvRunVpExitReasonMemoryAccess:
            gpa = exit.gpa
            base = gpa & ~0xfff
            pfn = gpa >> 12
            print(F"writing pfn {pfn:x}")

            data = context["pfn"][str(pfn)]
            data = base64.b64decode(data)

            emulator.allocate_physical_memory(base, 0x1000)
            emulator.write_physical_memory(base, data)

        if exit.reason == whvp.WHvRunVpExitReasonException:
            if exit.exception_type == 1:
                if exit.rip == return_address:
                    print("got return address")
                    break

    assert exits[0].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[0].rip == 0xfffff80046efeb50
    assert exits[0].gpa == 0x3dc5f80

    assert exits[1].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[1].rip == 0xfffff80046efeb50
    assert exits[1].gpa == 0x1108008

    assert exits[2].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[2].rip == 0xfffff80046efeb50
    assert exits[2].gpa == 0x11091b8

    assert exits[3].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[3].rip == 0xfffff80046efeb50
    assert exits[3].gpa == 0x11137f0

    assert exits[4].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[4].rip == 0xfffff80046efeb50
    assert exits[4].gpa == 0x1fe0b50

    assert exits[5].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[5].rip == 0xfffff80046efeb50
    assert exits[5].gpa == 0x5a71d8

    assert exits[6].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[6].rip == 0xfffff80046efeb50
    assert exits[6].gpa == 0x5a8490

    assert exits[7].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[7].rip == 0xfffff80046efeb50
    assert exits[7].gpa == 0x69423be0

    assert exits[8].reason == whvp.WHvRunVpExitReasonMemoryAccess
    assert exits[8].rip == 0xfffff80046efeb50
    assert exits[8].gpa == 0x706e8f90

    assert exits[9].reason == whvp.WHvRunVpExitReasonException
    assert exits[9].rip == 0xfffff80046efeb57

    assert exits[10].reason == whvp.WHvRunVpExitReasonException
    assert exits[10].rip == 0xfffff80046efeb5b

    assert exits[11].reason == whvp.WHvRunVpExitReasonException
    assert exits[11].rip == 0xfffff80046efeb5e

    assert exits[12].reason == whvp.WHvRunVpExitReasonException
    assert exits[12].rip == 0xfffff80046efeb60

    assert exits[13].reason == whvp.WHvRunVpExitReasonException
    assert exits[13].rip == return_address


@pytest.mark.skip("not implemented")
def test_infinite_loop():
    pass
