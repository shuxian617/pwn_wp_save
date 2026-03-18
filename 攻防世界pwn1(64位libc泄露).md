#先看看相关的知识点

###### 1，canary的泄露

canary的最后一个字节是/x00，又因为是小端序，所以这个是在第一个的，所以我们可以通过溢出，把这个值给溢出掉，从而打印的时候把canary一起打印出来

###### 2，libc泄露

使用plt表打印got表的内容

###### 3，ROPgadget的使用

​	`ROPgadget --binary ./**** | grep '***'`

###### 4，LibcSearch的使用

> ​	`obj = LibcSearcher('puts',putgot)`
>
> ​    `libcbase = putgot - obj.dump("puts")`
>
> ​    `binsh = libcbase + obj.dump("str_bin_sh")`
>
> ​    `sy = libcbase + obj.dump('system')`

###### 5，x64的函数调用（pop rdi,ret)

​	`rdi rsi rdx rcx r8 r9` 