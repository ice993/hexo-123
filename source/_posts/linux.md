---
title: "Linux 工具使用笔记"
date: 2025-04-01
categories:
  - 工具
tags:
  - Linux
  - tools
---

FinalShell远程连接


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1757179509280-81344924-e5c0-492b-affc-570c4f39adec.png)

运行时输入

```plain
ifconfig
```

ens33.有一个ip地址


![](https://cdn.nlark.com/yuque/0/2025/png/58878864/1757179639242-48ac0a64-4a19-4b1f-960d-c2c3a276ff1a.png)


## 写shellcode用到的汇编：
 当rax为0时。用cdq可以直接把rdx置零

```z80
cdq
#=
xor edx,edx
```