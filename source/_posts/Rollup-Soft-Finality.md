---
title: "知识点：Rollup Soft Finality 回滚导致的跨链双花"
date: 2025-08-03
categories:
  - 区块链安全
  - Web3
tags:
  - blockchain
  - CTF
  - Rollup
  - bridge
---

知识点：Rollup Soft Finality 回滚导致的跨链双花
1. 背景
论文 《DoubleUp Roll: Double-spending in Arbitrum by Rolling It Back》 研究的是 Optimistic Rollup 中一种很典型的漏洞模式：跨链应用过早相信 L2 的 soft finality，导致源链交易后来被回滚，但目标链资产已经发放，从而形成双花。 论文中作者披露了 Arbitrum 上三类双花攻击，并说明部分攻击思路也能迁移到 Optimism；这些问题已在 2022–2023 年报告给 Arbitrum 和 Optimism 团队并修复。
这个知识点的关键不是“传统 51% 攻击”，而是 Rollup 状态机和跨链桥状态机之间的确认语义不一致。

2. 核心概念：soft finality vs hard finality
在 Optimistic Rollup 中，一笔 L2 交易通常会经历两个阶段：
其中：
Soft Finality
交易已经被 L2 sequencer 执行，用户和应用可以看到交易成功。
但是，这个状态还不是最终状态，后续仍可能因为 L1/L2 同步、batch invalid、强制包含、时间戳修正等原因被回滚。
Hard Finality
交易数据已经被提交到 L1，并获得 L1 层面的确认。
这时交易结果才更接近真正不可逆。

3. 漏洞本质
这类漏洞可以总结成一句话：
抽象流程如下：
所以，漏洞点不是单个 Solidity 函数里的 transfer，而是整个跨链系统的状态机假设错了：

4. 三类攻击
4.1 Overtime Attack：利用时间边界触发回滚
Arbitrum 有时间边界机制，用于限制 L2 时间戳和 L1 时间戳之间的偏移。论文的攻击思路是：先制造 L2 到 L1 的提交延迟，使某些交易长时间停留在 soft-finalized 状态；当延迟超过时间边界后，系统修正时间戳，导致 soft-finalized 状态和 hard-finalized 状态不一致，进而触发 rollback。
可以抽象成：
出题关键词：
应该重点检查：

4.2 QueueCut Attack：利用 Force Inclusion 改变交易顺序
Rollup 为了抗审查，会允许用户绕过 sequencer，直接从 L1 提交 L1→L2 消息。等待窗口结束后，用户可以调用 force inclusion，让消息强制进入 L2。Arbitrum 文档中也描述了 Delayed Inbox 和 forceInclude 的流程：如果 sequencer 没有处理交易，等待后可以调用 forceInclude 保证包含。
论文中的 QueueCut Attack 利用的就是这个机制：攻击者先制造延迟，让某些 L2 soft-finalized 交易还没提交到 L1；然后通过 L1→L2 强制包含消息改变 canonical queue，导致 L2 原先的 soft queue 和最终 L1 hard queue 不一致，从而触发 rollback。
可以写成：
典型合约接口可能长这样：


4.3 Zip-Bomb Attack：压缩前后大小检查不一致
Arbitrum 当时的 transaction compression / decompression 机制存在不一致：解压阶段有 size-bound check，但压缩打包阶段没有对应的明文大小检查。攻击者可以构造大量高压缩率数据，比如大量 0x00，使压缩后的 batch 很小，但解压后超过上限。L2 节点从 L1 读取 batch 后解压，发现超限，于是判定 batch invalid，导致 soft-finalized 交易回滚。
通常会变成：
攻击 payload：
因为大量 0 极易压缩，所以：
最终目标不是单纯 DoS，而是让系统进入：
可能常见 flag 条件：
意思是：玩家在目标链拿到了钱，同时源链的钱也没少。

5. 可能的CTF 解题 checklist
遇到 Rollup / Bridge / L2 / Cross-chain 题，优先看下面几点。
5.1 桥是不是过早确认？
危险代码：
更安全的逻辑应该类似：
如果题目里只有 executed、confirmed、relayed，但没有 finalized，要高度怀疑。

5.2 是否存在 rollback 分支？
搜这些函数名：
如果系统里有 rollback，但桥的状态没有一起撤销，就可能形成双花。

5.3 是否存在双队列？
重点观察：
漏洞通常出现在：

5.4 是否存在压缩 / 解压不一致？
危险模式：
这种题目通常是 Zip-Bomb 方向。

5.5 是否存在跨链状态未同步撤销？
错误状态机：
如果 RolledBack 后没有把 Minted 撤销，就是漏洞。
更完整的状态机应该考虑：

6. 和普通 Bridge CTF 的区别
普通 Bridge CTF 常见漏洞是：
而 DoubleUp Roll 这篇论文对应的知识点更偏系统层：
也就是说，攻击者不是让桥“相信一个假事件”，而是让桥“过早相信一个之后会消失的真事件”。
这是它和很多普通 bridge 题的本质区别。

7. 对应的公开题目参考
这类东西可能出题难度比较高，只找到这两个
Real World CTF 6th - SafeBridge
这个题是 Web3 / Solidity / Cross-chain Bridge 方向，目标是 drain L1 bridge 里的 WETH；CTFtime 页面标注了标签 blockchain bridge smart-contract，题目目标是把 L1 bridge 里的资产清空。
它和 DoubleUp Roll 的关系是：
SafeBridge 不是直接考 Arbitrum rollback / soft finality / hard finality，但是它和这篇论文属于同一个大类知识点：
跨链系统中，两边链的状态映射不一致，导致桥的记账状态和真实资产状态脱节。
题目链接：github.com
wp参考链接：1、Real World CTF 6th – SafeBridge
2、CTFtime.org / Real World CTF 6th / SafeBridge / Writeup
3、CTFtime.org / Paradigm CTF 2023 / Hopping into Place / Writeup
参考：Paradigm CTF 2023 里也有跨链桥相关 writeup，作者思路是“欺骗 bridge 认为另一条链发来了一笔跨链 ETH transfer，然后 withdraw bridge 里的资产”，适合补充练习 bridge 状态机和 cross-domain messenger 思维。
wp参考：1、Blockchain - Enterprise Blockchain - Chictf-Writeups
2、🍳 Paradigm CTF 2023 Writeups
3、cn-sec.com
