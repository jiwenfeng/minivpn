# MiniVPN

极简高性能两跳 VPN 隧道。C 语言实现，7 平台系统自带 VPN 直连，零证书，智能路由，IPv4/IPv6 双栈。

## 特性

- **系统自带 VPN** — 客户端使用 L2TP/IPsec PSK，iOS / iPadOS / macOS / Android / HarmonyOS / Windows / Linux 无需安装任何 App
- **零证书** — 全程预共享密钥 + 用户名密码，无需管理或分发证书
- **智能路由** — 国内 IP 直连，国外 IP 走隧道，基于 APNIC 数据自动更新
- **IPv4/IPv6 双栈** — 隧道端口支持 IPv4 和 IPv6，TUN 设备可同时配置 IPv4 和 IPv6 地址
- **AES-256-GCM 加密** — HKDF-SHA256 派生密钥，随机填充抗流量分析
- **多隧道多线程** — SO_REUSEPORT 多 Worker，每个 Worker 独立 epoll + crypto_ctx，共享认证状态，所有 Worker 可读写 TUN
- **抗封锁** — 两跳架构，国内段标准 L2TP，跨境段自定义 UDP 协议，无明显特征
- **极简实现** — 纯 C 语言，仅依赖 libcrypto + libpthread，约 2000 行代码

## 架构

```
┌──────────┐    L2TP/IPsec PSK    ┌──────────────┐  自定义UDP隧道  ┌──────────────┐
│  客户端  │ ──────────────────> │  近端(国内)  │ ────────────> │  远端(海外)  │ ──> 目标网站
│ 系统自带  │  零证书,7平台原生    │ strongSwan   │  AES-256-GCM   │  minivpn     │     NAT转发
│   VPN    │                     │ + minivpn    │  随机填充       │  + iptables  │
└──────────┘                     └──────────────┘                └──────────────┘
                                       │
                                  策略路由判断
                                  ├─ 国内IP → 直连(默认网关)
                                  └─ 国外IP → 隧道转发
```

**数据流**：客户端 →(L2TP/IPsec)→ 近端 →(策略路由判断)→ 国内直连 / 自定义隧道 →(NAT)→ 目标

## 快速开始

### 1. 部署远端（海外服务器）

```bash
# 在海外服务器上执行（Ubuntu 22.04+ / Debian 12+）
sudo bash deploy-exit.sh -k "你的隧道密钥" -p 4567
```

### 2. 部署近端（国内服务器）

```bash
# 在国内服务器上执行
sudo bash deploy-entry.sh \
    -r 远端IP:4567 \
    -k "你的隧道密钥" \
    --vpn-psk "VPN预共享密钥" \
    --add-user user1:password123
```

### 3. 添加用户

```bash
sudo bash add-user.sh alice mypassword
```

### 4. 客户端连接

在手机/电脑上使用系统自带 VPN 功能，选择 **L2TP/IPsec PSK**，填入：

| 信息 | 值 |
|------|-----|
| 服务器地址 | 近端服务器 IP |
| VPN 类型 | L2TP/IPsec PSK |
| 预共享密钥 | 部署时设置的 `--vpn-psk` 值 |
| 用户名 | 添加的用户名 |
| 密码 | 添加的密码 |

> 各平台详细配置步骤见 [客户端配置指南](docs/client-guide.md)

## 手动编译安装

**依赖**：gcc、make、libssl-dev（OpenSSL）

```bash
# 安装依赖（Ubuntu/Debian）
sudo apt install -y gcc make libssl-dev

# 编译
make

# 安装到 /usr/local/bin/
sudo make install

# 卸载
sudo make uninstall
```

## 配置文件

配置文件为简单 INI 格式，默认路径 `/etc/minivpn/minivpn.conf`。

```ini
# 运行模式: server 或 client
mode = server

# 监听地址（server 模式）
listen = 0.0.0.0:4567
# IPv6: listen = [::]:4567

# 远端地址（client 模式）
# remote = 1.2.3.4:4567
# IPv6: remote = [2001:db8::1]:4567

# 隧道预共享密钥（两端必须一致）
secret = change-me-to-a-strong-secret

# TUN 设备 IPv4
tun_ip = 172.16.0.1
tun_peer = 172.16.0.2

# TUN 设备 IPv6（可选，启用双栈）
# tun_ip6 = fd00::1
# tun_peer6 = fd00::2
# tun_ip6_prefix = 64

# 强制 IPv6 (yes/no，默认 no=自动检测)
# ipv6 = no

# Worker 线程数（默认为 CPU 核数）
# threads = 4

# MTU（默认 1400）
# mtu = 1400

# 日志级别: 0=ERROR, 1=INFO, 2=DEBUG
log_level = 1
```

> 命令行参数优先级高于配置文件。示例配置见 [configs/minivpn.conf.example](configs/minivpn.conf.example)。

## 命令行参数

```
用法: minivpn [选项]

模式:
  -s, --server             服务端模式（远端）
  -c, --client             客户端模式（近端）

网络:
  -l, --listen ADDR:PORT   监听地址（如 0.0.0.0:4567 或 [::]:4567）
  -r, --remote ADDR:PORT   远端地址（如 1.2.3.4:4567 或 [::1]:4567）
  -k, --secret KEY         预共享密钥
      --secret-file FILE   从文件读取密钥
  -6, --ipv6               强制使用 IPv6

TUN 设备:
      --tun-ip IP          TUN 本端 IPv4（如 172.16.0.1）
      --tun-peer IP        TUN 对端 IPv4（如 172.16.0.2）
      --tun-ip6 IP6        TUN 本端 IPv6（如 fd00::1，可选）
      --tun-peer6 IP6      TUN 对端 IPv6（如 fd00::2，可选）
      --mtu N              MTU（默认 1400）

性能:
  -t, --threads N          Worker 线程数（默认=CPU核数）

其它:
  -f, --config FILE        配置文件路径
  -v, --verbose            增加日志级别（可多次 -vv）
  -h, --help               显示帮助
  -V, --version            显示版本号
```

**使用示例**：

```bash
# 远端 - 服务端模式（IPv4）
minivpn -s -l 0.0.0.0:4567 -k mysecret --tun-ip 172.16.0.1 --tun-peer 172.16.0.2

# 远端 - 服务端模式（IPv6 双栈）
minivpn -s -l [::]:4567 -k mysecret --tun-ip 172.16.0.1 --tun-peer 172.16.0.2 --tun-ip6 fd00::1

# 近端 - 客户端模式
minivpn -c -r 远端IP:4567 -k mysecret --tun-ip 172.16.0.2 --tun-peer 172.16.0.1

# 使用配置文件
minivpn -f /etc/minivpn/minivpn.conf
```

## 智能路由

近端通过策略路由实现国内外流量分流：

- **路由表 200**（cn_direct）：中国大陆 IP 段走默认网关直连
- **路由表 201**（tunnel）：其他流量走 TUN 隧道转发到远端

路由数据来源于 [APNIC](https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)，部署时自动初始化，并通过 cron 每周自动更新。

**手动更新路由**：

```bash
sudo bash /opt/minivpn/scripts/update-routes.sh
```

路由更新为热更新，使用 `ip -batch` 批量操作，即时生效，已有连接不中断。

## 管理命令

### 用户管理

```bash
# 添加用户
sudo bash add-user.sh <用户名> <密码>

# 删除用户
sudo bash add-user.sh -d <用户名>

# 列出所有用户
sudo bash add-user.sh -l
```

### 服务管理

```bash
# 查看服务状态
systemctl status minivpn

# 重启服务
systemctl restart minivpn

# 查看实时日志
journalctl -u minivpn -f

# 近端额外服务
systemctl status ipsec      # IPsec (strongSwan)
systemctl status xl2tpd     # L2TP
```

### 路由更新

```bash
# 手动更新中国大陆 IP 路由
sudo bash /opt/minivpn/scripts/update-routes.sh

# 查看路由更新日志
cat /var/log/minivpn-routes.log
```

## 安全设计

| 层面 | 方案 |
|------|------|
| 国内段加密 | L2TP/IPsec（系统原生，预共享密钥） |
| 跨境段加密 | 自定义 UDP + AES-256-GCM |
| 密钥派生 | HKDF-SHA256：预共享密钥 → encrypt_key(32B) + auth_key(32B) |
| 认证 | AUTH 帧：时间戳(8B) + 随机 nonce(32B) + HMAC-SHA256，±300 秒容差 |
| 抗重放 | 滑动窗口 2048 位 bitmap，基于 Nonce 前 8 字节序列号 |
| 抗流量分析 | 每帧随机填充 0~255 字节 Padding |
| 密钥安全 | 配置文件 chmod 600，内存中使用 OPENSSL_cleanse 擦除 |
| DNS 分流 | PPP 下发国内 DNS（223.5.5.5/119.29.29.29），避免 DNS 泄漏 |

### 帧格式

```
[Nonce:12B][加密区: Type:1B | Len:2B | Payload:0~1400B | Padding:随机][Tag:16B]
     ↑                    AES-256-GCM 加密                              ↑
   明文随机数                                                    认证标签
```

| Type | 说明 |
|:----:|------|
| 0x01 | DATA — IP 数据包 |
| 0x02 | PING — 心跳请求 |
| 0x03 | PONG — 心跳响应 |
| 0x04 | AUTH — 认证请求 |
| 0x05 | OK — 认证通过 |

## 性能调优

### 线程数

默认等于 CPU 核数，通过 `--threads` 或配置文件 `threads` 调整。每个线程维护独立的 UDP socket（SO_REUSEPORT）和 epoll，按源 IP 哈希分配，避免锁竞争。

### MTU

默认 1400，考虑到 L2TP/IPsec 头部开销。如果发现分片严重可适当降低：

```bash
minivpn -s -l 0.0.0.0:4567 -k mysecret --mtu 1300 --tun-ip 172.16.0.1 --tun-peer 172.16.0.2
```

### 系统参数

```bash
# 增大 UDP 缓冲区
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400

# 增大文件描述符限制
ulimit -n 65536
```

## 项目结构

```
minivpn/
├── src/
│   ├── main.c          # 入口，参数解析，配置读取，IPv6 地址解析
│   ├── server.c        # 远端：多 Worker UDP 监听 → 认证 → epoll 转发
│   ├── client.c        # 近端：多 Worker UDP 连接 → 认证 → epoll 转发 → 重连
│   ├── worker.c/h      # Worker 线程结构（共享认证状态、多线程 TUN 读写、IPv4/IPv6）
│   ├── tun.c/h         # Linux TUN 设备操作（IPv4 + IPv6 地址配置）
│   ├── protocol.c/h    # 帧编解码 + AES-256-GCM + HKDF + 抗重放
│   ├── config.h        # 统一配置结构（含 IPv6 字段和辅助函数）
│   └── log.h           # 日志宏
├── scripts/
│   ├── deploy-exit.sh      # 远端一键部署
│   ├── deploy-entry.sh     # 近端一键部署
│   ├── gen-config.sh       # 客户端配置文件生成
│   ├── update-routes.sh    # APNIC 中国大陆路由更新（awk 高效解析）
│   └── add-user.sh         # VPN 用户管理
├── configs/
│   └── minivpn.conf.example  # 配置文件示例（含 IPv6 选项）
├── docs/
│   ├── client-guide.md     # 7 平台客户端配置指南
│   └── code-review.md      # 代码审查报告
├── plans/
│   └── architecture.md     # 架构设计文档
├── Makefile
├── .gitignore
├── LICENSE               # MIT 许可证
└── README.md
```

## 许可证

[MIT](LICENSE)
