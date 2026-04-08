# MiniVPN 客户端配置指南

所有平台均使用系统自带 VPN 功能，无需安装任何 App。

## 连接信息

配置前请准备以下信息（由管理员提供）：

| 信息 | 说明 | 示例 |
|------|------|------|
| 服务器地址 | 近端服务器 IP | `1.2.3.4` |
| VPN 类型 | 固定选择 | L2TP/IPsec PSK |
| 预共享密钥 | 部署时 `--vpn-psk` 设置的值 | `my-psk-key` |
| 用户名 | `add-user.sh` 添加的用户 | `alice` |
| 密码 | 对应的密码 | `password123` |

---

## iOS / iPadOS

**适用版本**：iOS 15 及以上 / iPadOS 15 及以上

> **提示**：iPadOS 与 iOS 的 VPN 配置步骤完全一致。

1. 打开 **设置**
2. 点击 **通用**
3. 点击 **VPN 与设备管理**（较旧版本为「VPN」）
4. 点击 **VPN**
5. 点击 **添加 VPN 配置...**
6. 填写以下信息：

| 字段 | 值 |
|------|-----|
| 类型 | **L2TP** |
| 描述 | 自定义名称，如 `MiniVPN` |
| 服务器 | 近端服务器 IP |
| 帐户 | 你的用户名 |
| RSA SecurID | 关闭 |
| 密码 | 你的密码 |
| 密钥 | 预共享密钥 |
| 发送所有流量 | **开启** |

7. 点击右上角 **完成**
8. 回到 VPN 页面，打开开关连接

> **提示**：也可以在「设置」主页面直接看到 VPN 开关，方便快速开关。

---

## macOS

**适用版本**：macOS 13 Ventura 及以上

1. 打开 **系统设置**（Apple 菜单 → 系统设置）
2. 左侧点击 **VPN**
3. 点击 **添加 VPN 配置** → 选择 **L2TP（通过 IPSec）**
4. 填写以下信息：

| 字段 | 值 |
|------|-----|
| 显示名称 | 自定义名称，如 `MiniVPN` |
| 服务器地址 | 近端服务器 IP |
| 帐户名称 | 你的用户名 |
| 用户鉴定 | **密码** |
| 密码 | 你的密码 |
| 机器鉴定 | **共享的密钥** |
| 共享的密钥 | 预共享密钥 |

5. 点击 **创建**
6. 回到 VPN 页面，点击新创建的连接旁的开关连接

### 通过所有流量

连接后若需所有流量走 VPN：

1. 点击已创建的 VPN 连接右侧的 ⓘ
2. 点击 **详细信息...**
3. 勾选 **通过 VPN 连接发送所有流量**
4. 点击 **好**

---

## Android

**适用版本**：Android 10 及以上

1. 打开 **设置**
2. 点击 **网络和互联网**（部分机型为「连接」或「更多连接」）
3. 点击 **VPN**
4. 点击右上角 **+**（添加 VPN）
5. 填写以下信息：

| 字段 | 值 |
|------|-----|
| 名称 | 自定义名称，如 `MiniVPN` |
| 类型 | **L2TP/IPSec PSK** |
| 服务器地址 | 近端服务器 IP |
| L2TP 密钥 | 留空 |
| IPSec 标识符 | 留空 |
| IPSec 预共享密钥 | 预共享密钥 |
| 用户名 | 你的用户名 |
| 密码 | 你的密码 |

6. 点击 **保存**
7. 点击刚创建的 VPN 名称，点击 **连接**

> **提示**：首次使用可能需要设置屏幕锁（PIN / 密码 / 指纹）。

---

## HarmonyOS（鸿蒙）

**适用版本**：HarmonyOS 3.0 及以上（华为手机/平板）

1. 打开 **设置**
2. 点击 **更多连接**
3. 点击 **VPN**
4. 点击右上角 **+**（添加 VPN 网络）
5. 填写以下信息：

| 字段 | 值 |
|------|-----|
| 名称 | 自定义名称，如 `MiniVPN` |
| 类型 | **L2TP/IPSec PSK** |
| 服务器地址 | 近端服务器 IP |
| L2TP 密钥 | 留空 |
| IPSec 标识符 | 留空 |
| IPSec 预共享密钥 | 预共享密钥 |
| 用户名 | 你的用户名 |
| 密码 | 你的密码 |

6. 点击 **保存**
7. 点击刚创建的 VPN，点击 **连接**

> **提示**：HarmonyOS 的 VPN 配置界面与 Android 基本一致，操作步骤相同。

---

## Windows 10/11

**适用版本**：Windows 10 1903 及以上 / Windows 11

### 配置步骤

1. 打开 **设置**（Win + I）
2. 点击 **网络和 Internet**
3. 点击 **VPN**
4. 点击 **添加 VPN**（Windows 11）或 **添加 VPN 连接**（Windows 10）
5. 填写以下信息：

| 字段 | 值 |
|------|-----|
| VPN 提供商 | **Windows（内置）** |
| 连接名称 | 自定义名称，如 `MiniVPN` |
| 服务器名称或地址 | 近端服务器 IP |
| VPN 类型 | **使用预共享密钥的 L2TP/IPsec** |
| 预共享密钥 | 预共享密钥 |
| 登录信息的类型 | **用户名和密码** |
| 用户名 | 你的用户名 |
| 密码 | 你的密码 |

6. 点击 **保存**
7. 回到 VPN 页面，点击刚创建的连接，点击 **连接**

### ⚠️ 重要：注册表修复

Windows 默认可能无法连接 NAT 后面的 L2TP/IPsec 服务器。如果连接失败，需要修改注册表：

**方法一：命令行（推荐）**

以**管理员身份**打开 PowerShell，执行：

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -Value 2 -PropertyType DWORD -Force
```

执行后**重启电脑**生效。

**方法二：手动修改注册表**

1. 按 `Win + R`，输入 `regedit`，回车
2. 导航到：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent`
3. 右键空白处 → **新建** → **DWORD (32 位) 值**
4. 名称设为：`AssumeUDPEncapsulationContextOnSendRule`
5. 双击，将值设为 `2`
6. **重启电脑**

> **说明**：此注册表项允许 Windows 在 NAT 环境下使用 L2TP/IPsec，是微软官方推荐的配置。

---

## Linux

### 方式一：NetworkManager GUI

**前提**：安装 L2TP 插件

```bash
# Ubuntu/Debian
sudo apt install -y network-manager-l2tp network-manager-l2tp-gnome

# Fedora
sudo dnf install -y NetworkManager-l2tp NetworkManager-l2tp-gnome
```

1. 打开 **设置** → **网络**
2. 点击 VPN 旁的 **+**
3. 选择 **Layer 2 Tunneling Protocol (L2TP)**
4. 填写：

| 字段 | 值 |
|------|-----|
| 名称 | `MiniVPN` |
| 网关 | 近端服务器 IP |
| 用户名 | 你的用户名 |
| 密码 | 你的密码 |

5. 点击 **IPsec Settings...**
6. 勾选 **Enable IPsec tunnel to L2TP host**
7. **Pre-shared key** 填入预共享密钥
8. 点击 **OK** → **Add**
9. 打开 VPN 开关连接

### 方式二：nmcli 命令行

```bash
# 安装 L2TP 插件
sudo apt install -y network-manager-l2tp

# 添加 VPN 连接
nmcli connection add \
    type vpn \
    vpn-type l2tp \
    con-name "MiniVPN" \
    vpn.data "gateway=近端服务器IP, ipsec-enabled=yes, ipsec-psk=预共享密钥, user=你的用户名" \
    vpn.secrets "password=你的密码"

# 连接
nmcli connection up MiniVPN

# 断开
nmcli connection down MiniVPN

# 删除
nmcli connection delete MiniVPN
```

---

## 常见问题

### 连接不上？

1. **检查服务器状态**：
   ```bash
   # 在近端服务器上执行
   systemctl status ipsec
   systemctl status xl2tpd
   systemctl status minivpn
   ```

2. **检查防火墙**：确保近端服务器开放了 UDP 500、4500、1701 端口
   ```bash
   sudo iptables -L INPUT -n | grep -E "500|4500|1701"
   ```

3. **Windows 用户**：确认已添加注册表项并重启（见上文 Windows 章节）

4. **检查用户名密码**：
   ```bash
   sudo bash add-user.sh -l    # 确认用户存在
   ```

5. **查看日志**：
   ```bash
   journalctl -u ipsec -n 50     # IPsec 日志
   journalctl -u xl2tpd -n 50    # L2TP 日志
   ```

### 连接上但无法上网？

1. **检查 IP 转发**：
   ```bash
   sysctl net.ipv4.ip_forward    # 应为 1
   ```

2. **检查 NAT 规则**：
   ```bash
   sudo iptables -t nat -L POSTROUTING -n
   ```

3. **检查隧道状态**（近端到远端）：
   ```bash
   systemctl status minivpn
   ping -c 3 172.16.0.1    # ping 远端 TUN IP
   ```

4. **检查路由表**：
   ```bash
   ip route show table 200 | head    # 中国大陆直连路由
   ip route show table 201           # 隧道默认路由
   ```

### 速度慢？

1. **增加线程数**：编辑 `/etc/minivpn/minivpn.conf`，增大 `threads` 值

2. **调整 MTU**：如果有大量分片，尝试降低 MTU 到 1300

3. **检查服务器负载**：
   ```bash
   top -bn1 | head -5
   ```

4. **增大 UDP 缓冲区**：
   ```bash
   sudo sysctl -w net.core.rmem_max=26214400
   sudo sysctl -w net.core.wmem_max=26214400
   ```

5. **选择更近的服务器**：近端服务器应选择延迟最低的国内节点，远端选择到目标网站延迟最低的海外节点
