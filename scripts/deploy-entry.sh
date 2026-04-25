#!/bin/bash
set -e

###############################################################################
# deploy-entry.sh - MiniVPN 近端（国内入口）一键部署脚本
# 用法: ./deploy-entry.sh -r <远端IP:端口> -k <隧道密钥> --vpn-psk <VPN预共享密钥>
#       [--add-user user:pass] [--tun-ip <ip>] [--tun-peer <ip>]
#       [--tun-ip6 <ip6>] [--tun-peer6 <ip6>] [-6]
# 面向: Ubuntu 22.04+ / Debian 12+
###############################################################################

# ─── 颜色输出 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal()   { error "$*"; exit 1; }

# ─── 默认值 ──────────────────────────────────────────────────────────────────
REMOTE_ADDR=""       # 远端 IP:端口
SECRET=""            # 隧道密钥
VPN_PSK=""           # L2TP/IPsec 预共享密钥
TUN_IP="172.16.0.2"  # 近端TUN IP（client端）
TUN_PEER="172.16.0.1" # 远端TUN IP（server端）
TUN_IP6=""           # IPv6 TUN 本端地址（可选）
TUN_PEER6=""         # IPv6 TUN 对端地址（可选）
TUN_IP6_PREFIX=64    # IPv6 前缀长度
USE_IPV6=0           # 是否使用 IPv6 连接远端
ADD_USERS=()         # 要添加的用户列表 user:pass
TUN_DEV="tun0"       # TUN 设备名（需与 minivpn 创建的一致）
SRC_DIR="/opt/minivpn"
CONF_DIR="/etc/minivpn"
CONF_FILE="${CONF_DIR}/minivpn.conf"
SERVICE_FILE="/etc/systemd/system/minivpn.service"

# ─── 函数：检查root权限 ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "此脚本必须以root权限运行，请使用 sudo 或切换到root用户"
    fi
}

# ─── 函数：显示用法 ──────────────────────────────────────────────────────────
usage() {
    cat <<EOF
用法: $0 -r <远端IP:端口> -k <隧道密钥> --vpn-psk <VPN预共享密钥> [选项]

必须参数:
  -r, --remote <IP:PORT>         远端服务器地址和端口（如 1.2.3.4:4567 或 [::1]:4567）
  -k, --key <secret>             隧道预共享密钥
  --vpn-psk <psk>                L2TP/IPsec VPN 预共享密钥

可选参数:
  --add-user <user:pass>         添加VPN用户（可多次使用）
  --tun-ip <ip>                  本端TUN接口IPv4（默认: 172.16.0.2）
  --tun-peer <ip>                对端TUN接口IPv4（默认: 172.16.0.1）
  --tun-ip6 <ip6>                本端TUN接口IPv6（可选，如 fd00::2）
  --tun-peer6 <ip6>              对端TUN接口IPv6（可选，如 fd00::1）
  -6, --ipv6                     使用IPv6连接远端
  -h, --help                     显示此帮助信息

示例:
  $0 -r 1.2.3.4:4567 -k mysecret --vpn-psk myvpnpsk --add-user alice:password123
  $0 -r [2001:db8::1]:4567 -6 -k mysecret --vpn-psk mypsk --tun-ip6 fd00::2
EOF
}

# ─── 函数：解析命令行参数 ────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -r|--remote)
                REMOTE_ADDR="$2"
                shift 2
                ;;
            -k|--key)
                SECRET="$2"
                shift 2
                ;;
            --vpn-psk)
                VPN_PSK="$2"
                shift 2
                ;;
            --add-user)
                ADD_USERS+=("$2")
                shift 2
                ;;
            --tun-ip)
                TUN_IP="$2"
                shift 2
                ;;
            --tun-peer)
                TUN_PEER="$2"
                shift 2
                ;;
            --tun-ip6)
                TUN_IP6="$2"
                shift 2
                ;;
            --tun-peer6)
                TUN_PEER6="$2"
                shift 2
                ;;
            -6|--ipv6)
                USE_IPV6=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fatal "未知参数: $1\n使用 -h 查看帮助"
                ;;
        esac
    done

    [[ -z "$REMOTE_ADDR" ]] && fatal "必须指定远端地址，使用 -r <IP:PORT>"
    [[ -z "$SECRET" ]]      && fatal "必须指定隧道密钥，使用 -k <secret>"
    [[ -z "$VPN_PSK" ]]     && fatal "必须指定VPN预共享密钥，使用 --vpn-psk <psk>"

    # 解析远端地址（支持 IPv4 和 IPv6 [addr]:port 格式）
    if [[ "$REMOTE_ADDR" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
        # IPv6 格式: [addr]:port
        REMOTE_IP="${BASH_REMATCH[1]}"
        REMOTE_PORT="${BASH_REMATCH[2]}"
        USE_IPV6=1
    elif [[ "$REMOTE_ADDR" =~ ^([^:]+):([0-9]+)$ ]]; then
        # IPv4 格式: addr:port
        REMOTE_IP="${BASH_REMATCH[1]}"
        REMOTE_PORT="${BASH_REMATCH[2]}"
    else
        fatal "远端地址格式不正确，应为 IP:PORT 或 [IPv6]:PORT 格式"
    fi

    if [[ -z "$REMOTE_IP" || -z "$REMOTE_PORT" ]]; then
        fatal "远端地址解析失败"
    fi
}

# ─── 函数：安装系统依赖 ──────────────────────────────────────────────────────
install_deps() {
    info "更新软件包索引并安装依赖..."
    apt update
    apt install -y gcc make libssl-dev strongswan xl2tpd ppp iptables curl
    info "系统依赖安装完成"
}

# ─── 函数：编译安装 minivpn ──────────────────────────────────────────────────
build_minivpn() {
    info "编译安装 minivpn..."

    if [[ ! -d "$SRC_DIR" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        local project_dir
        project_dir="$(dirname "$script_dir")"

        if [[ -f "${project_dir}/Makefile" && -d "${project_dir}/src" ]]; then
            info "从 ${project_dir} 复制源码到 ${SRC_DIR}"
            mkdir -p "$SRC_DIR"
            cp -r "${project_dir}/src" "${project_dir}/Makefile" "$SRC_DIR/"
            [[ -d "${project_dir}/configs" ]] && cp -r "${project_dir}/configs" "$SRC_DIR/"
            [[ -d "${project_dir}/scripts" ]] && cp -r "${project_dir}/scripts" "$SRC_DIR/"
        else
            fatal "源码目录不存在: ${SRC_DIR}，且无法从脚本所在目录推断项目位置"
        fi
    fi

    cd "$SRC_DIR"
    make clean 2>/dev/null || true
    make
    make install
    info "minivpn 编译安装完成"
}

# ─── 函数：创建minivpn配置文件 ──────────────────────────────────────────────
create_minivpn_config() {
    info "创建 minivpn 配置文件（client模式）..."
    mkdir -p "$CONF_DIR"

    cat > "$CONF_FILE" <<EOF
# MiniVPN 近端（Entry Node）配置文件 - Client模式
# 由 deploy-entry.sh 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')

mode = client
remote = ${REMOTE_ADDR}
secret = ${SECRET}
tun_ip = ${TUN_IP}
tun_peer = ${TUN_PEER}
EOF

    # 添加 IPv6 TUN 配置（如果指定）
    if [[ -n "$TUN_IP6" ]]; then
        cat >> "$CONF_FILE" <<EOF
tun_ip6 = ${TUN_IP6}
tun_ip6_prefix = ${TUN_IP6_PREFIX}
EOF
    fi
    if [[ -n "$TUN_PEER6" ]]; then
        echo "tun_peer6 = ${TUN_PEER6}" >> "$CONF_FILE"
    fi
    if [[ "$USE_IPV6" -eq 1 ]]; then
        echo "ipv6 = yes" >> "$CONF_FILE"
    fi

    echo "log_level = 1" >> "$CONF_FILE"

    chmod 600 "$CONF_FILE"
    info "minivpn 配置文件创建完成"
}

# ─── 函数：配置strongSwan ───────────────────────────────────────────────────
configure_strongswan() {
    info "配置 strongSwan (IPsec)..."

    # 备份原有配置
    [[ -f /etc/ipsec.conf ]] && cp /etc/ipsec.conf /etc/ipsec.conf.bak.$(date +%s) 2>/dev/null || true
    [[ -f /etc/ipsec.secrets ]] && cp /etc/ipsec.secrets /etc/ipsec.secrets.bak.$(date +%s) 2>/dev/null || true

    cat > /etc/ipsec.conf <<'IPSEC_CONF'
# /etc/ipsec.conf - strongSwan IPsec 配置
# 由 deploy-entry.sh 自动生成

config setup
    uniqueids=no

conn l2tp
    type=transport
    authby=secret
    rekey=yes
    ikelifetime=24h
    lifetime=24h
    forceencaps=yes
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    auto=add
IPSEC_CONF

    cat > /etc/ipsec.secrets <<EOF
# /etc/ipsec.secrets - IPsec 预共享密钥
# 由 deploy-entry.sh 自动生成

: PSK "${VPN_PSK}"
EOF

    chmod 600 /etc/ipsec.secrets
    info "strongSwan 配置完成"
}

# ─── 函数：配置xl2tpd ───────────────────────────────────────────────────────
configure_xl2tpd() {
    info "配置 xl2tpd..."

    mkdir -p /etc/xl2tpd

    cat > /etc/xl2tpd/xl2tpd.conf <<'XL2TPD_CONF'
[global]
port = 1701

[lns default]
ip range = 10.10.10.10-10.10.10.200
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
XL2TPD_CONF

    info "xl2tpd 配置完成"
}

# ─── 函数：配置PPP ──────────────────────────────────────────────────────────
configure_ppp() {
    info "配置 PPP..."

    mkdir -p /etc/ppp

    # DNS 策略说明：
    # - 主 DNS 使用 Google DNS（8.8.8.8），通过隧道可达，用于外网域名正确解析
    #   避免国内 DNS 对外网域名的污染/错误解析
    # - 备 DNS 使用国内公共 DNS（223.5.5.5），用于国内域名解析到国内 CDN
    # MTU 1280: 满足 IPv6 最低 MTU 要求，同时兼顾 L2TP/IPsec 头部开销
    cat > /etc/ppp/options.xl2tpd <<'PPP_OPTS'
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 223.5.5.5
asyncmap 0
auth
hide-password
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1280
mru 1280
PPP_OPTS

    # 确保 chap-secrets 文件存在
    if [[ ! -f /etc/ppp/chap-secrets ]]; then
        cat > /etc/ppp/chap-secrets <<'CHAP'
# Secrets for authentication using CHAP
# client    server  secret          IP addresses
CHAP
        chmod 600 /etc/ppp/chap-secrets
    fi

    info "PPP 配置完成（MTU=1280）"
}

# ─── 函数：添加VPN用户 ──────────────────────────────────────────────────────
add_vpn_users() {
    if [[ ${#ADD_USERS[@]} -eq 0 ]]; then
        warn "未指定VPN用户，可稍后使用 add-user.sh 添加"
        return
    fi

    info "添加VPN用户..."
    for entry in "${ADD_USERS[@]}"; do
        local username password
        username=$(echo "$entry" | cut -d: -f1)
        password=$(echo "$entry" | cut -d: -f2)

        if [[ -z "$username" || -z "$password" ]]; then
            warn "用户格式不正确，跳过: $entry（应为 user:pass 格式）"
            continue
        fi

        # 幂等：检查是否已存在
        if grep -q "^${username} " /etc/ppp/chap-secrets 2>/dev/null; then
            warn "用户 ${username} 已存在，跳过"
        else
            echo "${username} l2tpd ${password} *" >> /etc/ppp/chap-secrets
            info "已添加用户: ${username}"
        fi
    done
}

# ─── 函数：开启IP转发 ────────────────────────────────────────────────────────
enable_ip_forward() {
    info "开启IP转发..."

    sysctl -w net.ipv4.ip_forward=1

    local sysctl_conf="/etc/sysctl.d/99-minivpn.conf"
    cat > "$sysctl_conf" <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
    sysctl --system > /dev/null 2>&1

    # IPv6 转发
    if [[ -n "$TUN_IP6" ]]; then
        sysctl -w net.ipv6.conf.all.forwarding=1
        sysctl -w net.ipv6.conf.default.forwarding=1
        info "IPv4 和 IPv6 转发已开启"
    else
        info "IPv4 转发已开启"
    fi
}

# ─── 函数：获取默认出口网卡 ─────────────────────────────────────────────────
get_default_iface() {
    local iface
    iface=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    if [[ -z "$iface" ]]; then
        fatal "无法检测默认出口网卡，请检查网络配置"
    fi
    echo "$iface"
}

# ─── 函数：配置iptables ─────────────────────────────────────────────────────
setup_iptables() {
    info "配置iptables规则..."

    local iface
    iface=$(get_default_iface)

    # === IPv4 规则 ===

    # mangle 规则：对来自 PPP 客户端子网的流量打 fwmark 标记
    # fwmark 100 配合 ip rule / ip route table 200 (CN直连) + table 201 (隧道) 实现分流
    if ! iptables -t mangle -C PREROUTING -s 10.10.10.0/24 -j MARK --set-mark 100 2>/dev/null; then
        iptables -t mangle -A PREROUTING -s 10.10.10.0/24 -j MARK --set-mark 100
        info "已添加 mangle 分流规则（PPP 客户端流量打标记 fwmark=100）"
    fi

    # L2TP VPN 客户端子网 NAT
    if ! iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o "$TUN_DEV" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$TUN_DEV" -j MASQUERADE
    fi

    # 也允许通过默认网卡的NAT（用于国内直连流量）
    if ! iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o "$iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$iface" -j MASQUERADE
    fi

    # FORWARD 规则
    if ! iptables -C FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
    fi
    if ! iptables -C FORWARD -d 10.10.10.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
    fi
    if ! iptables -C FORWARD -s 172.16.0.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -s 172.16.0.0/24 -j ACCEPT
    fi
    if ! iptables -C FORWARD -d 172.16.0.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -d 172.16.0.0/24 -j ACCEPT
    fi

    # 放行 IPsec 相关端口
    if ! iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport 500 -j ACCEPT
    fi
    if ! iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    fi
    if ! iptables -C INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    fi

    # TCP MSS Clamping（避免 MTU 问题导致分片）
    if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fi

    # === IPv6 规则（如果指定了 TUN IPv6 地址） ===
    if [[ -n "$TUN_IP6" ]]; then
        local tun6_subnet="${TUN_IP6}/${TUN_IP6_PREFIX}"
        info "配置 ip6tables 规则 (TUN IPv6: ${tun6_subnet})..."

        # IPv6 NAT（MASQUERADE）
        if ! ip6tables -t nat -C POSTROUTING -s "$tun6_subnet" -o "$iface" -j MASQUERADE 2>/dev/null; then
            ip6tables -t nat -A POSTROUTING -s "$tun6_subnet" -o "$iface" -j MASQUERADE 2>/dev/null || true
        fi

        # IPv6 FORWARD 规则
        if ! ip6tables -C FORWARD -s "$tun6_subnet" -j ACCEPT 2>/dev/null; then
            ip6tables -A FORWARD -s "$tun6_subnet" -j ACCEPT
        fi
        if ! ip6tables -C FORWARD -d "$tun6_subnet" -j ACCEPT 2>/dev/null; then
            ip6tables -A FORWARD -d "$tun6_subnet" -j ACCEPT
        fi

        # IPv6 放行 IPsec 端口
        if ! ip6tables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null; then
            ip6tables -A INPUT -p udp --dport 500 -j ACCEPT
        fi
        if ! ip6tables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null; then
            ip6tables -A INPUT -p udp --dport 4500 -j ACCEPT
        fi
        if ! ip6tables -C INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null; then
            ip6tables -A INPUT -p udp --dport 1701 -j ACCEPT
        fi

        # IPv6 MSS Clamping
        if ! ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        fi

        info "ip6tables 规则配置完成"
    fi

    # 保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true
    apt install -y iptables-persistent
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    info "iptables 规则配置完成（IPv4 + IPv6）"
}

# ─── 函数：初始化智能路由 ────────────────────────────────────────────────────
init_smart_routes() {
    info "初始化智能路由..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local routes_script="${script_dir}/update-routes.sh"

    # 也检查 /opt/minivpn/scripts/
    if [[ ! -f "$routes_script" ]]; then
        routes_script="/opt/minivpn/scripts/update-routes.sh"
    fi

    if [[ -f "$routes_script" ]]; then
        chmod +x "$routes_script"
        info "运行路由更新脚本..."
        bash "$routes_script" || warn "路由更新失败，可稍后手动运行 update-routes.sh"
    else
        warn "未找到 update-routes.sh 脚本，请稍后手动执行路由更新"
    fi
}

# ─── 函数：创建systemd服务 ───────────────────────────────────────────────────
create_service() {
    info "创建 systemd 服务..."

    # 创建启动后路由初始化脚本
    cat > "${CONF_DIR}/setup-routes.sh" <<'ROUTE_SCRIPT'
#!/bin/bash
# minivpn 启动后自动设置隧道路由
# 等待 TUN 设备就绪
sleep 3
TUN_DEV="tun0"
ROUTE_TABLE_TUNNEL=201
ROUTE_TABLE_CN=200
FWMARK=100

# 获取 TUN 对端 IP
TUN_PEER=$(ip addr show "$TUN_DEV" 2>/dev/null | awk '/peer / { split($4, a, "/"); print a[1] }' | head -n1)
if [ -z "$TUN_PEER" ]; then
    TUN_PEER=$(ip route show dev "$TUN_DEV" 2>/dev/null | awk '/^[0-9]/ { split($1, a, "/"); print a[1] }' | head -n1)
fi

if [ -n "$TUN_PEER" ]; then
    # 添加隧道默认路由
    ip route replace default via "$TUN_PEER" dev "$TUN_DEV" table "$ROUTE_TABLE_TUNNEL" 2>/dev/null || true
    echo "[$(date)] 隧道默认路由已设置: default via $TUN_PEER dev $TUN_DEV table $ROUTE_TABLE_TUNNEL"

    # 确保策略规则存在
    ip rule show | grep -q "fwmark $FWMARK lookup $ROUTE_TABLE_CN" || \
        ip rule add fwmark "$FWMARK" table "$ROUTE_TABLE_CN" priority 100 2>/dev/null || true
    ip rule show | grep -q "from 10.10.10.0/24 lookup $ROUTE_TABLE_TUNNEL" || \
        ip rule add from 10.10.10.0/24 table "$ROUTE_TABLE_TUNNEL" priority 200 2>/dev/null || true
else
    echo "[$(date)] 警告: 无法获取 TUN 对端 IP"
fi
ROUTE_SCRIPT
    chmod +x "${CONF_DIR}/setup-routes.sh"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MiniVPN Tunnel Service (Entry Node - Client)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minivpn -f ${CONF_FILE}
ExecStartPost=/bin/bash ${CONF_DIR}/setup-routes.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

# 安全加固
ProtectHome=yes
ReadWritePaths=/dev/net/tun
PrivateTmp=yes

# TUN 设备配置需要 CAP_NET_ADMIN（ioctl SIOCSIFADDR/SIOCSIFMTU 等）
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info "systemd 服务创建完成"
}

# ─── 函数：启动所有服务 ──────────────────────────────────────────────────────
start_services() {
    info "启动所有服务..."

    # 重启 strongSwan (ipsec)
    systemctl enable ipsec 2>/dev/null || systemctl enable strongswan 2>/dev/null || true
    systemctl restart ipsec 2>/dev/null || systemctl restart strongswan 2>/dev/null || true
    if systemctl is-active --quiet ipsec 2>/dev/null || systemctl is-active --quiet strongswan 2>/dev/null; then
        info "IPsec (strongSwan) 已启动"
    else
        warn "IPsec 服务可能未正常启动，请检查 systemctl status ipsec"
    fi

    # 重启 xl2tpd
    systemctl enable xl2tpd
    systemctl restart xl2tpd
    if systemctl is-active --quiet xl2tpd; then
        info "xl2tpd 已启动"
    else
        warn "xl2tpd 可能未正常启动，请检查 systemctl status xl2tpd"
    fi

    # 启动 minivpn
    systemctl enable minivpn
    systemctl restart minivpn
    sleep 2
    if systemctl is-active --quiet minivpn; then
        info "minivpn 已启动"
    else
        warn "minivpn 可能未正常启动，请检查 systemctl status minivpn"
    fi
}

# ─── 函数：添加cron定时任务 ──────────────────────────────────────────────────
setup_cron() {
    info "配置路由自动更新定时任务..."

    local cron_cmd
    local routes_script

    # 确定脚本路径
    if [[ -f "/opt/minivpn/scripts/update-routes.sh" ]]; then
        routes_script="/opt/minivpn/scripts/update-routes.sh"
    else
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        routes_script="${script_dir}/update-routes.sh"
    fi

    cron_cmd="0 3 * * 0 /bin/bash ${routes_script} >> /var/log/minivpn-routes.log 2>&1"

    # 幂等：检查是否已存在
    if crontab -l 2>/dev/null | grep -qF "update-routes.sh"; then
        warn "cron 定时任务已存在，跳过"
    else
        (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
        info "已添加cron任务：每周日凌晨3点更新路由"
    fi
}

# ─── 函数：输出部署成功信息 ──────────────────────────────────────────────────
show_summary() {
    local iface
    iface=$(get_default_iface)
    local public_ip
    public_ip=$(ip -4 addr show "$iface" | awk '/inet / { split($2, a, "/"); print a[1] }' | head -n1)

    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  MiniVPN 近端（Entry Node）部署完成！${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "  本机IP:           ${public_ip:-未知}"
    echo -e "  远端隧道:         ${REMOTE_ADDR}"
    echo -e "  TUN本端IPv4:     ${TUN_IP}"
    echo -e "  TUN对端IPv4:     ${TUN_PEER}"
    if [[ -n "$TUN_IP6" ]]; then
        echo -e "  TUN本端IPv6:     ${TUN_IP6}/${TUN_IP6_PREFIX}"
    fi
    if [[ -n "$TUN_PEER6" ]]; then
        echo -e "  TUN对端IPv6:     ${TUN_PEER6}"
    fi
    echo ""
    echo -e "  ${YELLOW}── L2TP/IPsec VPN 客户端配置 ──${NC}"
    echo -e "  服务器地址:       ${public_ip:-<此服务器IP>}"
    echo -e "  VPN类型:          L2TP/IPsec PSK"
    echo -e "  预共享密钥:       ${VPN_PSK}"
    echo -e "  PPP用户子网:      10.10.10.0/24"
    echo -e "  PPP MTU:          1280"
    echo ""
    if [[ ${#ADD_USERS[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}── 已添加的VPN用户 ──${NC}"
        for entry in "${ADD_USERS[@]}"; do
            local username
            username=$(echo "$entry" | cut -d: -f1)
            echo -e "    用户名: ${username}"
        done
        echo ""
    fi
    echo -e "  ${YELLOW}── 服务状态 ──${NC}"
    echo -e "  IPsec:      $(systemctl is-active ipsec 2>/dev/null || systemctl is-active strongswan 2>/dev/null || echo 'unknown')"
    echo -e "  xl2tpd:     $(systemctl is-active xl2tpd 2>/dev/null || echo 'unknown')"
    echo -e "  minivpn:    $(systemctl is-active minivpn 2>/dev/null || echo 'unknown')"
    echo ""
    echo -e "  常用命令:"
    echo -e "    systemctl status minivpn     # 查看隧道状态"
    echo -e "    systemctl status ipsec       # 查看IPsec状态"
    echo -e "    systemctl status xl2tpd      # 查看xl2tpd状态"
    echo -e "    journalctl -u minivpn -f     # 查看隧道日志"
    echo -e "    bash /opt/minivpn/scripts/update-routes.sh  # 手动更新路由"
    echo -e "    bash /opt/minivpn/scripts/add-user.sh user pass  # 添加用户"
    echo ""
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  MiniVPN 近端（Entry Node）一键部署脚本  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    parse_args "$@"
    install_deps
    build_minivpn
    create_minivpn_config
    configure_strongswan
    configure_xl2tpd
    configure_ppp
    add_vpn_users
    enable_ip_forward
    setup_iptables
    init_smart_routes
    create_service
    start_services
    setup_cron
    show_summary
}

main "$@"
