#!/bin/bash
set -e

###############################################################################
# deploy-exit.sh - MiniVPN 远端（海外出口）一键部署脚本
# 用法: ./deploy-exit.sh -k <secret> [-p <port>] [--tun-ip <ip>] [--tun-peer <ip>]
#       [--tun-ip6 <ip6>] [--tun-peer6 <ip6>] [--ipv6]
# 面向: Ubuntu 22.04+ / Debian 12+
###############################################################################

# ─── 颜色输出 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()    { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal()   { error "$*"; exit 1; }

# ─── 默认值 ──────────────────────────────────────────────────────────────────
PORT=4567
TUN_IP="172.16.0.1"
TUN_PEER="172.16.0.2"
TUN_IP6=""               # IPv6 TUN 本端地址（可选）
TUN_PEER6=""             # IPv6 TUN 对端地址（可选）
TUN_IP6_PREFIX=64        # IPv6 前缀长度
USE_IPV6=0               # 是否使用 IPv6 监听
SECRET=""
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

# ─── 函数：解析命令行参数 ────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -k|--key)
                SECRET="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
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

    if [[ -z "$SECRET" ]]; then
        fatal "必须指定隧道密钥，使用 -k <secret>"
    fi
}

# ─── 函数：显示用法 ──────────────────────────────────────────────────────────
usage() {
    cat <<EOF
用法: $0 -k <secret> [-p <port>] [--tun-ip <ip>] [--tun-peer <ip>] [选项]

参数:
  -k, --key <secret>       隧道预共享密钥（必须）
  -p, --port <port>        监听UDP端口（默认: 4567）
  --tun-ip <ip>            本端TUN接口IPv4（默认: 172.16.0.1）
  --tun-peer <ip>          对端TUN接口IPv4（默认: 172.16.0.2）
  --tun-ip6 <ip6>          本端TUN接口IPv6（可选，如 fd00::1）
  --tun-peer6 <ip6>        对端TUN接口IPv6（可选，如 fd00::2）
  -6, --ipv6               使用IPv6监听（默认IPv4）
  -h, --help               显示此帮助信息

示例:
  $0 -k mysecretkey
  $0 -k mysecretkey -p 5678 --tun-ip6 fd00::1 --tun-peer6 fd00::2
  $0 -k mysecretkey -6 -p 4567    # IPv6 监听
EOF
}

# ─── 函数：安装系统依赖 ──────────────────────────────────────────────────────
install_deps() {
    info "更新软件包索引并安装编译依赖..."
    apt update
    apt install -y gcc make libssl-dev iptables
    info "系统依赖安装完成"
}

# ─── 函数：编译安装 minivpn ──────────────────────────────────────────────────
build_minivpn() {
    info "编译安装 minivpn..."

    # 如果 /opt/minivpn 不存在，尝试从当前目录复制
    if [[ ! -d "$SRC_DIR" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        local project_dir
        project_dir="$(dirname "$script_dir")"

        if [[ -f "${project_dir}/Makefile" && -d "${project_dir}/src" ]]; then
            info "从 ${project_dir} 复制源码到 ${SRC_DIR}"
            mkdir -p "$SRC_DIR"
            cp -r "${project_dir}/src" "${project_dir}/Makefile" "$SRC_DIR/"
            # 如果有configs目录也复制
            [[ -d "${project_dir}/configs" ]] && cp -r "${project_dir}/configs" "$SRC_DIR/"
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

# ─── 函数：创建配置文件 ──────────────────────────────────────────────────────
create_config() {
    info "创建配置文件 ${CONF_FILE}..."
    mkdir -p "$CONF_DIR"

    local listen_addr="0.0.0.0:${PORT}"
    if [[ "$USE_IPV6" -eq 1 ]]; then
        listen_addr="[::]:${PORT}"
    fi

    cat > "$CONF_FILE" <<EOF
# MiniVPN 远端（Exit Node）配置文件
# 由 deploy-exit.sh 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')

mode = server
listen = ${listen_addr}
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
    info "配置文件创建完成"
}

# ─── 函数：开启IP转发 ────────────────────────────────────────────────────────
enable_ip_forward() {
    info "开启IP转发..."

    # IPv4 转发
    sysctl -w net.ipv4.ip_forward=1

    # 持久化配置
    local sysctl_conf="/etc/sysctl.d/99-minivpn.conf"
    cat > "$sysctl_conf" <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
    sysctl --system > /dev/null 2>&1

    # IPv6 转发（如果使用 IPv6 TUN）
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

# ─── 函数：配置iptables NAT（IPv4） ─────────────────────────────────────────
setup_iptables() {
    info "配置iptables NAT规则..."

    local iface
    iface=$(get_default_iface)
    local tun_subnet
    # 从TUN_IP推导子网（假设/24）
    tun_subnet=$(echo "$TUN_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')

    info "默认出口网卡: ${iface}"
    info "TUN IPv4 子网: ${tun_subnet}"

    # === IPv4 规则 ===

    # POSTROUTING NAT - TUN 子网（幂等：先检查是否已存在）
    if ! iptables -t nat -C POSTROUTING -s "$tun_subnet" -o "$iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$tun_subnet" -o "$iface" -j MASQUERADE
    fi

    # POSTROUTING NAT - PPP 客户端子网（近端 L2TP VPN 客户端流量经隧道过来后，
    # 源地址为 10.10.10.x，需要在出口节点做 NAT 才能访问外网）
    if ! iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o "$iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$iface" -j MASQUERADE
    fi

    # FORWARD 规则（幂等）
    if ! iptables -C FORWARD -s "$tun_subnet" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -s "$tun_subnet" -j ACCEPT
    fi
    if ! iptables -C FORWARD -d "$tun_subnet" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -d "$tun_subnet" -j ACCEPT
    fi

    # FORWARD 规则 - PPP 客户端子网
    if ! iptables -C FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
    fi
    if ! iptables -C FORWARD -d 10.10.10.0/24 -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
    fi

    # INPUT 放行 UDP 端口
    if ! iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
    fi

    # === IPv6 规则（如果指定了 TUN IPv6 地址） ===
    if [[ -n "$TUN_IP6" ]]; then
        # 从 TUN_IP6 推导 /64 子网
        local tun6_subnet="${TUN_IP6}/${TUN_IP6_PREFIX}"

        info "TUN IPv6 子网: ${tun6_subnet}"

        # IPv6 NAT（MASQUERADE）
        if ! ip6tables -t nat -C POSTROUTING -s "$tun6_subnet" -o "$iface" -j MASQUERADE 2>/dev/null; then
            ip6tables -t nat -A POSTROUTING -s "$tun6_subnet" -o "$iface" -j MASQUERADE
        fi

        # IPv6 FORWARD 规则
        if ! ip6tables -C FORWARD -s "$tun6_subnet" -j ACCEPT 2>/dev/null; then
            ip6tables -A FORWARD -s "$tun6_subnet" -j ACCEPT
        fi
        if ! ip6tables -C FORWARD -d "$tun6_subnet" -j ACCEPT 2>/dev/null; then
            ip6tables -A FORWARD -d "$tun6_subnet" -j ACCEPT
        fi

        # IPv6 INPUT 放行 UDP 端口
        if ! ip6tables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
            ip6tables -A INPUT -p udp --dport "$PORT" -j ACCEPT
        fi

        info "ip6tables 规则配置完成"
    fi

    info "iptables 规则配置完成"
}

# ─── 函数：配置 TCP MSS Clamping（避免 MTU 问题导致的分片） ─────────────────
setup_mss_clamping() {
    info "配置 TCP MSS Clamping..."

    # IPv4 MSS clamping
    if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fi

    # IPv6 MSS clamping（如果启用了 IPv6）
    if [[ -n "$TUN_IP6" ]]; then
        if ! ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        fi
    fi

    info "TCP MSS Clamping 配置完成"
}

# ─── 函数：保存iptables规则 ──────────────────────────────────────────────────
persist_iptables() {
    info "安装 iptables-persistent 并保存规则..."

    # 预设应答以避免交互式提示
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true

    apt install -y iptables-persistent

    # 保存当前规则（IPv4 和 IPv6）
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    info "iptables 规则已持久化（IPv4 + IPv6）"
}

# ─── 函数：创建systemd服务 ───────────────────────────────────────────────────
create_service() {
    info "创建 systemd 服务..."

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MiniVPN Tunnel Service (Exit Node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minivpn -f ${CONF_FILE}
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

# ─── 函数：启用并启动服务 ────────────────────────────────────────────────────
start_service() {
    info "启用并启动 minivpn 服务..."
    systemctl enable minivpn
    systemctl restart minivpn

    # 等待一秒检查服务状态
    sleep 2
    if systemctl is-active --quiet minivpn; then
        info "minivpn 服务已成功启动"
    else
        warn "minivpn 服务可能未正常启动，请检查: systemctl status minivpn"
    fi
}

# ─── 函数：输出部署成功信息 ──────────────────────────────────────────────────
show_summary() {
    local iface
    iface=$(get_default_iface)
    local public_ip
    public_ip=$(ip -4 addr show "$iface" | awk '/inet / { split($2, a, "/"); print a[1] }' | head -n1)

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  MiniVPN 远端（Exit Node）部署完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "  服务器IP:     ${public_ip:-未知}"
    echo -e "  监听端口:     ${PORT}/udp"
    echo -e "  监听模式:     $(if [[ "$USE_IPV6" -eq 1 ]]; then echo "IPv6 ([::])"; else echo "IPv4 (0.0.0.0)"; fi)"
    echo -e "  TUN本端IPv4: ${TUN_IP}"
    echo -e "  TUN对端IPv4: ${TUN_PEER}"
    if [[ -n "$TUN_IP6" ]]; then
        echo -e "  TUN本端IPv6: ${TUN_IP6}/${TUN_IP6_PREFIX}"
    fi
    if [[ -n "$TUN_PEER6" ]]; then
        echo -e "  TUN对端IPv6: ${TUN_PEER6}"
    fi
    echo -e "  配置文件:     ${CONF_FILE}"
    echo -e "  服务状态:     $(systemctl is-active minivpn)"
    echo ""
    echo -e "  ${YELLOW}近端部署时使用:${NC}"
    echo -e "  ${YELLOW}  ./deploy-entry.sh -r ${public_ip:-<此服务器IP>}:${PORT} -k '${SECRET}'${NC}"
    echo ""
    echo -e "  常用命令:"
    echo -e "    systemctl status minivpn    # 查看服务状态"
    echo -e "    journalctl -u minivpn -f    # 查看实时日志"
    echo -e "    systemctl restart minivpn   # 重启服务"
    echo ""
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  MiniVPN 远端（Exit Node）一键部署脚本  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    parse_args "$@"
    install_deps
    build_minivpn
    create_config
    enable_ip_forward
    setup_iptables
    setup_mss_clamping
    persist_iptables
    create_service
    start_service
    show_summary
}

main "$@"
