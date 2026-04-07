#!/bin/bash
set -e

###############################################################################
# deploy-exit.sh - MiniVPN 远端（海外出口）一键部署脚本
# 用法: ./deploy-exit.sh -k <secret> [-p <port>] [--tun-ip <ip>] [--tun-peer <ip>]
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
用法: $0 -k <secret> [-p <port>] [--tun-ip <ip>] [--tun-peer <ip>]

参数:
  -k, --key <secret>       隧道预共享密钥（必须）
  -p, --port <port>        监听UDP端口（默认: 4567）
  --tun-ip <ip>            本端TUN接口IP（默认: 172.16.0.1）
  --tun-peer <ip>          对端TUN接口IP（默认: 172.16.0.2）
  -h, --help               显示此帮助信息

示例:
  $0 -k mysecretkey
  $0 -k mysecretkey -p 5678 --tun-ip 10.0.0.1 --tun-peer 10.0.0.2
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

    cat > "$CONF_FILE" <<EOF
# MiniVPN 远端（Exit Node）配置文件
# 由 deploy-exit.sh 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')

mode = server
listen = 0.0.0.0:${PORT}
secret = ${SECRET}
tun_ip = ${TUN_IP}
tun_peer = ${TUN_PEER}
log_level = 1
EOF

    chmod 600 "$CONF_FILE"
    info "配置文件创建完成"
}

# ─── 函数：开启IP转发 ────────────────────────────────────────────────────────
enable_ip_forward() {
    info "开启IPv4转发..."

    # 立即生效
    sysctl -w net.ipv4.ip_forward=1

    # 持久化
    local sysctl_conf="/etc/sysctl.d/99-minivpn.conf"
    if [[ -f "$sysctl_conf" ]] && grep -q "net.ipv4.ip_forward=1" "$sysctl_conf"; then
        info "IP转发配置已存在，跳过"
    else
        echo "net.ipv4.ip_forward=1" > "$sysctl_conf"
        sysctl --system > /dev/null 2>&1
    fi

    info "IP转发已开启"
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

# ─── 函数：配置iptables NAT ─────────────────────────────────────────────────
setup_iptables() {
    info "配置iptables NAT规则..."

    local iface
    iface=$(get_default_iface)
    local tun_subnet
    # 从TUN_IP推导子网（假设/24）
    tun_subnet=$(echo "$TUN_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')

    info "默认出口网卡: ${iface}"
    info "TUN子网: ${tun_subnet}"

    # POSTROUTING NAT（幂等：先检查是否已存在）
    if ! iptables -t nat -C POSTROUTING -s "$tun_subnet" -o "$iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$tun_subnet" -o "$iface" -j MASQUERADE
    fi

    # FORWARD 规则（幂等）
    if ! iptables -C FORWARD -s "$tun_subnet" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -s "$tun_subnet" -j ACCEPT
    fi
    if ! iptables -C FORWARD -d "$tun_subnet" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -d "$tun_subnet" -j ACCEPT
    fi

    # INPUT 放行 UDP 端口
    if ! iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
    fi

    info "iptables 规则配置完成"
}

# ─── 函数：保存iptables规则 ──────────────────────────────────────────────────
persist_iptables() {
    info "安装 iptables-persistent 并保存规则..."

    # 预设应答以避免交互式提示
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true

    apt install -y iptables-persistent

    # 保存当前规则
    iptables-save > /etc/iptables/rules.v4
    info "iptables 规则已持久化"
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
    echo -e "  TUN本端IP:   ${TUN_IP}"
    echo -e "  TUN对端IP:   ${TUN_PEER}"
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
    persist_iptables
    create_service
    start_service
    show_summary
}

main "$@"
