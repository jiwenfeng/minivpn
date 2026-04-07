#!/bin/bash
set -e

###############################################################################
# update-routes.sh - APNIC中国大陆IP路由更新脚本
# 用法: ./update-routes.sh
# 功能: 从APNIC获取中国大陆IP段，更新Linux策略路由表（热更新，无需重启服务）
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

# ─── 配置变量 ────────────────────────────────────────────────────────────────
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
ROUTE_TABLE_CN=200         # 中国大陆IP走默认网关的路由表
ROUTE_TABLE_TUNNEL=201     # 其他流量走隧道的路由表
FWMARK=100                 # iptables fwmark 标记值
DATA_DIR="/var/lib/minivpn"
APNIC_FILE="${DATA_DIR}/delegated-apnic-latest"
BATCH_FILE="${DATA_DIR}/routes-cn.batch"
LOG_FILE="/var/log/minivpn-routes.log"
TUN_DEV="tun0"

# ─── 函数：检查root权限 ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "此脚本必须以root权限运行"
    fi
}

# ─── 函数：获取默认网关和网卡 ────────────────────────────────────────────────
get_default_route() {
    DEFAULT_GW=$(ip route show default | awk '/default/ {print $3}' | head -n1)
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)

    if [[ -z "$DEFAULT_GW" || -z "$DEFAULT_IFACE" ]]; then
        fatal "无法获取默认网关或网卡信息"
    fi

    info "默认网关: ${DEFAULT_GW}  默认网卡: ${DEFAULT_IFACE}"
}

# ─── 函数：获取TUN对端IP ────────────────────────────────────────────────────
get_tun_peer() {
    TUN_PEER=""
    if ip link show "$TUN_DEV" &>/dev/null; then
        TUN_PEER=$(ip addr show "$TUN_DEV" | awk '/peer / { split($4, a, "/"); print a[1] }' | head -n1)
        if [[ -z "$TUN_PEER" ]]; then
            # 尝试从 point-to-point 地址获取
            TUN_PEER=$(ip route show dev "$TUN_DEV" | awk '/^[0-9]/ { split($1, a, "/"); print a[1] }' | head -n1)
        fi
    fi

    if [[ -n "$TUN_PEER" ]]; then
        info "TUN对端IP: ${TUN_PEER}"
    else
        warn "TUN设备 ${TUN_DEV} 未就绪或无法获取对端IP，隧道默认路由将跳过"
    fi
}

# ─── 函数：下载APNIC数据 ────────────────────────────────────────────────────
download_apnic() {
    info "下载APNIC数据..."
    mkdir -p "$DATA_DIR"

    if curl -s -o "${APNIC_FILE}.tmp" --connect-timeout 30 --max-time 120 "$APNIC_URL"; then
        mv "${APNIC_FILE}.tmp" "$APNIC_FILE"
        info "APNIC数据下载完成: $(wc -l < "$APNIC_FILE") 行"
    else
        rm -f "${APNIC_FILE}.tmp"
        if [[ -f "$APNIC_FILE" ]]; then
            warn "下载失败，使用上次缓存的数据"
        else
            fatal "下载APNIC数据失败，且无缓存可用"
        fi
    fi
}

# ─── 函数：将主机数转换为CIDR前缀长度 ───────────────────────────────────────
hosts_to_cidr() {
    local hosts=$1
    local prefix=32
    local n=1
    while [[ $n -lt $hosts ]]; do
        n=$((n * 2))
        prefix=$((prefix - 1))
    done
    echo $prefix
}

# ─── 函数：解析CN IPv4段并生成批量路由命令 ───────────────────────────────────
generate_routes() {
    info "解析中国大陆IPv4地址段..."

    local count=0

    # 清空批量文件
    > "$BATCH_FILE"

    # 解析 APNIC 数据中的 CN IPv4 条目
    # 格式: apnic|CN|ipv4|起始IP|主机数|日期|状态
    while IFS='|' read -r registry cc type start value _ _; do
        if [[ "$registry" == "apnic" && "$cc" == "CN" && "$type" == "ipv4" ]]; then
            local cidr
            cidr=$(hosts_to_cidr "$value")
            echo "route add ${start}/${cidr} via ${DEFAULT_GW} dev ${DEFAULT_IFACE} table ${ROUTE_TABLE_CN}" >> "$BATCH_FILE"
            count=$((count + 1))
        fi
    done < "$APNIC_FILE"

    info "共解析 ${count} 条中国大陆IPv4路由"
    echo "$count"
}

# ─── 函数：刷新并应用路由 ────────────────────────────────────────────────────
apply_routes() {
    info "刷新路由表 ${ROUTE_TABLE_CN}..."
    ip route flush table "$ROUTE_TABLE_CN" 2>/dev/null || true

    info "批量添加中国大陆路由..."
    if [[ -s "$BATCH_FILE" ]]; then
        # ip -batch 执行
        ip -batch "$BATCH_FILE" 2>/dev/null || {
            warn "部分路由添加失败，尝试逐条添加..."
            local failed=0
            while read -r line; do
                ip $line 2>/dev/null || failed=$((failed + 1))
            done < "$BATCH_FILE"
            if [[ $failed -gt 0 ]]; then
                warn "${failed} 条路由添加失败"
            fi
        }
    else
        warn "路由批量文件为空"
    fi

    info "路由表更新完成"
}

# ─── 函数：确保策略路由规则存在 ──────────────────────────────────────────────
setup_policy_rules() {
    info "配置策略路由规则..."

    # 规则1: 带有 fwmark 标记的流量查 CN 路由表（中国IP直连）
    if ! ip rule show | grep -q "fwmark ${FWMARK} lookup ${ROUTE_TABLE_CN}"; then
        ip rule add fwmark "$FWMARK" table "$ROUTE_TABLE_CN" priority 100
        info "已添加策略规则: fwmark ${FWMARK} -> table ${ROUTE_TABLE_CN}"
    else
        info "策略规则(CN)已存在，跳过"
    fi

    # 规则2: 来自 VPN 客户端子网的流量查隧道路由表
    if ! ip rule show | grep -q "from 10.10.10.0/24 lookup ${ROUTE_TABLE_TUNNEL}"; then
        ip rule add from 10.10.10.0/24 table "$ROUTE_TABLE_TUNNEL" priority 200
        info "已添加策略规则: from 10.10.10.0/24 -> table ${ROUTE_TABLE_TUNNEL}"
    else
        info "策略规则(Tunnel)已存在，跳过"
    fi

    # iptables mangle 规则: 对目的为中国IP的流量打标记
    # 使用 ipset 或逐条 iptables 不现实，这里用路由表实现：
    # 中国IP走 table 200（直连），其他走 table 201（隧道）
    # mangle PREROUTING: 标记来自VPN客户端的流量
    if ! iptables -t mangle -C PREROUTING -s 10.10.10.0/24 -j CONNMARK --restore-mark 2>/dev/null; then
        iptables -t mangle -A PREROUTING -s 10.10.10.0/24 -j CONNMARK --restore-mark 2>/dev/null || true
    fi

    info "策略路由规则配置完成"
}

# ─── 函数：确保隧道默认路由存在 ──────────────────────────────────────────────
setup_tunnel_default_route() {
    info "配置隧道默认路由..."

    if [[ -z "$TUN_PEER" ]]; then
        warn "TUN对端IP未知，跳过隧道默认路由配置"
        return
    fi

    # 在隧道路由表中添加默认路由（通过TUN设备转发）
    if ! ip route show table "$ROUTE_TABLE_TUNNEL" | grep -q "default"; then
        ip route add default via "$TUN_PEER" dev "$TUN_DEV" table "$ROUTE_TABLE_TUNNEL" 2>/dev/null || {
            warn "添加隧道默认路由失败（TUN设备可能未就绪）"
            return
        }
        info "已添加隧道默认路由: default via ${TUN_PEER} dev ${TUN_DEV} table ${ROUTE_TABLE_TUNNEL}"
    else
        info "隧道默认路由已存在，跳过"
    fi

    # 确保隧道路由表中也有中国IP直连路由（避免回环）
    # 中国IP在 table 200 中已配置，通过策略路由优先级保证
}

# ─── 函数：确保路由表名称注册 ────────────────────────────────────────────────
register_route_tables() {
    local rt_tables="/etc/iproute2/rt_tables"

    if ! grep -q "^${ROUTE_TABLE_CN}" "$rt_tables" 2>/dev/null; then
        echo "${ROUTE_TABLE_CN}    cn_direct" >> "$rt_tables"
        info "已注册路由表: ${ROUTE_TABLE_CN} cn_direct"
    fi

    if ! grep -q "^${ROUTE_TABLE_TUNNEL}" "$rt_tables" 2>/dev/null; then
        echo "${ROUTE_TABLE_TUNNEL}    tunnel" >> "$rt_tables"
        info "已注册路由表: ${ROUTE_TABLE_TUNNEL} tunnel"
    fi
}

# ─── 函数：记录日志 ──────────────────────────────────────────────────────────
log_result() {
    local count=$1
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local cn_routes
    cn_routes=$(ip route show table "$ROUTE_TABLE_CN" 2>/dev/null | wc -l)

    local log_entry="[${timestamp}] 路由更新完成: 解析 ${count} 条CN路由，实际生效 ${cn_routes} 条"
    echo "$log_entry" >> "$LOG_FILE"
    info "$log_entry"
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  MiniVPN APNIC中国大陆路由更新脚本        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    get_default_route
    get_tun_peer
    register_route_tables
    download_apnic

    local count
    count=$(generate_routes)

    apply_routes
    setup_policy_rules
    setup_tunnel_default_route
    log_result "$count"

    echo ""
    info "路由更新完成！无需重启任何服务。"
    echo ""
}

main "$@"
