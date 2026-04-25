#!/bin/bash
set -e

###############################################################################
# update-routes.sh - APNIC中国大陆IP路由更新脚本（IPv4 + IPv6）
# 用法: ./update-routes.sh
# 功能: 从APNIC获取中国大陆IPv4/IPv6段，更新Linux策略路由表（热更新，无需重启）
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
APNIC_MIRROR_URLS=(
    "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
    "https://mirror.xtom.com.hk/apnic/stats/apnic/delegated-apnic-latest"
    "https://mirror1.apnic.net/stats/apnic/delegated-apnic-latest"
)
ROUTE_TABLE_CN=200         # 中国大陆IP走默认网关的路由表
ROUTE_TABLE_TUNNEL=201     # 其他流量走隧道的路由表
FWMARK=100                 # iptables fwmark 标记值
DATA_DIR="/var/lib/minivpn"
APNIC_FILE="${DATA_DIR}/delegated-apnic-latest"
BATCH_FILE_V4="${DATA_DIR}/routes-cn-v4.batch"
BATCH_FILE_V6="${DATA_DIR}/routes-cn-v6.batch"
LOG_FILE="/var/log/minivpn-routes.log"
TUN_DEV="tun0"

# ─── 函数：检查root权限 ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "此脚本必须以root权限运行"
    fi
}

# ─── 函数：获取IPv4默认网关和网卡 ────────────────────────────────────────────
get_default_route() {
    DEFAULT_GW=$(ip route show default | awk '/default/ {print $3}' | head -n1)
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)

    if [[ -z "$DEFAULT_GW" || -z "$DEFAULT_IFACE" ]]; then
        fatal "无法获取IPv4默认网关或网卡信息"
    fi

    info "IPv4 默认网关: ${DEFAULT_GW}  默认网卡: ${DEFAULT_IFACE}"
}

# ─── 函数：获取IPv6默认网关和网卡 ────────────────────────────────────────────
get_default_route6() {
    DEFAULT_GW6=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $3}' | head -n1)
    DEFAULT_IFACE6=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1)

    if [[ -n "$DEFAULT_GW6" && -n "$DEFAULT_IFACE6" ]]; then
        info "IPv6 默认网关: ${DEFAULT_GW6}  默认网卡: ${DEFAULT_IFACE6}"
        HAS_IPV6=1
    else
        warn "无法获取IPv6默认网关，将跳过IPv6路由处理"
        HAS_IPV6=0
    fi
}

# ─── 函数：获取TUN IPv4 对端IP ────────────────────────────────────────────────
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
        info "TUN IPv4 对端: ${TUN_PEER}"
    else
        warn "TUN设备 ${TUN_DEV} 未就绪或无法获取IPv4对端IP，隧道默认路由将跳过"
    fi
}

# ─── 函数：获取TUN IPv6 对端IP ────────────────────────────────────────────────
get_tun_peer6() {
    TUN_PEER6=""
    if ip link show "$TUN_DEV" &>/dev/null; then
        # 获取 TUN 设备上的全局 IPv6 地址的 peer 地址
        TUN_PEER6=$(ip -6 addr show dev "$TUN_DEV" scope global 2>/dev/null | \
            awk '/peer / { split($4, a, "/"); print a[1] }' | head -n1)
        if [[ -z "$TUN_PEER6" ]]; then
            # 尝试从 IPv6 路由获取（fd00::/ULA 或全局地址）
            TUN_PEER6=$(ip -6 route show dev "$TUN_DEV" 2>/dev/null | \
                awk '/^[0-9a-f]/ && !/^fe80/ { split($1, a, "/"); print a[1] }' | head -n1)
        fi
    fi

    if [[ -n "$TUN_PEER6" ]]; then
        info "TUN IPv6 对端: ${TUN_PEER6}"
    else
        warn "无法获取TUN IPv6对端IP，IPv6隧道默认路由将跳过"
    fi
}

# ─── 函数：下载APNIC数据 ────────────────────────────────────────────────────
download_apnic() {
    info "下载APNIC数据..."
    mkdir -p "$DATA_DIR"

    local downloaded=0
    for url in "${APNIC_MIRROR_URLS[@]}"; do
        info "尝试下载: ${url}"
        if curl -s -o "${APNIC_FILE}.tmp" --connect-timeout 15 --max-time 120 "$url"; then
            # 验证文件有效性（至少包含 CN 行）
            if grep -q '|CN|' "${APNIC_FILE}.tmp" 2>/dev/null; then
                mv "${APNIC_FILE}.tmp" "$APNIC_FILE"
                info "APNIC数据下载完成: $(wc -l < "$APNIC_FILE") 行"
                downloaded=1
                break
            else
                warn "下载的文件内容无效，尝试下一个镜像..."
                rm -f "${APNIC_FILE}.tmp"
            fi
        else
            warn "从 ${url} 下载失败，尝试下一个镜像..."
            rm -f "${APNIC_FILE}.tmp"
        fi
    done

    if [[ "$downloaded" -eq 0 ]]; then
        if [[ -f "$APNIC_FILE" ]]; then
            warn "所有镜像下载失败，使用上次缓存的数据"
        else
            warn "所有镜像下载失败，且无缓存可用。将仅配置策略路由（无CN IP分流，所有流量走隧道）"
            APNIC_DOWNLOAD_FAILED=1
        fi
    fi
}

# ─── 函数：解析CN IPv4段并生成批量路由命令 ────────────────────────────────────
generate_routes_v4() {
    info "解析中国大陆 IPv4 地址段..."

    # APNIC IPv4 格式: apnic|CN|ipv4|起始IP|主机数|日期|状态
    # hosts → CIDR 前缀长度（主机数一定是 2 的幂）
    awk -F'|' \
        -v gw="$DEFAULT_GW" \
        -v iface="$DEFAULT_IFACE" \
        -v table="$ROUTE_TABLE_CN" \
    '
    $1 == "apnic" && $2 == "CN" && $3 == "ipv4" {
        hosts = $5 + 0
        prefix = 32
        n = 1
        while (n < hosts) {
            n *= 2
            prefix--
        }
        print "route add " $4 "/" prefix " via " gw " dev " iface " table " table
    }
    ' "$APNIC_FILE" > "$BATCH_FILE_V4"

    local count
    count=$(wc -l < "$BATCH_FILE_V4")
    info "共解析 ${count} 条中国大陆 IPv4 路由"
    echo "$count"
}

# ─── 函数：解析CN IPv6段并生成批量路由命令 ────────────────────────────────────
generate_routes_v6() {
    if [[ "$HAS_IPV6" -ne 1 ]]; then
        info "跳过 IPv6 路由生成（无IPv6默认路由）"
        echo "0" > "$BATCH_FILE_V6"
        echo "0"
        return
    fi

    info "解析中国大陆 IPv6 地址段..."

    # APNIC IPv6 格式: apnic|CN|ipv6|前缀|前缀长度|日期|状态
    # 例如: apnic|CN|ipv6|2001:250::|35|20000101|allocated
    # 注意: $5 已经是 CIDR 前缀长度，无需转换
    awk -F'|' \
        -v gw="$DEFAULT_GW6" \
        -v iface="$DEFAULT_IFACE6" \
        -v table="$ROUTE_TABLE_CN" \
    '
    $1 == "apnic" && $2 == "CN" && $3 == "ipv6" {
        prefix_len = $5 + 0
        # 过滤无效的前缀长度
        if (prefix_len >= 16 && prefix_len <= 128) {
            print "-6 route add " $4 "/" prefix_len " via " gw " dev " iface " table " table
        }
    }
    ' "$APNIC_FILE" > "$BATCH_FILE_V6"

    local count
    count=$(wc -l < "$BATCH_FILE_V6")
    info "共解析 ${count} 条中国大陆 IPv6 路由"
    echo "$count"
}

# ─── 函数：刷新并应用IPv4路由 ────────────────────────────────────────────────
apply_routes_v4() {
    info "刷新 IPv4 路由表 ${ROUTE_TABLE_CN}..."
    ip route flush table "$ROUTE_TABLE_CN" 2>/dev/null || true

    info "批量添加中国大陆 IPv4 路由..."
    if [[ -s "$BATCH_FILE_V4" ]]; then
        ip -batch "$BATCH_FILE_V4" 2>/dev/null || {
            warn "部分IPv4路由添加失败，尝试逐条添加..."
            local failed=0
            while read -r line; do
                ip $line 2>/dev/null || failed=$((failed + 1))
            done < "$BATCH_FILE_V4"
            if [[ $failed -gt 0 ]]; then
                warn "${failed} 条IPv4路由添加失败"
            fi
        }
    else
        warn "IPv4 路由批量文件为空"
    fi

    info "IPv4 路由更新完成"
}

# ─── 函数：刷新并应用IPv6路由 ────────────────────────────────────────────────
apply_routes_v6() {
    if [[ "$HAS_IPV6" -ne 1 ]]; then
        info "跳过 IPv6 路由应用（无IPv6默认路由）"
        return
    fi

    info "刷新 IPv6 路由表 ${ROUTE_TABLE_CN}..."
    ip -6 route flush table "$ROUTE_TABLE_CN" 2>/dev/null || true

    info "批量添加中国大陆 IPv6 路由..."
    if [[ -s "$BATCH_FILE_V6" ]]; then
        ip -batch "$BATCH_FILE_V6" 2>/dev/null || {
            warn "部分IPv6路由添加失败，尝试逐条添加..."
            local failed=0
            while read -r line; do
                ip $line 2>/dev/null || failed=$((failed + 1))
            done < "$BATCH_FILE_V6"
            if [[ $failed -gt 0 ]]; then
                warn "${failed} 条IPv6路由添加失败"
            fi
        }
    else
        warn "IPv6 路由批量文件为空"
    fi

    info "IPv6 路由更新完成"
}

# ─── 函数：确保策略路由规则存在 ──────────────────────────────────────────────
setup_policy_rules() {
    info "配置策略路由规则..."

    # === IPv4 策略规则 ===

    # 规则1: 带有 fwmark 标记的流量查 CN 路由表（中国IP直连）
    if ! ip rule show | grep -q "fwmark ${FWMARK} lookup ${ROUTE_TABLE_CN}"; then
        ip rule add fwmark "$FWMARK" table "$ROUTE_TABLE_CN" priority 100
        info "已添加 IPv4 策略规则: fwmark ${FWMARK} -> table ${ROUTE_TABLE_CN}"
    else
        info "IPv4 策略规则(CN)已存在，跳过"
    fi

    # 规则2: 来自 VPN 客户端子网的流量查隧道路由表
    if ! ip rule show | grep -q "from 10.10.10.0/24 lookup ${ROUTE_TABLE_TUNNEL}"; then
        ip rule add from 10.10.10.0/24 table "$ROUTE_TABLE_TUNNEL" priority 200
        info "已添加 IPv4 策略规则: from 10.10.10.0/24 -> table ${ROUTE_TABLE_TUNNEL}"
    else
        info "IPv4 策略规则(Tunnel)已存在，跳过"
    fi

    # iptables mangle: 对来自VPN客户端的流量打上fwmark标记
    if ! iptables -t mangle -C PREROUTING -s 10.10.10.0/24 -j MARK --set-mark ${FWMARK} 2>/dev/null; then
        iptables -t mangle -A PREROUTING -s 10.10.10.0/24 -j MARK --set-mark ${FWMARK}
    fi

    # === IPv6 策略规则（如果有IPv6默认路由） ===
    if [[ "$HAS_IPV6" -eq 1 ]]; then
        # IPv6 fwmark 策略: 带标记的IPv6流量查 CN 路由表
        if ! ip -6 rule show 2>/dev/null | grep -q "fwmark ${FWMARK} lookup ${ROUTE_TABLE_CN}"; then
            ip -6 rule add fwmark "$FWMARK" table "$ROUTE_TABLE_CN" priority 100
            info "已添加 IPv6 策略规则: fwmark ${FWMARK} -> table ${ROUTE_TABLE_CN}"
        else
            info "IPv6 策略规则(CN)已存在，跳过"
        fi

        # IPv6 隧道策略: 来自 VPN 客户端子网的 IPv6 流量查隧道路由表
        # 注：PPP 客户端可能没有 IPv6 地址，这里为 TUN IPv6 子网添加策略
        if [[ -n "$TUN_PEER6" ]]; then
            # 获取 TUN 设备上本端的 IPv6 地址/前缀
            local tun_local6
            tun_local6=$(ip -6 addr show dev "$TUN_DEV" scope global 2>/dev/null | \
                awk '/inet6/ && !/peer/ { print $2 }' | head -n1)
            if [[ -n "$tun_local6" ]]; then
                local tun6_net
                tun6_net=$(echo "$tun_local6" | sed 's|/[0-9]*$||')
                local tun6_prefix
                tun6_prefix=$(echo "$tun_local6" | grep -o '/[0-9]*$' | tr -d '/')
                : "${tun6_prefix:=64}"
                # 简化：使用 from 规则匹配 TUN IPv6 子网
                # 通常 PPP 客户端不会有 IPv6，此规则主要为将来扩展保留
            fi
        fi

        # IPv6 隧道默认路由策略（与 IPv4 类似）
        # 对于 PPP 客户端的 IPv6 流量，目前通过 fwmark 分流即可
        info "IPv6 策略路由规则配置完成"
    fi

    info "策略路由规则配置完成"
}

# ─── 函数：确保隧道默认路由存在（IPv4 + IPv6） ────────────────────────────────
setup_tunnel_default_route() {
    info "配置隧道默认路由..."

    # === IPv4 隧道默认路由 ===
    if [[ -n "$TUN_PEER" ]]; then
        if ! ip route show table "$ROUTE_TABLE_TUNNEL" | grep -q "default"; then
            ip route add default via "$TUN_PEER" dev "$TUN_DEV" table "$ROUTE_TABLE_TUNNEL" 2>/dev/null || {
                warn "添加 IPv4 隧道默认路由失败（TUN设备可能未就绪）"
            }
            info "已添加 IPv4 隧道默认路由: default via ${TUN_PEER} dev ${TUN_DEV} table ${ROUTE_TABLE_TUNNEL}"
        else
            info "IPv4 隧道默认路由已存在，跳过"
        fi
    else
        warn "TUN IPv4 对端未知，跳过 IPv4 隧道默认路由"
    fi

    # === IPv6 隧道默认路由 ===
    if [[ "$HAS_IPV6" -eq 1 && -n "$TUN_PEER6" ]]; then
        if ! ip -6 route show table "$ROUTE_TABLE_TUNNEL" 2>/dev/null | grep -q "default"; then
            ip -6 route add default via "$TUN_PEER6" dev "$TUN_DEV" table "$ROUTE_TABLE_TUNNEL" 2>/dev/null || {
                warn "添加 IPv6 隧道默认路由失败（TUN设备或IPv6未就绪）"
            }
            info "已添加 IPv6 隧道默认路由: default via ${TUN_PEER6} dev ${TUN_DEV} table ${ROUTE_TABLE_TUNNEL}"
        else
            info "IPv6 隧道默认路由已存在，跳过"
        fi
    else
        if [[ "$HAS_IPV6" -eq 1 ]]; then
            warn "TUN IPv6 对端未知，跳过 IPv6 隧道默认路由"
        fi
    fi
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
    local count_v4=$1
    local count_v6=$2
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local cn_routes_v4
    cn_routes_v4=$(ip route show table "$ROUTE_TABLE_CN" 2>/dev/null | wc -l)
    local cn_routes_v6
    cn_routes_v6=$(ip -6 route show table "$ROUTE_TABLE_CN" 2>/dev/null | wc -l)

    local log_entry="[${timestamp}] 路由更新完成: IPv4 解析 ${count_v4} 条/生效 ${cn_routes_v4} 条, IPv6 解析 ${count_v6} 条/生效 ${cn_routes_v6} 条"
    echo "$log_entry" >> "$LOG_FILE"
    info "$log_entry"
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  MiniVPN APNIC中国大陆路由更新（IPv4 + IPv6）    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    # 文件锁：防止多个实例同时运行
    exec 200>/var/lock/minivpn-routes.lock
    flock -n 200 || { warn "另一个实例正在运行，退出"; exit 0; }

    APNIC_DOWNLOAD_FAILED=0

    get_default_route
    get_default_route6
    get_tun_peer
    get_tun_peer6
    register_route_tables

    # 无论 APNIC 数据是否可用，都要先设置策略规则和隧道默认路由
    # 这确保即使没有 CN IP 分流数据，外网流量也能通过隧道转发
    setup_policy_rules
    setup_tunnel_default_route

    download_apnic

    local count_v4=0 count_v6=0
    if [[ "$APNIC_DOWNLOAD_FAILED" -eq 0 ]]; then
        count_v4=$(generate_routes_v4)
        count_v6=$(generate_routes_v6)

        apply_routes_v4
        apply_routes_v6
    else
        warn "跳过 CN 路由更新（APNIC 数据不可用），所有标记流量将走隧道"
    fi

    log_result "$count_v4" "$count_v6"

    echo ""
    info "路由更新完成！无需重启任何服务。"
    echo ""
}

main "$@"
