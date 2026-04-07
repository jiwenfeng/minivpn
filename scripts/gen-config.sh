#!/bin/bash
set -e

###############################################################################
# gen-config.sh - MiniVPN 配置文件生成脚本
# 用法:
#   ./gen-config.sh -s -l 0.0.0.0:4567 -k mysecret                  # 服务端
#   ./gen-config.sh -c -r 1.2.3.4:4567 -k mysecret                  # 客户端
#   ./gen-config.sh -i                                                # 交互模式
#   ./gen-config.sh -s -l 0.0.0.0:4567 -k mysecret -o /etc/minivpn/minivpn.conf
# 面向: GNU bash 5.2.15+ (Ubuntu 22.04+ / Debian 12+)
###############################################################################

# ─── 颜色输出 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal()   { error "$*"; exit 1; }

# ─── 默认值 ──────────────────────────────────────────────────────────────────
MODE=""                   # server 或 client
LISTEN=""                 # ADDR:PORT（server 模式）
REMOTE=""                 # ADDR:PORT（client 模式）
SECRET=""                 # 预共享密钥
TUN_IP=""                 # TUN 本端 IP
TUN_PEER=""               # TUN 对端 IP
THREADS=""                # Worker 线程数（空=自动检测 CPU 核数）
MTU="1400"                # MTU
LOG_LEVEL="1"             # 日志级别: 0=ERROR, 1=INFO, 2=DEBUG
OUTPUT=""                 # 输出文件路径（空=stdout）
INTERACTIVE=false         # 是否交互模式
FORCE=false               # 是否覆盖已有文件

# ─── 函数：显示用法 ──────────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
用法: $0 [选项]

模式:
  -s, --server              生成服务端配置
  -c, --client              生成客户端配置
  -i, --interactive         交互式引导生成

网络:
  -l, --listen ADDR:PORT    监听地址（server 模式，如 0.0.0.0:4567）
  -r, --remote ADDR:PORT    远端地址（client 模式，如 1.2.3.4:4567）
  -k, --secret KEY          预共享密钥

TUN 设备:
      --tun-ip IP           TUN 本端 IP（默认: server=172.16.0.1, client=172.16.0.2）
      --tun-peer IP         TUN 对端 IP（默认: server=172.16.0.2, client=172.16.0.1）
      --mtu N               MTU（默认: 1400）

性能:
  -t, --threads N           Worker 线程数（默认: 自动检测 CPU 核数）

日志:
      --log-level N         日志级别 0=ERROR, 1=INFO, 2=DEBUG（默认: 1）

输出:
  -o, --output FILE         输出文件路径（默认: 输出到 stdout）
  -f, --force               强制覆盖已有文件
  -h, --help                显示此帮助信息

示例:
  # 生成服务端配置并输出到 stdout
  $0 -s -l 0.0.0.0:4567 -k my-strong-secret

  # 生成客户端配置并写入文件
  $0 -c -r 1.2.3.4:4567 -k my-strong-secret -o /etc/minivpn/minivpn.conf

  # 交互式引导生成
  $0 -i

  # 自动生成随机密钥的服务端配置
  $0 -s -l 0.0.0.0:4567 -k \$(openssl rand -hex 32) -o server.conf
EOF
}

# ─── 函数：校验 ADDR:PORT 格式 ───────────────────────────────────────────────
validate_addr_port() {
    local input="$1"
    local label="$2"

    if [[ -z "$input" ]]; then
        fatal "${label} 不能为空"
    fi

    local addr port
    # 取最后一个冒号后面的部分作为端口
    addr="${input%:*}"
    port="${input##*:}"

    if [[ -z "$addr" || -z "$port" || "$addr" == "$input" ]]; then
        fatal "${label} 格式不正确 '${input}'，应为 ADDR:PORT（如 0.0.0.0:4567）"
    fi

    # 校验端口范围
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        fatal "${label} 端口号无效 '${port}'，应为 1-65535"
    fi
}

# ─── 函数：校验 IP 地址格式 ──────────────────────────────────────────────────
validate_ip() {
    local ip="$1"
    local label="$2"

    if [[ -z "$ip" ]]; then
        fatal "${label} 不能为空"
    fi

    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        fatal "${label} 格式不正确 '${ip}'，应为 IPv4 地址（如 172.16.0.1）"
    fi

    # 校验每个八位组
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
            fatal "${label} 地址无效 '${ip}'，八位组 ${octet} 超出 0-255 范围"
        fi
    done
}

# ─── 函数：解析命令行参数 ────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--server)
                MODE="server"
                shift
                ;;
            -c|--client)
                MODE="client"
                shift
                ;;
            -i|--interactive)
                INTERACTIVE=true
                shift
                ;;
            -l|--listen)
                LISTEN="$2"
                shift 2
                ;;
            -r|--remote)
                REMOTE="$2"
                shift 2
                ;;
            -k|--secret)
                SECRET="$2"
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
            --mtu)
                MTU="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT="$2"
                shift 2
                ;;
            -f|--force)
                FORCE=true
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
}

# ─── 函数：交互模式 ──────────────────────────────────────────────────────────
interactive_mode() {
    echo "" >&2
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}" >&2
    echo -e "${CYAN}║  MiniVPN 配置文件生成向导                  ║${NC}" >&2
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}" >&2
    echo "" >&2

    # 选择模式
    if [[ -z "$MODE" ]]; then
        echo -e "${CYAN}请选择运行模式:${NC}" >&2
        echo -e "  1) server（服务端 - 远端出口节点）" >&2
        echo -e "  2) client（客户端 - 近端入口节点）" >&2
        while true; do
            read -r -p "请输入 [1/2]: " choice
            case "$choice" in
                1) MODE="server"; break ;;
                2) MODE="client"; break ;;
                *) echo -e "${RED}无效选择，请输入 1 或 2${NC}" >&2 ;;
            esac
        done
        echo "" >&2
    fi

    # 网络地址
    if [[ "$MODE" == "server" && -z "$LISTEN" ]]; then
        read -r -p "$(echo -e "${CYAN}监听地址 [0.0.0.0:4567]:${NC} ")" LISTEN
        [[ -z "$LISTEN" ]] && LISTEN="0.0.0.0:4567"
    fi

    if [[ "$MODE" == "client" && -z "$REMOTE" ]]; then
        read -r -p "$(echo -e "${CYAN}远端服务器地址 (ADDR:PORT):${NC} ")" REMOTE
        if [[ -z "$REMOTE" ]]; then
            fatal "客户端模式必须指定远端地址"
        fi
    fi

    # 密钥
    if [[ -z "$SECRET" ]]; then
        echo -e "${CYAN}预共享密钥（两端必须一致）:${NC}" >&2
        echo -e "  直接输入密钥，或按回车自动生成 32 字节随机密钥" >&2
        read -r -p "密钥: " SECRET
        if [[ -z "$SECRET" ]]; then
            if command -v openssl &>/dev/null; then
                SECRET=$(openssl rand -hex 32)
                info "已自动生成密钥: ${SECRET}"
            else
                fatal "未安装 openssl，无法自动生成密钥。请手动指定。"
            fi
        fi
        echo "" >&2
    fi

    # TUN IP
    if [[ -z "$TUN_IP" ]]; then
        local default_tun_ip
        if [[ "$MODE" == "server" ]]; then
            default_tun_ip="172.16.0.1"
        else
            default_tun_ip="172.16.0.2"
        fi
        read -r -p "$(echo -e "${CYAN}TUN 本端 IP [${default_tun_ip}]:${NC} ")" TUN_IP
        [[ -z "$TUN_IP" ]] && TUN_IP="$default_tun_ip"
    fi

    if [[ -z "$TUN_PEER" ]]; then
        local default_tun_peer
        if [[ "$MODE" == "server" ]]; then
            default_tun_peer="172.16.0.2"
        else
            default_tun_peer="172.16.0.1"
        fi
        read -r -p "$(echo -e "${CYAN}TUN 对端 IP [${default_tun_peer}]:${NC} ")" TUN_PEER
        [[ -z "$TUN_PEER" ]] && TUN_PEER="$default_tun_peer"
    fi

    # MTU
    read -r -p "$(echo -e "${CYAN}MTU [${MTU}]:${NC} ")" input_mtu
    [[ -n "$input_mtu" ]] && MTU="$input_mtu"

    # 线程数
    read -r -p "$(echo -e "${CYAN}Worker 线程数 [自动检测]:${NC} ")" THREADS

    # 日志级别
    echo -e "${CYAN}日志级别:${NC}" >&2
    echo -e "  0) ERROR（仅错误）" >&2
    echo -e "  1) INFO（默认）" >&2
    echo -e "  2) DEBUG（详细调试）" >&2
    read -r -p "$(echo -e "${CYAN}日志级别 [${LOG_LEVEL}]:${NC} ")" input_log
    [[ -n "$input_log" ]] && LOG_LEVEL="$input_log"

    # 输出路径
    if [[ -z "$OUTPUT" ]]; then
        read -r -p "$(echo -e "${CYAN}输出文件路径 [stdout]:${NC} ")" OUTPUT
    fi

    echo "" >&2
}

# ─── 函数：设置默认 TUN IP ───────────────────────────────────────────────────
apply_defaults() {
    if [[ -z "$TUN_IP" ]]; then
        if [[ "$MODE" == "server" ]]; then
            TUN_IP="172.16.0.1"
        else
            TUN_IP="172.16.0.2"
        fi
    fi

    if [[ -z "$TUN_PEER" ]]; then
        if [[ "$MODE" == "server" ]]; then
            TUN_PEER="172.16.0.2"
        else
            TUN_PEER="172.16.0.1"
        fi
    fi
}

# ─── 函数：参数校验 ──────────────────────────────────────────────────────────
validate_params() {
    # 模式
    if [[ -z "$MODE" ]]; then
        fatal "必须指定运行模式: -s (server) 或 -c (client) 或 -i (交互模式)"
    fi

    if [[ "$MODE" != "server" && "$MODE" != "client" ]]; then
        fatal "运行模式无效 '${MODE}'，应为 server 或 client"
    fi

    # 密钥
    if [[ -z "$SECRET" ]]; then
        fatal "必须指定预共享密钥 (-k)"
    fi

    if [[ ${#SECRET} -lt 8 ]]; then
        warn "密钥长度不足 8 字符，建议使用更强的密钥"
    fi

    # 网络地址
    if [[ "$MODE" == "server" ]]; then
        if [[ -z "$LISTEN" ]]; then
            fatal "服务端模式必须指定监听地址 (-l ADDR:PORT)"
        fi
        validate_addr_port "$LISTEN" "监听地址"
    else
        if [[ -z "$REMOTE" ]]; then
            fatal "客户端模式必须指定远端地址 (-r ADDR:PORT)"
        fi
        validate_addr_port "$REMOTE" "远端地址"
    fi

    # TUN IP
    validate_ip "$TUN_IP" "TUN 本端 IP"
    validate_ip "$TUN_PEER" "TUN 对端 IP"

    if [[ "$TUN_IP" == "$TUN_PEER" ]]; then
        fatal "TUN 本端 IP 和对端 IP 不能相同: ${TUN_IP}"
    fi

    # MTU
    if ! [[ "$MTU" =~ ^[0-9]+$ ]] || [[ "$MTU" -lt 576 || "$MTU" -gt 65535 ]]; then
        fatal "MTU 值无效 '${MTU}'，应为 576-65535"
    fi

    # 线程数
    if [[ -n "$THREADS" ]]; then
        if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
            fatal "线程数无效 '${THREADS}'，应为正整数"
        fi
    fi

    # 日志级别
    if ! [[ "$LOG_LEVEL" =~ ^[0-2]$ ]]; then
        fatal "日志级别无效 '${LOG_LEVEL}'，应为 0、1 或 2"
    fi

    # 输出文件
    if [[ -n "$OUTPUT" && -f "$OUTPUT" && "$FORCE" != true ]]; then
        fatal "输出文件已存在: ${OUTPUT}（使用 -f 覆盖）"
    fi
}

# ─── 函数：生成配置内容 ──────────────────────────────────────────────────────
generate_config() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    cat <<EOF
# ============================================================
# MiniVPN 配置文件
# 由 gen-config.sh 自动生成于 ${timestamp}
# ============================================================

# 运行模式: server 或 client
mode = ${MODE}
EOF

    if [[ "$MODE" == "server" ]]; then
        cat <<EOF

# 监听地址（server 模式）
# 格式: ADDR:PORT
listen = ${LISTEN}
EOF
    else
        cat <<EOF

# 远端地址（client 模式）
# 格式: ADDR:PORT
remote = ${REMOTE}
EOF
    fi

    cat <<EOF

# 预共享密钥（server/client 两端必须一致）
secret = ${SECRET}

# TUN 设备本端 IP
tun_ip = ${TUN_IP}

# TUN 设备对端 IP
tun_peer = ${TUN_PEER}
EOF

    if [[ -n "$THREADS" ]]; then
        cat <<EOF

# Worker 线程数
threads = ${THREADS}
EOF
    else
        cat <<EOF

# Worker 线程数（默认为 CPU 核数）
# threads = 4
EOF
    fi

    cat <<EOF

# MTU（默认 1400）
mtu = ${MTU}

# 日志级别: 0=ERROR, 1=INFO, 2=DEBUG
log_level = ${LOG_LEVEL}
EOF
}

# ─── 函数：输出配置 ──────────────────────────────────────────────────────────
write_config() {
    local config
    config=$(generate_config)

    if [[ -z "$OUTPUT" ]]; then
        # 输出到 stdout
        echo "$config"
    else
        # 写入文件
        local dir
        dir=$(dirname "$OUTPUT")
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            info "已创建目录: ${dir}"
        fi

        echo "$config" > "$OUTPUT"
        chmod 600 "$OUTPUT"
        info "配置文件已生成: ${OUTPUT}（权限 600）"

        # 摘要
        echo "" >&2
        echo -e "${GREEN}════════════════════════════════════════${NC}" >&2
        echo -e "${GREEN}  配置文件生成成功！${NC}" >&2
        echo -e "${GREEN}════════════════════════════════════════${NC}" >&2
        echo "" >&2
        echo -e "  模式:      ${MODE}" >&2
        if [[ "$MODE" == "server" ]]; then
            echo -e "  监听地址:  ${LISTEN}" >&2
        else
            echo -e "  远端地址:  ${REMOTE}" >&2
        fi
        echo -e "  TUN 本端:  ${TUN_IP}" >&2
        echo -e "  TUN 对端:  ${TUN_PEER}" >&2
        echo -e "  MTU:       ${MTU}" >&2
        echo -e "  日志级别:  ${LOG_LEVEL}" >&2
        echo -e "  文件路径:  ${OUTPUT}" >&2
        echo "" >&2
        echo -e "  使用方式:" >&2
        echo -e "    minivpn -f ${OUTPUT}" >&2
        echo "" >&2
    fi
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    if [[ "$INTERACTIVE" == true ]]; then
        interactive_mode
    fi

    apply_defaults
    validate_params
    write_config
}

main "$@"
