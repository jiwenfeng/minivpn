#!/bin/bash
set -e

###############################################################################
# add-user.sh - MiniVPN (L2TP/IPsec) 用户管理脚本
# 用法:
#   ./add-user.sh <username> <password>   # 添加用户
#   ./add-user.sh -d <username>           # 删除用户
#   ./add-user.sh -l                      # 列出所有用户
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

# ─── 常量 ────────────────────────────────────────────────────────────────────
CHAP_SECRETS="/etc/ppp/chap-secrets"
PPP_SERVER="l2tpd"

# ─── 函数：检查root权限 ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "此脚本必须以root权限运行，请使用 sudo 或切换到root用户"
    fi
}

# ─── 函数：显示用法 ──────────────────────────────────────────────────────────
usage() {
    cat <<EOF
用法:
  $0 <username> <password>     添加VPN用户
  $0 -d <username>             删除VPN用户
  $0 -l                        列出所有VPN用户
  $0 -h                        显示此帮助信息

示例:
  $0 alice mypassword123       # 添加用户alice
  $0 -d alice                  # 删除用户alice
  $0 -l                        # 列出所有用户
EOF
}

# ─── 函数：确保chap-secrets文件存在 ─────────────────────────────────────────
ensure_chap_file() {
    if [[ ! -f "$CHAP_SECRETS" ]]; then
        mkdir -p "$(dirname "$CHAP_SECRETS")"
        cat > "$CHAP_SECRETS" <<'EOF'
# Secrets for authentication using CHAP
# client    server  secret          IP addresses
EOF
        chmod 600 "$CHAP_SECRETS"
        info "已创建 ${CHAP_SECRETS}"
    fi
}

# ─── 函数：添加用户 ─────────────────────────────────────────────────────────
add_user() {
    local username="$1"
    local password="$2"

    if [[ -z "$username" || -z "$password" ]]; then
        fatal "添加用户需要提供用户名和密码\n用法: $0 <username> <password>"
    fi

    # 检查用户名合法性（只允许字母、数字、下划线、连字符）
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        fatal "用户名只能包含字母、数字、下划线和连字符"
    fi

    ensure_chap_file

    # 幂等：检查用户是否已存在
    if grep -q "^${username} " "$CHAP_SECRETS" 2>/dev/null; then
        warn "用户 '${username}' 已存在"
        read -r -p "是否更新密码？[y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 删除旧条目
            sed -i "/^${username} /d" "$CHAP_SECRETS"
            echo "${username} ${PPP_SERVER} ${password} *" >> "$CHAP_SECRETS"
            info "用户 '${username}' 密码已更新"
        else
            info "操作已取消"
        fi
    else
        echo "${username} ${PPP_SERVER} ${password} *" >> "$CHAP_SECRETS"
        info "用户 '${username}' 添加成功"
    fi
}

# ─── 函数：删除用户 ─────────────────────────────────────────────────────────
delete_user() {
    local username="$1"

    if [[ -z "$username" ]]; then
        fatal "删除用户需要提供用户名\n用法: $0 -d <username>"
    fi

    ensure_chap_file

    if grep -q "^${username} " "$CHAP_SECRETS" 2>/dev/null; then
        sed -i "/^${username} /d" "$CHAP_SECRETS"
        info "用户 '${username}' 已删除"
    else
        warn "用户 '${username}' 不存在"
    fi
}

# ─── 函数：列出所有用户 ─────────────────────────────────────────────────────
list_users() {
    ensure_chap_file

    echo ""
    echo -e "${GREEN}── VPN 用户列表 ──${NC}"
    echo ""

    local count=0
    while IFS= read -r line; do
        # 跳过注释行和空行
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

        local username
        username=$(echo "$line" | awk '{print $1}')
        if [[ -n "$username" ]]; then
            echo -e "  ${GREEN}●${NC} ${username}"
            count=$((count + 1))
        fi
    done < "$CHAP_SECRETS"

    echo ""
    if [[ $count -eq 0 ]]; then
        warn "暂无VPN用户"
    else
        info "共 ${count} 个用户"
    fi
    echo ""
}

# ─── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    check_root

    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -l|--list)
            list_users
            ;;
        -d|--delete)
            delete_user "$2"
            ;;
        -*)
            fatal "未知选项: $1\n使用 -h 查看帮助"
            ;;
        *)
            add_user "$1" "$2"
            ;;
    esac
}

main "$@"
