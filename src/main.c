/*
 * MiniVPN - 程序入口
 *
 * 功能：
 * 1. 命令行参数解析（getopt_long）
 * 2. 配置文件解析（简单 INI 格式）
 * 3. 参数校验
 * 4. protocol_init() 初始化协议层
 * 5. 调用 server_run() 或 client_run()
 *
 * 改进:
 * - 支持 IPv6 地址格式 [addr]:port
 * - 自动检测地址族 (含 ':' 视为 IPv6)
 * - 新增 --ipv6/-6, --tun-ip6, --tun-peer6 选项
 * - 密钥安全擦除使用 OPENSSL_cleanse
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "log.h"
#include "config.h"
#include "protocol.h"

#define VERSION "0.3.0"

/* ========== 全局日志级别（log.h 中 extern 引用） ========== */

int g_log_level = 1;

/* 外部函数声明 */
extern int server_run(const struct vpn_config *cfg);
extern int client_run(const struct vpn_config *cfg);

/* ========== 内部配置（命令行 + 配置文件合并后） ========== */

struct app_config {
    enum vpn_mode mode;
    char listen[128];       /* ADDR:PORT 或 [IPv6]:PORT */
    char remote[128];       /* ADDR:PORT 或 [IPv6]:PORT */
    char secret[256];
    char secret_file[256];  /* 密钥文件路径 */
    char tun_ip[64];        /* TUN IPv4 本端地址 */
    char tun_peer[64];      /* TUN IPv4 对端地址 */
    char tun_ip6[64];       /* TUN IPv6 本端地址（可选，双栈使用） */
    char tun_peer6[64];     /* TUN IPv6 对端地址（可选，双栈使用） */
    int tun_ip6_prefix;     /* IPv6 前缀长度（默认 64） */
    int ipv6;               /* 强制使用 IPv6: 0=自动, 1=强制 IPv6 */
    int threads;
    int mtu;
    int log_level;
    char config_file[256];
};

/* ========== 帮助信息 ========== */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "MiniVPN v" VERSION " - 轻量级点对点 VPN\n"
        "\n"
        "用法: %s [选项]\n"
        "\n"
        "模式:\n"
        "  -s, --server             服务端模式\n"
        "  -c, --client             客户端模式\n"
        "\n"
        "网络:\n"
        "  -l, --listen ADDR:PORT   监听地址 (如 0.0.0.0:4567 或 [::]:4567)\n"
        "  -r, --remote ADDR:PORT   远端地址 (如 1.2.3.4:4567 或 [::1]:4567)\n"
        "  -k, --secret KEY         预共享密钥\n"
        "      --secret-file FILE   从文件读取密钥\n"
        "  -6, --ipv6               强制使用 IPv6 (默认自动检测)\n"
        "\n"
        "TUN 设备:\n"
        "      --tun-ip IP          TUN 本端 IPv4 (如 172.16.0.1)\n"
        "      --tun-peer IP        TUN 对端 IPv4 (如 172.16.0.2)\n"
        "      --tun-ip6 IP6        TUN 本端 IPv6 (如 fd00::1，可选)\n"
        "      --tun-peer6 IP6      TUN 对端 IPv6 (如 fd00::2，可选)\n"
        "      --mtu N              MTU (默认 1400)\n"
        "\n"
        "性能:\n"
        "  -t, --threads N          Worker 线程数 (默认=CPU核数)\n"
        "\n"
        "其它:\n"
        "  -f, --config FILE        配置文件路径\n"
        "  -v, --verbose            增加日志级别 (可多次使用 -vv)\n"
        "  -h, --help               显示帮助信息\n"
        "  -V, --version            显示版本号\n"
        "\n"
        "配置文件格式 (INI，无 section):\n"
        "  mode = server\n"
        "  listen = 0.0.0.0:4567\n"
        "  # listen = [::]:4567      # IPv6 监听\n"
        "  secret = my-secret\n"
        "  tun_ip = 172.16.0.1\n"
        "  tun_peer = 172.16.0.2\n"
        "  tun_ip6 = fd00::1         # 可选: IPv6 TUN 地址\n"
        "  tun_peer6 = fd00::2       # 可选: IPv6 TUN 对端\n"
        "  tun_ip6_prefix = 64       # 可选: IPv6 前缀长度\n"
        "  ipv6 = no                 # 可选: yes/no 强制 IPv6\n"
        "  threads = 4\n"
        "  mtu = 1400\n"
        "  log_level = 1\n"
        "\n"
        "命令行参数优先级高于配置文件。\n",
        prog);
}

static void print_version(void)
{
    printf("MiniVPN v" VERSION "\n");
}

/* ========== 字符串工具 ========== */

/* 去除字符串首尾空白 */
static char *str_trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

/*
 * 解析 ADDR:PORT 格式（支持 IPv4 和 IPv6）
 *
 * IPv4 格式: 1.2.3.4:4567
 * IPv6 格式: [::1]:4567 或 [2001:db8::1]:4567
 *
 * 输出：
 *   addr_buf: 纯地址（不含 [] 和端口）
 *   port:     端口号
 *   is_ipv6:  是否为 IPv6 地址（1=IPv6, 0=IPv4, NULL=忽略）
 */
static int parse_addr_port(const char *input, char *addr_buf, int addr_buf_size,
                           int *port, int *is_ipv6)
{
    if (!input || !addr_buf || !port)
        return -1;

    /* 检测是否为 IPv6 格式: [addr]:port */
    if (input[0] == '[') {
        /* IPv6: [addr]:port */
        const char *close = strchr(input, ']');
        if (!close) {
            fprintf(stderr, "错误: IPv6 地址缺少右括号 '%s'，格式应为 [ADDR]:PORT\n",
                    input);
            return -1;
        }

        int addr_len = (int)(close - input - 1);
        if (addr_len <= 0 || addr_len >= addr_buf_size) {
            fprintf(stderr, "错误: IPv6 地址无效或过长 '%s'\n", input);
            return -1;
        }

        memcpy(addr_buf, input + 1, addr_len);
        addr_buf[addr_len] = '\0';

        /* 检查紧跟 ]:port */
        if (close[1] != ':') {
            fprintf(stderr, "错误: IPv6 地址格式应为 [ADDR]:PORT，缺少冒号: '%s'\n",
                    input);
            return -1;
        }

        char *endptr = NULL;
        long p = strtol(close + 2, &endptr, 10);
        if (!endptr || *endptr != '\0' || p <= 0 || p > 65535) {
            fprintf(stderr, "错误: 无效的端口号 '%s'\n", close + 2);
            return -1;
        }

        *port = (int)p;
        if (is_ipv6)
            *is_ipv6 = 1;
        return 0;
    }

    /* IPv4: addr:port (使用 strrchr 查找最后一个冒号) */
    const char *colon = strrchr(input, ':');
    if (!colon || colon == input) {
        fprintf(stderr, "错误: 无效的地址格式 '%s'，期望 ADDR:PORT 或 [IPv6]:PORT\n",
                input);
        return -1;
    }

    /* 检查是否有多个冒号但没有方括号（可能是裸 IPv6 地址） */
    if (strchr(input, ':') != colon) {
        fprintf(stderr, "错误: IPv6 地址请使用 [ADDR]:PORT 格式: '%s'\n", input);
        return -1;
    }

    int addr_len = (int)(colon - input);
    if (addr_len >= addr_buf_size) {
        fprintf(stderr, "错误: 地址过长 '%s'\n", input);
        return -1;
    }

    memcpy(addr_buf, input, addr_len);
    addr_buf[addr_len] = '\0';

    char *endptr = NULL;
    long p = strtol(colon + 1, &endptr, 10);
    if (!endptr || *endptr != '\0' || p <= 0 || p > 65535) {
        fprintf(stderr, "错误: 无效的端口号 '%s'\n", colon + 1);
        return -1;
    }

    *port = (int)p;
    if (is_ipv6)
        *is_ipv6 = 0;
    return 0;
}

/* ========== 配置文件解析 ========== */

static int parse_config_file(const char *path, struct app_config *cfg)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "错误: 无法打开配置文件 '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;

        /* 去除首尾空白 */
        char *s = str_trim(line);

        /* 跳过空行和注释 */
        if (*s == '\0' || *s == '#')
            continue;

        /* 查找等号 */
        char *eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "警告: 配置文件第 %d 行格式错误，忽略: %s\n",
                    lineno, s);
            continue;
        }

        /* 分离 key 和 value */
        *eq = '\0';
        char *key = str_trim(s);
        char *value = str_trim(eq + 1);

        if (*key == '\0') {
            fprintf(stderr, "警告: 配置文件第 %d 行 key 为空，忽略\n", lineno);
            continue;
        }

        /* 将配置项应用到 cfg（仅当命令行未设置时） */
        if (strcmp(key, "mode") == 0) {
            if (cfg->mode == VPN_MODE_NONE) {
                if (strcmp(value, "server") == 0)
                    cfg->mode = VPN_MODE_SERVER;
                else if (strcmp(value, "client") == 0)
                    cfg->mode = VPN_MODE_CLIENT;
                else
                    fprintf(stderr, "警告: 配置文件第 %d 行 mode 值无效 '%s'，"
                            "应为 server 或 client\n", lineno, value);
            }
        } else if (strcmp(key, "listen") == 0) {
            if (cfg->listen[0] == '\0')
                snprintf(cfg->listen, sizeof(cfg->listen), "%s", value);
        } else if (strcmp(key, "remote") == 0) {
            if (cfg->remote[0] == '\0')
                snprintf(cfg->remote, sizeof(cfg->remote), "%s", value);
        } else if (strcmp(key, "secret") == 0) {
            if (cfg->secret[0] == '\0')
                snprintf(cfg->secret, sizeof(cfg->secret), "%s", value);
        } else if (strcmp(key, "secret_file") == 0) {
            if (cfg->secret_file[0] == '\0')
                snprintf(cfg->secret_file, sizeof(cfg->secret_file), "%s", value);
        } else if (strcmp(key, "tun_ip") == 0) {
            if (cfg->tun_ip[0] == '\0')
                snprintf(cfg->tun_ip, sizeof(cfg->tun_ip), "%s", value);
        } else if (strcmp(key, "tun_peer") == 0) {
            if (cfg->tun_peer[0] == '\0')
                snprintf(cfg->tun_peer, sizeof(cfg->tun_peer), "%s", value);
        } else if (strcmp(key, "tun_ip6") == 0) {
            if (cfg->tun_ip6[0] == '\0')
                snprintf(cfg->tun_ip6, sizeof(cfg->tun_ip6), "%s", value);
        } else if (strcmp(key, "tun_peer6") == 0) {
            if (cfg->tun_peer6[0] == '\0')
                snprintf(cfg->tun_peer6, sizeof(cfg->tun_peer6), "%s", value);
        } else if (strcmp(key, "tun_ip6_prefix") == 0) {
            if (cfg->tun_ip6_prefix <= 0) {
                int pfx = atoi(value);
                if (pfx > 0 && pfx <= 128)
                    cfg->tun_ip6_prefix = pfx;
                else
                    fprintf(stderr, "警告: 配置文件第 %d 行 tun_ip6_prefix 值无效 '%s'\n",
                            lineno, value);
            }
        } else if (strcmp(key, "ipv6") == 0) {
            if (cfg->ipv6 == 0) {
                if (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0 ||
                    strcmp(value, "1") == 0)
                    cfg->ipv6 = 1;
            }
        } else if (strcmp(key, "threads") == 0) {
            if (cfg->threads <= 0) {
                int t = atoi(value);
                if (t > 0)
                    cfg->threads = t;
                else
                    fprintf(stderr, "警告: 配置文件第 %d 行 threads 值无效 '%s'\n",
                            lineno, value);
            }
        } else if (strcmp(key, "mtu") == 0) {
            if (cfg->mtu <= 0) {
                int m = atoi(value);
                if (m > 0)
                    cfg->mtu = m;
                else
                    fprintf(stderr, "警告: 配置文件第 %d 行 mtu 值无效 '%s'\n",
                            lineno, value);
            }
        } else if (strcmp(key, "log_level") == 0) {
            if (cfg->log_level < 0) {
                int l = atoi(value);
                if (l >= 0)
                    cfg->log_level = l;
                else
                    fprintf(stderr, "警告: 配置文件第 %d 行 log_level 值无效 '%s'\n",
                            lineno, value);
            }
        } else {
            fprintf(stderr, "警告: 配置文件第 %d 行未知配置项 '%s'，忽略\n",
                    lineno, key);
        }
    }

    fclose(fp);
    return 0;
}

/* ========== 长选项定义 ========== */

enum {
    OPT_TUN_IP = 256,
    OPT_TUN_PEER,
    OPT_TUN_IP6,
    OPT_TUN_PEER6,
    OPT_MTU,
    OPT_SECRET_FILE
};

static const struct option long_options[] = {
    {"server",      no_argument,       NULL, 's'},
    {"client",      no_argument,       NULL, 'c'},
    {"config",      required_argument, NULL, 'f'},
    {"listen",      required_argument, NULL, 'l'},
    {"remote",      required_argument, NULL, 'r'},
    {"secret",      required_argument, NULL, 'k'},
    {"secret-file", required_argument, NULL, OPT_SECRET_FILE},
    {"ipv6",        no_argument,       NULL, '6'},
    {"tun-ip",      required_argument, NULL, OPT_TUN_IP},
    {"tun-peer",    required_argument, NULL, OPT_TUN_PEER},
    {"tun-ip6",     required_argument, NULL, OPT_TUN_IP6},
    {"tun-peer6",   required_argument, NULL, OPT_TUN_PEER6},
    {"threads",     required_argument, NULL, 't'},
    {"mtu",         required_argument, NULL, OPT_MTU},
    {"verbose",     no_argument,       NULL, 'v'},
    {"help",        no_argument,       NULL, 'h'},
    {"version",     no_argument,       NULL, 'V'},
    {NULL,          0,                 NULL, 0}
};

/* ========== main ========== */

int main(int argc, char *argv[])
{
    struct app_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = VPN_MODE_NONE;
    cfg.threads = 0;
    cfg.mtu = 0;
    cfg.log_level = -1;  /* -1 表示未通过命令行/配置文件设置 */
    cfg.ipv6 = 0;
    cfg.tun_ip6_prefix = 0;

    int verbose_count = 0;  /* -v 出现次数 */
    int opt;

    /* 第一遍：解析命令行参数 */
    while ((opt = getopt_long(argc, argv, "scf:l:r:k:t:6vhV",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
            cfg.mode = VPN_MODE_SERVER;
            break;
        case 'c':
            cfg.mode = VPN_MODE_CLIENT;
            break;
        case 'f':
            snprintf(cfg.config_file, sizeof(cfg.config_file), "%s", optarg);
            break;
        case 'l':
            snprintf(cfg.listen, sizeof(cfg.listen), "%s", optarg);
            break;
        case 'r':
            snprintf(cfg.remote, sizeof(cfg.remote), "%s", optarg);
            break;
        case 'k':
            snprintf(cfg.secret, sizeof(cfg.secret), "%s", optarg);
            fprintf(stderr, "警告: 通过命令行传递密钥不安全（可被 ps 或 /proc 读取），"
                    "建议使用 --secret-file 或配置文件 (-f) 并设置 chmod 600\n");
            break;
        case OPT_SECRET_FILE:
            snprintf(cfg.secret_file, sizeof(cfg.secret_file), "%s", optarg);
            break;
        case '6':
            cfg.ipv6 = 1;
            break;
        case OPT_TUN_IP:
            snprintf(cfg.tun_ip, sizeof(cfg.tun_ip), "%s", optarg);
            break;
        case OPT_TUN_PEER:
            snprintf(cfg.tun_peer, sizeof(cfg.tun_peer), "%s", optarg);
            break;
        case OPT_TUN_IP6:
            snprintf(cfg.tun_ip6, sizeof(cfg.tun_ip6), "%s", optarg);
            break;
        case OPT_TUN_PEER6:
            snprintf(cfg.tun_peer6, sizeof(cfg.tun_peer6), "%s", optarg);
            break;
        case 't': {
            int t = atoi(optarg);
            if (t <= 0) {
                fprintf(stderr, "错误: 线程数必须为正整数: '%s'\n", optarg);
                return 1;
            }
            cfg.threads = t;
            break;
        }
        case OPT_MTU: {
            int m = atoi(optarg);
            if (m <= 0 || m > 65535) {
                fprintf(stderr, "错误: MTU 值无效: '%s'\n", optarg);
                return 1;
            }
            cfg.mtu = m;
            break;
        }
        case 'v':
            verbose_count++;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            print_version();
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* 处理 verbose：基础级别 1，每个 -v 增加 1 */
    if (verbose_count > 0)
        cfg.log_level = 1 + verbose_count;

    /* 解析配置文件（如果指定） */
    if (cfg.config_file[0] != '\0') {
        if (parse_config_file(cfg.config_file, &cfg) != 0)
            return 1;
    }

    /* 设置日志级别（优先级：命令行 > 配置文件 > 默认值 1） */
    if (cfg.log_level >= 0)
        g_log_level = cfg.log_level;
    else
        g_log_level = 1;  /* 默认 INFO 级别 */

    /* ========== 从密钥文件加载密钥 ========== */

    if (cfg.secret_file[0] != '\0') {
        FILE *sf = fopen(cfg.secret_file, "r");
        if (!sf) {
            fprintf(stderr, "错误: 无法打开密钥文件 '%s': %s\n",
                    cfg.secret_file, strerror(errno));
            return 1;
        }
        char secret_buf[256];
        if (!fgets(secret_buf, sizeof(secret_buf), sf)) {
            fprintf(stderr, "错误: 密钥文件 '%s' 为空\n", cfg.secret_file);
            fclose(sf);
            return 1;
        }
        fclose(sf);
        /* 去除尾部换行符 */
        char *nl = strchr(secret_buf, '\n');
        if (nl) *nl = '\0';
        nl = strchr(secret_buf, '\r');
        if (nl) *nl = '\0';
        if (secret_buf[0] == '\0') {
            fprintf(stderr, "错误: 密钥文件 '%s' 中密钥为空\n", cfg.secret_file);
            return 1;
        }
        /* secret_file 优先级高于 secret */
        snprintf(cfg.secret, sizeof(cfg.secret), "%s", secret_buf);
        /* 安全擦除临时缓冲区（使用 OPENSSL_cleanse 防止编译器优化消除） */
        OPENSSL_cleanse(secret_buf, sizeof(secret_buf));
    }

    /* ========== 参数校验 ========== */

    if (cfg.mode == VPN_MODE_NONE) {
        fprintf(stderr, "错误: 必须指定运行模式 (-s/--server 或 -c/--client)\n");
        fprintf(stderr, "使用 -h 查看帮助信息\n");
        return 1;
    }

    if (cfg.secret[0] == '\0') {
        fprintf(stderr, "错误: 必须指定预共享密钥 (-k/--secret 或 --secret-file)\n");
        return 1;
    }

    if (cfg.tun_ip[0] == '\0') {
        fprintf(stderr, "错误: 必须指定 TUN 本端 IP (--tun-ip)\n");
        return 1;
    }

    if (cfg.tun_peer[0] == '\0') {
        fprintf(stderr, "错误: 必须指定 TUN 对端 IP (--tun-peer)\n");
        return 1;
    }

    /* 初始化协议层 (在创建任何线程之前) */
    if (protocol_init() != 0) {
        fprintf(stderr, "错误: 协议层初始化失败\n");
        return 1;
    }

    /* 统一确定线程数 */
    if (cfg.threads <= 0) {
        cfg.threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (cfg.threads <= 0) cfg.threads = 1;
    }

    /* ========== 构建统一的 vpn_config 并启动 ========== */

    struct vpn_config vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.mode = cfg.mode;
    vcfg.threads = cfg.threads;
    vcfg.mtu = cfg.mtu > 0 ? cfg.mtu : 1400;
    snprintf(vcfg.secret, sizeof(vcfg.secret), "%s", cfg.secret);
    snprintf(vcfg.tun_ip, sizeof(vcfg.tun_ip), "%s", cfg.tun_ip);
    snprintf(vcfg.tun_peer, sizeof(vcfg.tun_peer), "%s", cfg.tun_peer);
    snprintf(vcfg.tun_ip6, sizeof(vcfg.tun_ip6), "%s", cfg.tun_ip6);
    snprintf(vcfg.tun_peer6, sizeof(vcfg.tun_peer6), "%s", cfg.tun_peer6);
    vcfg.tun_ip6_prefix = cfg.tun_ip6_prefix > 0 ? cfg.tun_ip6_prefix : 64;

    if (cfg.mode == VPN_MODE_SERVER) {
        if (cfg.listen[0] == '\0') {
            fprintf(stderr, "错误: 服务端模式必须指定监听地址 (-l/--listen)\n");
            return 1;
        }

        int is_ipv6 = 0;
        if (parse_addr_port(cfg.listen, vcfg.addr, sizeof(vcfg.addr),
                            &vcfg.port, &is_ipv6) != 0) {
            return 1;
        }

        /* 确定地址族：显式 --ipv6 > 地址格式自动检测 */
        if (cfg.ipv6)
            vcfg.af = AF_INET6;
        else if (is_ipv6)
            vcfg.af = AF_INET6;
        else
            vcfg.af = AF_INET;

        const char *af_str = (vcfg.af == AF_INET6) ? "IPv6" : "IPv4";
        log_info("启动服务端模式: 监听 %s:%d (%s), TUN %s <-> %s, "
                 "线程数=%d, MTU=%d",
                 vcfg.addr, vcfg.port, af_str,
                 vcfg.tun_ip, vcfg.tun_peer,
                 vcfg.threads, vcfg.mtu);
        if (vcfg.tun_ip6[0]) {
            log_info("  TUN IPv6: %s (prefix=%d)", vcfg.tun_ip6, vcfg.tun_ip6_prefix);
        }

        return server_run(&vcfg);

    } else {
        if (cfg.remote[0] == '\0') {
            fprintf(stderr, "错误: 客户端模式必须指定远端地址 (-r/--remote)\n");
            return 1;
        }

        int is_ipv6 = 0;
        if (parse_addr_port(cfg.remote, vcfg.addr, sizeof(vcfg.addr),
                            &vcfg.port, &is_ipv6) != 0) {
            return 1;
        }

        /* 确定地址族 */
        if (cfg.ipv6)
            vcfg.af = AF_INET6;
        else if (is_ipv6)
            vcfg.af = AF_INET6;
        else
            vcfg.af = AF_INET;

        const char *af_str = (vcfg.af == AF_INET6) ? "IPv6" : "IPv4";
        log_info("启动客户端模式: 远端 %s:%d (%s), TUN %s <-> %s, "
                 "线程数=%d, MTU=%d",
                 vcfg.addr, vcfg.port, af_str,
                 vcfg.tun_ip, vcfg.tun_peer,
                 vcfg.threads, vcfg.mtu);
        if (vcfg.tun_ip6[0]) {
            log_info("  TUN IPv6: %s (prefix=%d)", vcfg.tun_ip6, vcfg.tun_ip6_prefix);
        }

        return client_run(&vcfg);
    }
}
