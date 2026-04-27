/*
 * MiniVPN - Linux TUN 设备实现
 *
 * 使用 /dev/net/tun + ioctl 创建和配置 TUN 设备
 * 支持 IPv4 和 IPv6 地址配置
 */

#include "tun.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int tun_create(char *dev_name, int dev_name_size)
{
    if (!dev_name || dev_name_size < IFNAMSIZ) {
        log_error("tun_create: 参数无效");
        return -1;
    }

    /* 打开 TUN 克隆设备 */
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        log_error("tun_create: 无法打开 /dev/net/tun (需要 root 权限?)");
        return -1;
    }

    /* 配置 TUN 设备 */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* TUN 模式，无包信息头 */

    /* 如果 dev_name 已有内容，使用指定的设备名 */
    if (dev_name[0] != '\0') {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        log_error("tun_create: ioctl TUNSETIFF 失败");
        close(fd);
        return -1;
    }

    /* 复制内核分配的设备名 */
    strncpy(dev_name, ifr.ifr_name, dev_name_size - 1);
    dev_name[dev_name_size - 1] = '\0';

    /* 设为非阻塞模式 */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error("tun_create: 设置非阻塞模式失败");
        close(fd);
        return -1;
    }

    log_info("TUN 设备 %s 已创建, fd=%d", dev_name, fd);
    return fd;
}

int tun_configure(const char *dev_name, const char *local_ip, const char *peer_ip)
{
    if (!dev_name || !local_ip || !peer_ip) {
        log_error("tun_configure: 参数为空");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("tun_configure: 创建 socket 失败");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    /* 设置本端 IP 地址 */
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, local_ip, &addr->sin_addr) != 1) {
        log_error("tun_configure: 无效的本端 IP: %s", local_ip);
        close(sock);
        return -1;
    }
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        log_error("tun_configure: 设置本端 IP 失败");
        close(sock);
        return -1;
    }

    /* 设置对端 IP 地址 (点对点链路) */
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, peer_ip, &addr->sin_addr) != 1) {
        log_error("tun_configure: 无效的对端 IP: %s", peer_ip);
        close(sock);
        return -1;
    }
    if (ioctl(sock, SIOCSIFDSTADDR, &ifr) < 0) {
        log_error("tun_configure: 设置对端 IP 失败");
        close(sock);
        return -1;
    }

    /* 启用设备 (UP) */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("tun_configure: 获取接口标志失败");
        close(sock);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("tun_configure: 启用接口失败");
        close(sock);
        return -1;
    }

    close(sock);
    log_info("TUN 设备 %s IPv4 配置完成: %s -> %s", dev_name, local_ip, peer_ip);
    return 0;
}

/*
 * 验证 IPv6 地址格式是否安全（仅允许 hex 数字、冒号和点）
 * 防止 system() 命令注入
 */
static int validate_ipv6_addr(const char *addr)
{
    for (const char *p = addr; *p; p++) {
        char c = *p;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F') ||
            c == ':' || c == '.') {
            continue;
        }
        return -1;  /* 包含非法字符 */
    }
    return 0;
}

/*
 * 验证网卡名称是否安全（仅允许字母、数字和下划线）
 */
static int validate_dev_name(const char *name)
{
    for (const char *p = name; *p; p++) {
        char c = *p;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            c == '_' || c == '-') {
            continue;
        }
        return -1;
    }
    return 0;
}

int tun_configure_ipv6(const char *dev_name, const char *local_ip6,
                       int prefix_len)
{
    if (!dev_name || !local_ip6) {
        log_error("tun_configure_ipv6: 参数为空");
        return -1;
    }
    if (prefix_len <= 0 || prefix_len > 128) {
        log_error("tun_configure_ipv6: 前缀长度无效: %d", prefix_len);
        return -1;
    }

    /* 输入验证：防止命令注入 */
    if (validate_ipv6_addr(local_ip6) != 0) {
        log_error("tun_configure_ipv6: IPv6 地址包含非法字符: %s", local_ip6);
        return -1;
    }
    if (validate_dev_name(dev_name) != 0) {
        log_error("tun_configure_ipv6: 设备名包含非法字符: %s", dev_name);
        return -1;
    }

    /*
     * 使用 fork/execvp 配置 IPv6 地址（比 system() 更安全，无需 shell）
     * ioctl 对 IPv6 支持有限，netlink 或 ip 命令更合适
     */
    char prefix_str[8];
    snprintf(prefix_str, sizeof(prefix_str), "%d", prefix_len);

    char addr_prefix[80];
    snprintf(addr_prefix, sizeof(addr_prefix), "%s/%s", local_ip6, prefix_str);

    pid_t pid = fork();
    if (pid < 0) {
        log_error("tun_configure_ipv6: fork 失败: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* 子进程：执行 ip -6 addr add <addr>/<prefix> dev <dev> */
        execlp("ip", "ip", "-6", "addr", "add", addr_prefix, "dev", dev_name, NULL);
        _exit(127);  /* exec 失败 */
    }

    int status = 0;
    waitpid(pid, &status, 0);

    if (status != 0) {
        /* 错误码 2 通常表示地址已存在 (RTNETLINK answers: File exists)，可忽略 */
        if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
            log_info("tun_configure_ipv6: IPv6 地址已存在，跳过: %s/%d",
                     local_ip6, prefix_len);
        } else {
            log_error("tun_configure_ipv6: 配置 IPv6 地址失败 (exit=%d): %s/%d",
                      WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                      local_ip6, prefix_len);
            return -1;
        }
    }

    log_info("TUN 设备 %s IPv6 配置完成: %s/%d", dev_name, local_ip6, prefix_len);
    return 0;
}

int tun_set_mtu(const char *dev_name, int mtu)
{
    if (!dev_name || mtu <= 0 || mtu > 65535) {
        log_error("tun_set_mtu: 参数无效 (mtu=%d)", mtu);
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("tun_set_mtu: 创建 socket 失败");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        log_error("tun_set_mtu: 设置 MTU 失败");
        close(sock);
        return -1;
    }

    close(sock);
    log_info("TUN 设备 %s MTU 设置为 %d", dev_name, mtu);
    return 0;
}
