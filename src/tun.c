/*
 * MiniVPN - Linux TUN 设备实现
 *
 * 使用 /dev/net/tun + ioctl 创建和配置 TUN 设备
 */

#include "tun.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

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
    log_info("TUN 设备 %s 配置完成: %s -> %s", dev_name, local_ip, peer_ip);
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
