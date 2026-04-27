/*
 * MiniVPN - 配置结构体定义
 *
 * 统一的 vpn_config 结构体，供 main.c、server.c、client.c 共同引用
 * 支持 IPv4 和 IPv6 双栈
 */

#ifndef MINIVPN_CONFIG_H
#define MINIVPN_CONFIG_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum vpn_mode {
    VPN_MODE_NONE = 0,
    VPN_MODE_SERVER,
    VPN_MODE_CLIENT
};

struct vpn_config {
    enum vpn_mode mode;            /* 运行模式 */
    char addr[128];                /* 地址: 监听地址(server) 或 远端地址(client) */
    int port;                      /* 端口 */
    int af;                        /* 地址族: AF_INET 或 AF_INET6 */
    char secret[256];              /* 预共享密钥 */
    char tun_ip[64];               /* TUN 设备本端 IP（IPv4 或 IPv6） */
    char tun_peer[64];             /* TUN 设备对端 IP（IPv4 或 IPv6） */
    char tun_ip6[64];              /* TUN 设备本端 IPv6 地址（可选，双栈时使用） */
    char tun_peer6[64];            /* TUN 设备对端 IPv6 地址（可选，双栈时使用） */
    int tun_ip6_prefix;            /* IPv6 前缀长度（默认 64） */
    int threads;                   /* Worker 线程数，0=自动(CPU核数) */
    int mtu;                       /* MTU，默认 1400 */
};

/*
 * 辅助函数：从 sockaddr_storage 获取地址长度
 */
static inline socklen_t sockaddr_len(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    return sizeof(struct sockaddr_in);
}

/*
 * 辅助函数：从 sockaddr_storage 获取端口号（主机字节序）
 */
static inline int sockaddr_port(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET6)
        return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
    return ntohs(((struct sockaddr_in *)ss)->sin_port);
}

/*
 * 辅助函数：将 sockaddr_storage 转换为可读字符串
 * buf 至少需要 INET6_ADDRSTRLEN + 8 字节（含端口和 []）
 */
static inline const char *sockaddr_to_str(const struct sockaddr_storage *ss,
                                           char *buf, int buf_size)
{
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buf_size, "[%s]:%d", ip, ntohs(s6->sin6_port));
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(buf, buf_size, "%s:%d", ip, ntohs(s4->sin_port));
    }
    return buf;
}

#endif /* MINIVPN_CONFIG_H */
