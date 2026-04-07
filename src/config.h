/*
 * MiniVPN - 配置结构体定义
 *
 * server_config 和 client_config 的共享定义
 * 供 main.c、server.c、client.c 共同引用，避免重复定义导致 ABI 不一致
 */

#ifndef MINIVPN_CONFIG_H
#define MINIVPN_CONFIG_H

struct server_config {
    char listen_addr[64];      /* 监听地址 如 "0.0.0.0" */
    int listen_port;           /* 监听端口 */
    char secret[256];          /* 预共享密钥 */
    char tun_ip[32];           /* TUN 设备本端 IP */
    char tun_peer[32];         /* TUN 设备对端 IP */
    int threads;               /* Worker 线程数 */
    int mtu;                   /* MTU，默认 1400 */
};

struct client_config {
    char remote_addr[64];      /* 远端地址 */
    int remote_port;           /* 远端端口 */
    char secret[256];          /* 预共享密钥 */
    char tun_ip[32];           /* TUN 设备本端 IP */
    char tun_peer[32];         /* TUN 设备对端 IP */
    int threads;               /* Worker 线程数 */
    int mtu;                   /* MTU，默认 1400 */
};

#endif /* MINIVPN_CONFIG_H */
