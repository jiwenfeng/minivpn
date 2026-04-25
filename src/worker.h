/*
 * MiniVPN - Worker 线程结构
 *
 * 每个 Worker 拥有独立的 UDP socket + epoll 事件循环 + 线程
 * 多个 Worker 通过 SO_REUSEPORT 共享同一监听端口
 *
 * 改进:
 * - 共享认证状态（所有Worker可见）
 * - 共享抗重放窗口（避免多Worker独立窗口导致的重放漏洞）
 * - 每个Worker拥有独立的 crypto_ctx (避免锁竞争)
 * - 所有Worker都监听TUN设备（使用EPOLLEXCLUSIVE减少惊群）
 * - 支持 IPv4/IPv6 双栈（sockaddr_storage）
 */

#ifndef MINIVPN_WORKER_H
#define MINIVPN_WORKER_H

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "protocol.h"

/*
 * 共享认证状态 (所有 Worker 共享)
 * 通过原子操作访问 authenticated 标志
 * peer_addr 通过 seqlock 保护（无锁）
 * 支持 IPv4 和 IPv6（使用 sockaddr_storage）
 */
struct shared_peer_state {
    int authenticated;                /* 0=未认证, 1=已认证 (__atomic 访问) */
    uint64_t reconnect_gen;           /* 重连代数 (__atomic 访问) */
    volatile long last_active_time;   /* 上次收到有效帧的时间戳 (__atomic 访问，所有 Worker 共享） */
    unsigned int addr_seq;            /* seqlock 序列号 (__atomic 访问，奇数=写入中) */
    struct sockaddr_storage peer_addr;/* 对端地址（IPv4 或 IPv6） */
    struct replay_window replay;      /* 无锁抗重放窗口 (atomic CAS) */
};

struct worker {
    int id;                        /* Worker 编号 */
    int udp_fd;                    /* UDP socket */
    int tun_fd;                    /* TUN 设备 fd（所有 Worker 共享） */
    int epoll_fd;                  /* epoll 实例 */
    int af;                        /* 地址族: AF_INET 或 AF_INET6 */
    pthread_t thread;              /* 工作线程 */

    struct crypto_ctx *crypto;     /* 加密上下文 (每个Worker独立) */

    struct shared_peer_state *shared_peer;  /* 共享认证状态+抗重放窗口 */

    int running;                   /* 运行标志（通过 __atomic 操作访问） */
    void *user_data;               /* 用户自定义数据（供线程函数使用） */
};

/*
 * 初始化共享认证状态
 *
 * @param state  共享状态结构
 * @return       0成功, -1失败
 */
int shared_peer_init(struct shared_peer_state *state);

/*
 * 销毁共享认证状态
 */
void shared_peer_destroy(struct shared_peer_state *state);

/*
 * 更新共享peer地址 (线程安全，支持 IPv4/IPv6)
 */
void shared_peer_update_addr(struct shared_peer_state *state,
                             const struct sockaddr_storage *addr);

/*
 * 获取共享peer地址 (线程安全，支持 IPv4/IPv6)
 */
void shared_peer_get_addr(struct shared_peer_state *state,
                          struct sockaddr_storage *addr);

/*
 * 检查共享抗重放窗口 (线程安全)
 *
 * @param state  共享状态
 * @param nonce  12字节 nonce
 * @return       0=新帧(已记录), -1=重放(丢弃)
 */
int shared_peer_replay_check(struct shared_peer_state *state,
                             const uint8_t *nonce);

/*
 * 重置共享抗重放窗口 (线程安全)
 */
void shared_peer_replay_reset(struct shared_peer_state *state);

/*
 * 初始化 Worker（创建 UDP socket + epoll，将 udp_fd 和 tun_fd 加入 epoll）
 * 所有 Worker 都监听 TUN 设备
 *
 * @param w              Worker 结构
 * @param id             Worker 编号
 * @param tun_fd         TUN 设备 fd
 * @param af             地址族: AF_INET 或 AF_INET6
 * @param encrypt_key    加密密钥 (32字节)
 * @param auth_key       认证密钥 (32字节)
 * @param shared_peer    共享认证状态 (所有Worker共享同一个)
 * @return               0成功, -1失败
 */
int worker_init(struct worker *w, int id, int tun_fd, int af,
                const uint8_t *encrypt_key, const uint8_t *auth_key,
                struct shared_peer_state *shared_peer);

/*
 * 启动 Worker 线程
 *
 * @param w            Worker 结构
 * @param thread_func  线程函数
 * @return             0成功, -1失败
 */
int worker_start(struct worker *w, void *(*thread_func)(void *));

/*
 * 停止 Worker（设置 running=0，等待线程退出）
 *
 * @param w  Worker 结构
 */
void worker_stop(struct worker *w);

/*
 * 清理 Worker 资源（关闭 fd，释放 crypto_ctx）
 *
 * @param w  Worker 结构
 */
void worker_cleanup(struct worker *w);

#endif /* MINIVPN_WORKER_H */
