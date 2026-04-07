/*
 * MiniVPN - Worker 线程结构
 *
 * 每个 Worker 拥有独立的 UDP socket + epoll 事件循环 + 线程
 * 多个 Worker 通过 SO_REUSEPORT 共享同一监听端口
 */

#ifndef MINIVPN_WORKER_H
#define MINIVPN_WORKER_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>

struct worker {
    int id;                        /* Worker 编号 */
    int udp_fd;                    /* UDP socket */
    int tun_fd;                    /* TUN 设备 fd（所有 Worker 共享） */
    int epoll_fd;                  /* epoll 实例 */
    pthread_t thread;              /* 工作线程 */

    uint8_t encrypt_key[32];       /* AES-GCM 加密密钥 */
    uint8_t auth_key[32];          /* 认证密钥 */

    struct sockaddr_in peer_addr;  /* 对端地址 */
    int peer_authenticated;        /* 是否已认证 */

    int running;                   /* 运行标志（通过 __atomic 操作访问） */
    void *user_data;               /* 用户自定义数据（供线程函数使用） */
};

/*
 * 初始化 Worker（创建 UDP socket + epoll，将 udp_fd 和 tun_fd 加入 epoll）
 *
 * @param w            Worker 结构
 * @param id           Worker 编号
 * @param tun_fd       TUN 设备 fd
 * @param encrypt_key  加密密钥 (32字节)
 * @param auth_key     认证密钥 (32字节)
 * @return             0成功, -1失败
 */
int worker_init(struct worker *w, int id, int tun_fd,
                const uint8_t *encrypt_key, const uint8_t *auth_key);

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
 * 清理 Worker 资源（关闭 fd）
 *
 * @param w  Worker 结构
 */
void worker_cleanup(struct worker *w);

#endif /* MINIVPN_WORKER_H */
