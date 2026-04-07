/*
 * MiniVPN - Worker 线程实现
 *
 * 创建 UDP socket (SO_REUSEPORT) + epoll 事件循环
 */

#include "worker.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/crypto.h>

/* UDP socket 缓冲区大小: 4MB */
#define UDP_BUF_SIZE (4 * 1024 * 1024)

int worker_init(struct worker *w, int id, int tun_fd,
                const uint8_t *encrypt_key, const uint8_t *auth_key)
{
    if (!w || !encrypt_key || !auth_key) {
        log_error("worker_init: 参数为空");
        return -1;
    }

    memset(w, 0, sizeof(*w));
    w->id = id;
    w->tun_fd = tun_fd;
    w->udp_fd = -1;
    w->epoll_fd = -1;
    w->peer_authenticated = 0;
    __atomic_store_n(&w->running, 0, __ATOMIC_SEQ_CST);
    w->user_data = NULL;

    memcpy(w->encrypt_key, encrypt_key, 32);
    memcpy(w->auth_key, auth_key, 32);

    /* 创建 UDP socket */
    w->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (w->udp_fd < 0) {
        log_error("worker[%d]: 创建 UDP socket 失败", id);
        return -1;
    }

    /* 设置 SO_REUSEPORT */
    int opt = 1;
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        log_error("worker[%d]: 设置 SO_REUSEPORT 失败", id);
        goto fail;
    }

    /* 设置 SO_REUSEADDR */
    opt = 1;
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("worker[%d]: 设置 SO_REUSEADDR 失败", id);
        goto fail;
    }

    /* 设置收发缓冲区为 4MB */
    int buf_size = UDP_BUF_SIZE;
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        log_error("worker[%d]: 设置 SO_RCVBUF 失败", id);
        /* 非致命错误，继续 */
    }
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        log_error("worker[%d]: 设置 SO_SNDBUF 失败", id);
        /* 非致命错误，继续 */
    }

    /* 创建 epoll 实例 */
    w->epoll_fd = epoll_create1(0);
    if (w->epoll_fd < 0) {
        log_error("worker[%d]: 创建 epoll 失败", id);
        goto fail;
    }

    /* 将 udp_fd 加入 epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = w->udp_fd;
    if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->udp_fd, &ev) < 0) {
        log_error("worker[%d]: epoll 添加 udp_fd 失败", id);
        goto fail;
    }

    /* 将 tun_fd 加入 epoll */
    ev.events = EPOLLIN;
    ev.data.fd = w->tun_fd;
    if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->tun_fd, &ev) < 0) {
        log_error("worker[%d]: epoll 添加 tun_fd 失败", id);
        goto fail;
    }

    log_info("worker[%d]: 初始化完成, udp_fd=%d, epoll_fd=%d",
             id, w->udp_fd, w->epoll_fd);
    return 0;

fail:
    if (w->epoll_fd >= 0) {
        close(w->epoll_fd);
        w->epoll_fd = -1;
    }
    if (w->udp_fd >= 0) {
        close(w->udp_fd);
        w->udp_fd = -1;
    }
    return -1;
}

int worker_start(struct worker *w, void *(*thread_func)(void *))
{
    if (!w || !thread_func) {
        log_error("worker_start: 参数为空");
        return -1;
    }

    __atomic_store_n(&w->running, 1, __ATOMIC_SEQ_CST);

    int ret = pthread_create(&w->thread, NULL, thread_func, w);
    if (ret != 0) {
        log_error("worker[%d]: 创建线程失败, errno=%d", w->id, ret);
        __atomic_store_n(&w->running, 0, __ATOMIC_SEQ_CST);
        return -1;
    }

    log_info("worker[%d]: 线程已启动", w->id);
    return 0;
}

void worker_stop(struct worker *w)
{
    if (!w) return;

    if (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST)) {
        __atomic_store_n(&w->running, 0, __ATOMIC_SEQ_CST);
        log_info("worker[%d]: 正在停止...", w->id);
        pthread_join(w->thread, NULL);
        log_info("worker[%d]: 线程已退出", w->id);
    }
}

void worker_cleanup(struct worker *w)
{
    if (!w) return;

    if (w->epoll_fd >= 0) {
        close(w->epoll_fd);
        w->epoll_fd = -1;
    }
    if (w->udp_fd >= 0) {
        close(w->udp_fd);
        w->udp_fd = -1;
    }
    /* 注意: tun_fd 是共享的，不在这里关闭 */

    /* 清除密钥材料 */
    OPENSSL_cleanse(w->encrypt_key, sizeof(w->encrypt_key));
    OPENSSL_cleanse(w->auth_key, sizeof(w->auth_key));

    log_info("worker[%d]: 资源已清理", w->id);
}
