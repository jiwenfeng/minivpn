/*
 * MiniVPN - Worker 线程实现
 *
 * 创建 UDP socket (SO_REUSEPORT) + epoll 事件循环
 *
 * 改进:
 * - 所有 Worker 都监听 TUN 设备（使用 EPOLLEXCLUSIVE 减少惊群）
 * - 共享认证状态 + 共享抗重放窗口（mutex 保护）
 * - 独立的 crypto_ctx（每个 Worker 无锁加解密）
 * - 支持 IPv4/IPv6 双栈（sockaddr_storage）
 */

#include "worker.h"
#include "config.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/crypto.h>

/* UDP socket 缓冲区大小: 4MB */
#define UDP_BUF_SIZE (4 * 1024 * 1024)

/* ========== 共享认证状态 ========== */

int shared_peer_init(struct shared_peer_state *state)
{
    if (!state) return -1;
    state->authenticated = 0;
    state->reconnect_gen = 0;
    state->last_pong_time = (long)time(NULL);
    memset(&state->peer_addr, 0, sizeof(state->peer_addr));
    if (pthread_mutex_init(&state->addr_mutex, NULL) != 0) {
        return -1;
    }
    replay_window_init(&state->replay);
    if (pthread_mutex_init(&state->replay_mutex, NULL) != 0) {
        pthread_mutex_destroy(&state->addr_mutex);
        return -1;
    }
    return 0;
}

void shared_peer_destroy(struct shared_peer_state *state)
{
    if (!state) return;
    pthread_mutex_destroy(&state->addr_mutex);
    pthread_mutex_destroy(&state->replay_mutex);
}

void shared_peer_update_addr(struct shared_peer_state *state,
                             const struct sockaddr_storage *addr)
{
    if (!state || !addr) return;
    pthread_mutex_lock(&state->addr_mutex);
    memcpy(&state->peer_addr, addr, sizeof(state->peer_addr));
    pthread_mutex_unlock(&state->addr_mutex);
}

void shared_peer_get_addr(struct shared_peer_state *state,
                          struct sockaddr_storage *addr)
{
    if (!state || !addr) return;
    pthread_mutex_lock(&state->addr_mutex);
    memcpy(addr, &state->peer_addr, sizeof(*addr));
    pthread_mutex_unlock(&state->addr_mutex);
}

int shared_peer_replay_check(struct shared_peer_state *state,
                             const uint8_t *nonce)
{
    if (!state || !nonce) return -1;
    pthread_mutex_lock(&state->replay_mutex);
    int ret = replay_window_check(&state->replay, nonce);
    pthread_mutex_unlock(&state->replay_mutex);
    return ret;
}

void shared_peer_replay_reset(struct shared_peer_state *state)
{
    if (!state) return;
    pthread_mutex_lock(&state->replay_mutex);
    replay_window_init(&state->replay);
    pthread_mutex_unlock(&state->replay_mutex);
}

/* ========== Worker 实现 ========== */

int worker_init(struct worker *w, int id, int tun_fd, int af,
                const uint8_t *encrypt_key, const uint8_t *auth_key,
                struct shared_peer_state *shared_peer)
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
    w->af = af;
    w->shared_peer = shared_peer;
    __atomic_store_n(&w->running, 0, __ATOMIC_SEQ_CST);
    w->user_data = NULL;

    /* 创建独立的加密上下文 */
    w->crypto = crypto_ctx_new(encrypt_key, auth_key);
    if (!w->crypto) {
        log_error("worker[%d]: 创建加密上下文失败", id);
        return -1;
    }

    /* 抗重放窗口已移至 shared_peer_state 中共享 */

    /* 创建 UDP socket（支持 IPv4 和 IPv6） */
    w->udp_fd = socket(af, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (w->udp_fd < 0) {
        log_error("worker[%d]: 创建 UDP socket 失败 (af=%d)", id, af);
        goto fail;
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

    /* IPv6 socket: 设置 IPV6_V6ONLY=0 允许双栈，或 =1 仅 IPv6 */
    if (af == AF_INET6) {
        int v6only = 0;  /* 双栈：允许 IPv6 socket 也接受 IPv4 连接 */
        setsockopt(w->udp_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   &v6only, sizeof(v6only));
    }

    /* 设置收发缓冲区为 4MB */
    int buf_size = UDP_BUF_SIZE;
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        log_error("worker[%d]: 设置 SO_RCVBUF 失败 (非致命)", id);
    }
    if (setsockopt(w->udp_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        log_error("worker[%d]: 设置 SO_SNDBUF 失败 (非致命)", id);
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

    /*
     * 所有 Worker 都监听 TUN 设备
     * 使用 EPOLLEXCLUSIVE (Linux 4.5+) 让内核只唤醒一个 Worker，
     * 避免 level-triggered 模式下所有 Worker 被惊群唤醒
     */
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.fd = w->tun_fd;
    if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->tun_fd, &ev) < 0) {
        log_error("worker[%d]: epoll 添加 tun_fd 失败", id);
        goto fail;
    }

    log_info("worker[%d]: 初始化完成, af=%s, udp_fd=%d, epoll_fd=%d",
             id, af == AF_INET6 ? "IPv6" : "IPv4", w->udp_fd, w->epoll_fd);
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
    if (w->crypto) {
        crypto_ctx_free(w->crypto);
        w->crypto = NULL;
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

    /* 释放加密上下文 */
    if (w->crypto) {
        crypto_ctx_free(w->crypto);
        w->crypto = NULL;
    }

    log_info("worker[%d]: 资源已清理", w->id);
}
