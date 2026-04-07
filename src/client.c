/*
 * MiniVPN - 客户端模式
 *
 * 运行在近端服务器上：
 * 1. 创建 TUN 设备
 * 2. 启动 N 个 Worker 线程（SO_REUSEPORT 连接到远端）
 * 3. 发送 AUTH 帧，等待 OK 响应
 * 4. epoll 事件循环：
 *    - TUN 可读：读 IP 包 → 加密 → UDP 发送
 *    - UDP 可读：接收 → 解密 → 写入 TUN
 * 5. 心跳：每 30 秒 PING，90 秒超时断线重连
 */

#include "worker.h"
#include "protocol.h"
#include "tun.h"
#include "log.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

/* ========== 全局信号标志 ========== */

static volatile sig_atomic_t g_client_running = 1;

static void client_signal_handler(int sig)
{
    (void)sig;
    g_client_running = 0;
}

/* ========== 常量 ========== */

#define MAX_EVENTS       64
#define PING_INTERVAL    30   /* 心跳间隔 (秒) */
#define PONG_TIMEOUT     90   /* PONG 超时 (秒) */
#define AUTH_TIMEOUT     10   /* AUTH 等待 OK 超时 (秒) */
#define AUTH_RETRY_MAX   5    /* AUTH 最大重试次数 */
#define RECONNECT_DELAY  3    /* 重连延迟 (秒) */

/* ========== 客户端 Worker 扩展上下文 ========== */

struct client_worker_ctx {
    struct worker *w;
    struct sockaddr_in remote_addr;  /* 远端地址 */
    time_t last_ping_time;           /* 上次发送 PING 的时间 */
    time_t last_pong_time;           /* 上次收到 PONG 的时间 */
};

/* ========== 断线重连：重建 UDP socket ========== */

static int client_reconnect_socket(struct worker *w,
                                   const struct sockaddr_in *remote_addr)
{
    /* 从 epoll 移除旧的 udp_fd */
    if (w->udp_fd >= 0) {
        epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, w->udp_fd, NULL);
        close(w->udp_fd);
        w->udp_fd = -1;
    }

    /* 创建新的 UDP socket */
    w->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (w->udp_fd < 0) {
        log_error("client worker[%d]: 重建 UDP socket 失败: %s",
                  w->id, strerror(errno));
        return -1;
    }

    /* 设置 SO_REUSEPORT */
    int opt = 1;
    setsockopt(w->udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* 设置缓冲区 */
    int buf_size = 4 * 1024 * 1024;
    setsockopt(w->udp_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(w->udp_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    /* 连接到远端 (UDP connect 绑定默认目标) */
    if (connect(w->udp_fd, (struct sockaddr *)remote_addr,
                sizeof(*remote_addr)) < 0) {
        log_error("client worker[%d]: UDP connect 失败: %s",
                  w->id, strerror(errno));
        close(w->udp_fd);
        w->udp_fd = -1;
        return -1;
    }

    /* 将新 udp_fd 加入 epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = w->udp_fd;
    if (epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->udp_fd, &ev) < 0) {
        log_error("client worker[%d]: epoll 添加新 udp_fd 失败: %s",
                  w->id, strerror(errno));
        close(w->udp_fd);
        w->udp_fd = -1;
        return -1;
    }

    w->peer_authenticated = 0;
    log_info("client worker[%d]: UDP socket 重建完成, fd=%d", w->id, w->udp_fd);
    return 0;
}

/* ========== 发送 AUTH 并等待 OK ========== */

static int client_authenticate(struct worker *w)
{
    uint8_t auth_payload[AUTH_NONCE_SIZE + HMAC_SIZE];
    int auth_payload_len = 0;
    uint8_t frame_buf[MAX_FRAME_SIZE];
    uint8_t recv_buf[MAX_FRAME_SIZE];

    /* 生成 AUTH 帧内容 */
    if (protocol_make_auth(w->auth_key, auth_payload, &auth_payload_len) != 0) {
        log_error("client worker[%d]: 生成 AUTH 帧失败", w->id);
        return -1;
    }

    for (int retry = 0; retry < AUTH_RETRY_MAX; retry++) {
        if (!__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) || !g_client_running) return -1;

        /* 加密 AUTH 帧 */
        int enc_len = protocol_encrypt(w->encrypt_key, FRAME_AUTH,
                                       auth_payload, auth_payload_len,
                                       frame_buf, sizeof(frame_buf));
        if (enc_len <= 0) {
            log_error("client worker[%d]: 加密 AUTH 帧失败", w->id);
            return -1;
        }

        /* 发送 AUTH (由于 UDP 已 connect，使用 send) */
        ssize_t sn = send(w->udp_fd, frame_buf, enc_len, 0);
        if (sn < 0) {
            log_error("client worker[%d]: 发送 AUTH 失败: %s",
                      w->id, strerror(errno));
            return -1;
        }

        log_info("client worker[%d]: 已发送 AUTH 帧 (尝试 %d/%d)",
                 w->id, retry + 1, AUTH_RETRY_MAX);

        /* 等待 OK 帧 */
        struct epoll_event events[4];
        time_t deadline = time(NULL) + AUTH_TIMEOUT;

        while (time(NULL) < deadline && __atomic_load_n(&w->running, __ATOMIC_SEQ_CST) && g_client_running) {
            int timeout_ms = (int)(deadline - time(NULL)) * 1000;
            if (timeout_ms <= 0) break;

            int nfds = epoll_wait(w->epoll_fd, events, 4, timeout_ms);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                return -1;
            }

            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd != w->udp_fd) continue;
                if (!(events[i].events & EPOLLIN)) continue;

                ssize_t n = recv(w->udp_fd, recv_buf, sizeof(recv_buf), 0);
                if (n <= 0) continue;

                uint8_t frame_type;
                uint8_t payload[MAX_PAYLOAD];
                int payload_len = 0;

                if (protocol_decrypt(w->encrypt_key, recv_buf, (int)n,
                                     &frame_type, payload, &payload_len) != 0) {
                    continue;
                }

                if (frame_type == FRAME_OK) {
                    w->peer_authenticated = 1;
                    log_info("client worker[%d]: 认证成功，收到 OK 帧",
                             w->id);
                    return 0;
                }
            }
        }

        log_info("client worker[%d]: 等待 OK 超时，重试...", w->id);
    }

    log_error("client worker[%d]: AUTH 认证失败，超过最大重试次数", w->id);
    return -1;
}

/* ========== 客户端 Worker 线程函数 ========== */

static void *client_worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    struct client_worker_ctx *ctx = (struct client_worker_ctx *)w->user_data;
    struct sockaddr_in remote_addr = ctx->remote_addr;
    struct epoll_event events[MAX_EVENTS];

    /* 预分配缓冲区 */
    uint8_t udp_recv_buf[MAX_FRAME_SIZE];
    uint8_t udp_send_buf[MAX_FRAME_SIZE];
    uint8_t tun_buf[MAX_PAYLOAD];
    uint8_t decrypt_payload[MAX_PAYLOAD];

    log_info("client worker[%d]: 线程开始运行", w->id);

    /* 首次认证 */
    if (client_authenticate(w) != 0) {
        log_error("client worker[%d]: 首次认证失败", w->id);
        /* 不退出线程，进入重连循环 */
    }

    ctx->last_ping_time = time(NULL);
    ctx->last_pong_time = time(NULL);

    while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) && g_client_running) {
        /* 检查是否需要重连 */
        if (!w->peer_authenticated) {
            log_info("client worker[%d]: 开始重连...", w->id);
            sleep(RECONNECT_DELAY);

            if (!__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) || !g_client_running) break;

            if (client_reconnect_socket(w, &remote_addr) != 0) {
                log_error("client worker[%d]: 重建 socket 失败", w->id);
                continue;
            }

            if (client_authenticate(w) != 0) {
                log_error("client worker[%d]: 重连认证失败", w->id);
                continue;
            }

            ctx->last_ping_time = time(NULL);
            ctx->last_pong_time = time(NULL);
            log_info("client worker[%d]: 重连成功", w->id);
        }

        /* 心跳检查 */
        time_t now = time(NULL);

        /* 发送 PING */
        if (now - ctx->last_ping_time >= PING_INTERVAL) {
            int ping_len = protocol_encrypt(w->encrypt_key, FRAME_PING,
                                            NULL, 0,
                                            udp_send_buf,
                                            sizeof(udp_send_buf));
            if (ping_len > 0) {
                send(w->udp_fd, udp_send_buf, ping_len, 0);
                log_debug("client worker[%d]: 发送 PING", w->id);
            }
            ctx->last_ping_time = now;
        }

        /* PONG 超时检测 */
        if (now - ctx->last_pong_time > PONG_TIMEOUT) {
            log_error("client worker[%d]: PONG 超时 (%d 秒)，触发重连",
                      w->id, PONG_TIMEOUT);
            w->peer_authenticated = 0;
            continue;
        }

        /* epoll 事件循环 */
        int nfds = epoll_wait(w->epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error("client worker[%d]: epoll_wait 失败: %s",
                      w->id, strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == w->tun_fd && (events[i].events & EPOLLIN)) {
                /* ---- TUN 可读：读取 IP 包 → 加密 → UDP 发送 ---- */
                ssize_t n = read(w->tun_fd, tun_buf, sizeof(tun_buf));
                if (n <= 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        log_error("client worker[%d]: 读 TUN 失败: %s",
                                  w->id, strerror(errno));
                    }
                    continue;
                }

                if (!w->peer_authenticated) continue;

                int enc_len = protocol_encrypt(w->encrypt_key, FRAME_DATA,
                                               tun_buf, (int)n,
                                               udp_send_buf,
                                               sizeof(udp_send_buf));
                if (enc_len <= 0) {
                    log_error("client worker[%d]: 加密失败", w->id);
                    continue;
                }

                ssize_t sn = send(w->udp_fd, udp_send_buf, enc_len, 0);
                if (sn < 0 && errno != EAGAIN) {
                    log_error("client worker[%d]: send 失败: %s",
                              w->id, strerror(errno));
                }

            } else if (fd == w->udp_fd && (events[i].events & EPOLLIN)) {
                /* ---- UDP 可读：接收 → 解密 → 写入 TUN ---- */
                ssize_t n = recv(w->udp_fd, udp_recv_buf,
                                 sizeof(udp_recv_buf), 0);
                if (n <= 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        log_error("client worker[%d]: recv 失败: %s",
                                  w->id, strerror(errno));
                    }
                    continue;
                }

                uint8_t frame_type;
                int payload_len = 0;

                if (protocol_decrypt(w->encrypt_key, udp_recv_buf, (int)n,
                                     &frame_type, decrypt_payload,
                                     &payload_len) != 0) {
                    log_debug("client worker[%d]: 解密失败，丢弃帧", w->id);
                    continue;
                }

                switch (frame_type) {
                case FRAME_DATA:
                    if (payload_len > 0) {
                        ssize_t wn = write(w->tun_fd, decrypt_payload,
                                           payload_len);
                        if (wn < 0 && errno != EAGAIN) {
                            log_error("client worker[%d]: 写 TUN 失败: %s",
                                      w->id, strerror(errno));
                        }
                    }
                    break;

                case FRAME_PONG:
                    ctx->last_pong_time = time(NULL);
                    log_debug("client worker[%d]: 收到 PONG", w->id);
                    break;

                case FRAME_OK:
                    /* 延迟到的 OK 帧，忽略 */
                    log_debug("client worker[%d]: 收到延迟 OK 帧", w->id);
                    break;

                case FRAME_PING:
                    /* 服务端发来的 PING，回复 PONG */
                    {
                        int pong_len = protocol_encrypt(w->encrypt_key,
                                                        FRAME_PONG,
                                                        NULL, 0,
                                                        udp_send_buf,
                                                        sizeof(udp_send_buf));
                        if (pong_len > 0) {
                            send(w->udp_fd, udp_send_buf, pong_len, 0);
                        }
                    }
                    break;

                default:
                    log_debug("client worker[%d]: 未知帧类型 0x%02x",
                              w->id, frame_type);
                    break;
                }
            }
        }
    }

    log_info("client worker[%d]: 线程退出", w->id);
    return NULL;
}

/* ========== 客户端入口 ========== */

int client_run(const struct client_config *cfg)
{
    if (!cfg) {
        log_error("client_run: 配置为空");
        return -1;
    }

    /* 注册信号处理 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = client_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 派生密钥 */
    uint8_t encrypt_key[32], auth_key[32];
    if (protocol_derive_keys(cfg->secret, encrypt_key, auth_key) != 0) {
        log_error("client: 密钥派生失败");
        return -1;
    }

    /* 创建 TUN 设备 */
    char tun_name[IFNAMSIZ] = "";
    int tun_fd = tun_create(tun_name, sizeof(tun_name));
    if (tun_fd < 0) {
        log_error("client: 创建 TUN 设备失败");
        return -1;
    }

    /* 配置 TUN 设备 */
    if (tun_configure(tun_name, cfg->tun_ip, cfg->tun_peer) != 0) {
        log_error("client: 配置 TUN 设备失败");
        close(tun_fd);
        return -1;
    }

    int mtu = cfg->mtu > 0 ? cfg->mtu : 1400;
    if (tun_set_mtu(tun_name, mtu) != 0) {
        log_error("client: 设置 MTU 失败");
        close(tun_fd);
        return -1;
    }

    /* 解析远端地址 */
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(cfg->remote_port);
    if (inet_pton(AF_INET, cfg->remote_addr, &remote_addr.sin_addr) != 1) {
        log_error("client: 无效的远端地址: %s", cfg->remote_addr);
        close(tun_fd);
        return -1;
    }

    /* 确定线程数 */
    int num_threads = cfg->threads;
    if (num_threads <= 0) {
        num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_threads <= 0) num_threads = 1;
    }

    log_info("client: 启动 %d 个 Worker 线程, 连接 %s:%d",
             num_threads, cfg->remote_addr, cfg->remote_port);

    /* 分配 Worker 数组 + 上下文数组 */
    struct worker *workers = (struct worker *)calloc(num_threads,
                                                     sizeof(struct worker));
    struct client_worker_ctx *ctxs = (struct client_worker_ctx *)calloc(
        num_threads, sizeof(struct client_worker_ctx));
    if (!workers || !ctxs) {
        log_error("client: 内存分配失败");
        free(workers);
        free(ctxs);
        close(tun_fd);
        return -1;
    }

    /* 初始化并启动所有 Worker */
    int started = 0;
    for (int i = 0; i < num_threads; i++) {
        if (worker_init(&workers[i], i, tun_fd, encrypt_key, auth_key) != 0) {
            log_error("client: Worker[%d] 初始化失败", i);
            break;
        }

        /* UDP connect 到远端 */
        if (connect(workers[i].udp_fd, (struct sockaddr *)&remote_addr,
                    sizeof(remote_addr)) < 0) {
            log_error("client: Worker[%d] UDP connect 失败: %s",
                      i, strerror(errno));
            worker_cleanup(&workers[i]);
            break;
        }

        /* 初始化上下文并关联到 worker */
        ctxs[i].w = &workers[i];
        ctxs[i].remote_addr = remote_addr;
        ctxs[i].last_ping_time = time(NULL);
        ctxs[i].last_pong_time = time(NULL);
        workers[i].user_data = &ctxs[i];

        if (worker_start(&workers[i], client_worker_thread) != 0) {
            log_error("client: Worker[%d] 启动失败", i);
            worker_cleanup(&workers[i]);
            break;
        }

        started++;
    }

    if (started == 0) {
        log_error("client: 没有 Worker 成功启动");
        free(workers);
        free(ctxs);
        close(tun_fd);
        return -1;
    }

    log_info("client: %d 个 Worker 已启动", started);

    /* 主线程等待信号 */
    while (g_client_running) {
        sleep(1);
    }

    log_info("client: 收到退出信号，正在关闭...");

    /* 停止并清理所有 Worker */
    for (int i = 0; i < started; i++) {
        worker_stop(&workers[i]);
        worker_cleanup(&workers[i]);
    }

    free(workers);
    free(ctxs);
    close(tun_fd);

    /* 清除栈上密钥材料 */
    OPENSSL_cleanse(encrypt_key, sizeof(encrypt_key));
    OPENSSL_cleanse(auth_key, sizeof(auth_key));

    log_info("client: 已退出");
    return 0;
}
