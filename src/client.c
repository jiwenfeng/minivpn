/*
 * MiniVPN - 客户端模式
 *
 * 运行在近端服务器上：
 * 1. 创建 TUN 设备
 * 2. 启动 N 个 Worker 线程（SO_REUSEPORT 连接到远端）
 * 3. 发送 AUTH 帧，等待 OK 响应
 * 4. epoll 事件循环：
 *    - TUN 可读：drain loop 批量读 IP 包 → 加密 → sendmmsg 批量发送
 *    - UDP 可读：drain loop 批量 recv → 解密 → 批量写 TUN
 * 5. 心跳：每 30 秒 PING，90 秒超时断线重连
 *
 * 改进:
 * - 共享认证状态
 * - 抗重放窗口
 * - crypto_ctx 复用
 * - SIGPIPE 忽略
 * - 短写检测
 * - IPv4/IPv6 双栈支持
 * - drain loop + sendmmsg 批量 I/O
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
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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
#define BATCH_SIZE       32    /* drain loop / sendmmsg 批量大小 */
#define PING_INTERVAL    30   /* 心跳间隔 (秒) */
#define PONG_TIMEOUT     90   /* PONG 超时 (秒) */
#define AUTH_TIMEOUT     10   /* AUTH 等待 OK 超时 (秒) */
#define AUTH_RETRY_MAX   5    /* AUTH 最大重试次数 */
#define RECONNECT_DELAY  3    /* 重连延迟 (秒) */

/* ========== 客户端 Worker 扩展上下文 ========== */

struct client_worker_ctx {
    struct worker *w;
    struct sockaddr_storage remote_addr;  /* 远端地址（IPv4 或 IPv6） */
    time_t last_ping_time;                /* 上次发送 PING 的时间 */
    time_t last_pong_time;                /* 上次收到 PONG 的时间 */
    uint64_t local_gen;                   /* 本 Worker 已同步的重连代数 */
};

/* ========== 断线重连：重建 UDP socket（通用，所有 Worker 可调用） ========== */

static int client_rebuild_socket(struct worker *w,
                                 const struct sockaddr_storage *remote_addr)
{
    /* 从 epoll 移除旧的 udp_fd */
    if (w->udp_fd >= 0) {
        epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, w->udp_fd, NULL);
        close(w->udp_fd);
        w->udp_fd = -1;
    }

    /* 创建新的 UDP socket（支持 IPv4/IPv6） */
    w->udp_fd = socket(w->af, SOCK_DGRAM | SOCK_NONBLOCK, 0);
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

    /* IPv6: 设置双栈 */
    if (w->af == AF_INET6) {
        int v6only = 0;
        setsockopt(w->udp_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   &v6only, sizeof(v6only));
    }

    /* 连接到远端 (UDP connect 绑定默认目标) */
    socklen_t addr_len = sockaddr_len(remote_addr);
    if (connect(w->udp_fd, (struct sockaddr *)remote_addr, addr_len) < 0) {
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

    log_info("client worker[%d]: UDP socket 重建完成, fd=%d", w->id, w->udp_fd);
    return 0;
}

/*
 * Worker 0 专用重连：重建 socket + 重置共享状态 + 递增重连代数
 */
static int client_reconnect_socket(struct worker *w,
                                   const struct sockaddr_storage *remote_addr)
{
    if (client_rebuild_socket(w, remote_addr) != 0) {
        return -1;
    }

    /* 重置共享抗重放窗口 (线程安全) */
    shared_peer_replay_reset(w->shared_peer);

    /* 清除认证状态 */
    __atomic_store_n(&w->shared_peer->authenticated, 0, __ATOMIC_SEQ_CST);

    /* 递增重连代数，通知所有 Worker 重建 socket */
    __atomic_fetch_add(&w->shared_peer->reconnect_gen, 1, __ATOMIC_SEQ_CST);

    return 0;
}

/* ========== 发送 AUTH 并等待 OK ========== */

static int client_authenticate(struct worker *w)
{
    uint8_t auth_payload[AUTH_TS_SIZE + AUTH_NONCE_SIZE + HMAC_SIZE];
    int auth_payload_len = 0;
    uint8_t frame_buf[MAX_FRAME_SIZE];
    uint8_t recv_buf[MAX_FRAME_SIZE];

    for (int retry = 0; retry < AUTH_RETRY_MAX; retry++) {
        if (!__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) || !g_client_running)
            return -1;

        /* 每次重试都生成新的 AUTH 帧内容（刷新时间戳和 nonce） */
        if (protocol_make_auth(w->crypto, auth_payload, &auth_payload_len) != 0) {
            log_error("client worker[%d]: 生成 AUTH 帧失败", w->id);
            return -1;
        }

        /* 加密 AUTH 帧 */
        int enc_len = protocol_encrypt(w->crypto, FRAME_AUTH,
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

        while (time(NULL) < deadline &&
               __atomic_load_n(&w->running, __ATOMIC_SEQ_CST) &&
               g_client_running) {
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

                if (protocol_decrypt(w->crypto, recv_buf, (int)n,
                                     &frame_type, payload, &payload_len) != 0) {
                    continue;
                }

                if (frame_type == FRAME_OK) {
                    __atomic_store_n(&w->shared_peer->authenticated, 1,
                                    __ATOMIC_SEQ_CST);
                    log_info("client worker[%d]: 认证成功，收到 OK 帧",
                             w->id);
                    return 0;
                }
            }
        }

        log_info("client worker[%d]: 等待 OK 超时，重试...", w->id);
    }

    log_error("client worker[%d]: AUTH 认证失败，超过最大重试次数 (%d 次, 每次超时 %d 秒)",
              w->id, AUTH_RETRY_MAX, AUTH_TIMEOUT);
    log_error("client worker[%d]: 请检查: 1) 服务端是否运行 2) 防火墙/安全组是否放行 UDP 端口"
              " 3) 两端 secret 密钥是否一致", w->id);
    return -1;
}

/* ========== 客户端 Worker 线程函数 ========== */

static void *client_worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    struct client_worker_ctx *ctx = (struct client_worker_ctx *)w->user_data;
    struct sockaddr_storage remote_addr;
    memcpy(&remote_addr, &ctx->remote_addr, sizeof(remote_addr));
    struct epoll_event events[MAX_EVENTS];

    /* ---- sendmmsg 批量发送缓冲区 (TUN → UDP) ---- */
    uint8_t udp_send_bufs[BATCH_SIZE][MAX_FRAME_SIZE];
    struct iovec send_iovs[BATCH_SIZE];
    struct mmsghdr send_msgs[BATCH_SIZE];

    /* ---- drain loop 复用缓冲区 ---- */
    uint8_t tun_buf[MAX_PAYLOAD];
    uint8_t udp_recv_buf[MAX_FRAME_SIZE];
    uint8_t decrypt_payload[MAX_PAYLOAD];
    uint8_t ctrl_send_buf[MAX_FRAME_SIZE]; /* 控制帧发送 */

    /* 初始化 sendmmsg 结构 (客户端已 connect，msg_name = NULL) */
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int k = 0; k < BATCH_SIZE; k++) {
        send_msgs[k].msg_hdr.msg_iov = &send_iovs[k];
        send_msgs[k].msg_hdr.msg_iovlen = 1;
        /* msg_name = NULL, msg_namelen = 0 (已 connect) */
    }

    log_info("client worker[%d]: 线程开始运行", w->id);

    /* 初始化本 Worker 的重连代数 */
    ctx->local_gen = __atomic_load_n(&w->shared_peer->reconnect_gen,
                                     __ATOMIC_SEQ_CST);

    /* 只有 Worker 0 负责首次认证 */
    if (w->id == 0) {
        if (client_authenticate(w) != 0) {
            log_error("client worker[%d]: 首次认证失败", w->id);
        }
    } else {
        /* 其他 Worker 等待 Worker 0 完成认证 */
        while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) &&
               g_client_running &&
               !__atomic_load_n(&w->shared_peer->authenticated,
                                __ATOMIC_SEQ_CST)) {
            usleep(100000);  /* 100ms */
        }
    }

    ctx->last_ping_time = time(NULL);
    __atomic_store_n(&w->shared_peer->last_pong_time, (long)time(NULL),
                     __ATOMIC_SEQ_CST);

    while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) && g_client_running) {

        /* 非 Worker 0: 检查是否需要跟随重连代数重建 socket */
        if (w->id != 0) {
            uint64_t cur_gen = __atomic_load_n(&w->shared_peer->reconnect_gen,
                                               __ATOMIC_SEQ_CST);
            if (cur_gen != ctx->local_gen) {
                log_info("client worker[%d]: 检测到重连代数变化 (%llu -> %llu)，重建 socket",
                         w->id, (unsigned long long)ctx->local_gen,
                         (unsigned long long)cur_gen);

                if (client_rebuild_socket(w, &remote_addr) != 0) {
                    log_error("client worker[%d]: 跟随重建 socket 失败", w->id);
                    usleep(500000);  /* 500ms 后重试 */
                    continue;
                }

                ctx->local_gen = cur_gen;
                log_info("client worker[%d]: socket 重建完成", w->id);

                /* 等待 Worker 0 完成认证 */
                while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) &&
                       g_client_running &&
                       !__atomic_load_n(&w->shared_peer->authenticated,
                                        __ATOMIC_SEQ_CST)) {
                    usleep(100000);  /* 100ms */
                }
                ctx->last_ping_time = time(NULL);
                __atomic_store_n(&w->shared_peer->last_pong_time,
                                 (long)time(NULL), __ATOMIC_SEQ_CST);
                continue;
            }
        }

        /* 检查是否需要重连 (只有 Worker 0 负责重连决策) */
        if (!__atomic_load_n(&w->shared_peer->authenticated,
                             __ATOMIC_SEQ_CST)) {
            if (w->id == 0) {
                log_info("client worker[%d]: 开始重连...", w->id);
                sleep(RECONNECT_DELAY);

                if (!__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) ||
                    !g_client_running)
                    break;

                if (client_reconnect_socket(w, &remote_addr) != 0) {
                    log_error("client worker[%d]: 重建 socket 失败", w->id);
                    continue;
                }

                /* 同步 Worker 0 自身的代数 */
                ctx->local_gen = __atomic_load_n(
                    &w->shared_peer->reconnect_gen, __ATOMIC_SEQ_CST);

                if (client_authenticate(w) != 0) {
                    log_error("client worker[%d]: 重连认证失败", w->id);
                    continue;
                }

                ctx->last_ping_time = time(NULL);
                __atomic_store_n(&w->shared_peer->last_pong_time,
                                 (long)time(NULL), __ATOMIC_SEQ_CST);
                log_info("client worker[%d]: 重连成功", w->id);
            } else {
                /* 非 Worker 0 等待认证恢复（重建 socket 由代数检查处理） */
                usleep(100000);
                continue;
            }
        }

        /* 心跳检查 (只有 Worker 0 发送心跳) */
        if (w->id == 0) {
            time_t now = time(NULL);

            /* 发送 PING */
            if (now - ctx->last_ping_time >= PING_INTERVAL) {
                int ping_len = protocol_encrypt(w->crypto, FRAME_PING,
                                                NULL, 0,
                                                ctrl_send_buf,
                                                sizeof(ctrl_send_buf));
                if (ping_len > 0) {
                    send(w->udp_fd, ctrl_send_buf, ping_len, 0);
                    log_debug("client worker[%d]: 发送 PING", w->id);
                }
                ctx->last_ping_time = now;
            }

            /* PONG 超时检测（读取共享的 last_pong_time，任何 Worker 收到 PONG 都会更新） */
            long shared_pong = __atomic_load_n(&w->shared_peer->last_pong_time,
                                               __ATOMIC_SEQ_CST);
            if (now - (time_t)shared_pong > PONG_TIMEOUT) {
                log_error("client worker[%d]: PONG 超时 (%d 秒)，触发重连",
                          w->id, PONG_TIMEOUT);
                __atomic_store_n(&w->shared_peer->authenticated, 0,
                                __ATOMIC_SEQ_CST);
                continue;
            }
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
                /* ==== TUN 批量读取 + sendmmsg 批量发送 ==== */
                if (!__atomic_load_n(&w->shared_peer->authenticated,
                                     __ATOMIC_SEQ_CST)) {
                    /* 未认证，排空 TUN 避免积压 */
                    for (int k = 0; k < BATCH_SIZE; k++) {
                        if (read(w->tun_fd, tun_buf, sizeof(tun_buf)) <= 0)
                            break;
                    }
                    continue;
                }

                int batch_count = 0;
                for (int k = 0; k < BATCH_SIZE; k++) {
                    ssize_t n = read(w->tun_fd, tun_buf, sizeof(tun_buf));
                    if (n <= 0) break;

                    int enc_len = protocol_encrypt(
                        w->crypto, FRAME_DATA,
                        tun_buf, (int)n,
                        udp_send_bufs[batch_count],
                        sizeof(udp_send_bufs[batch_count]));
                    if (enc_len <= 0) {
                        log_error("client worker[%d]: 加密失败", w->id);
                        continue;
                    }

                    send_iovs[batch_count].iov_base =
                        udp_send_bufs[batch_count];
                    send_iovs[batch_count].iov_len = enc_len;
                    batch_count++;
                }

                if (batch_count > 0) {
                    int sent = sendmmsg(w->udp_fd, send_msgs,
                                        batch_count, 0);
                    if (sent < 0) {
                        if (errno != EAGAIN) {
                            log_error("client worker[%d]: sendmmsg 失败: %s",
                                      w->id, strerror(errno));
                        }
                    } else if (sent < batch_count) {
                        log_debug("client worker[%d]: sendmmsg 部分发送: %d/%d",
                                  w->id, sent, batch_count);
                    }
                }

            } else if (fd == w->udp_fd && (events[i].events & EPOLLIN)) {
                /* ==== UDP drain loop：批量接收 + 处理 ==== */
                for (int k = 0; k < BATCH_SIZE; k++) {
                    ssize_t n = recv(w->udp_fd, udp_recv_buf,
                                     sizeof(udp_recv_buf), MSG_DONTWAIT);
                    if (n <= 0) break;

                    uint8_t frame_type;
                    int payload_len = 0;

                    if (protocol_decrypt(w->crypto, udp_recv_buf, (int)n,
                                         &frame_type, decrypt_payload,
                                         &payload_len) != 0) {
                        log_debug("client worker[%d]: 解密失败，丢弃帧",
                                  w->id);
                        continue;
                    }

                    /* 抗重放检查 (共享窗口，线程安全) */
                    if (shared_peer_replay_check(w->shared_peer,
                                                 udp_recv_buf) != 0) {
                        log_debug("client worker[%d]: 检测到重放帧，丢弃",
                                  w->id);
                        continue;
                    }

                    switch (frame_type) {
                    case FRAME_DATA:
                        if (payload_len > 0) {
                            ssize_t wn = write(w->tun_fd, decrypt_payload,
                                               payload_len);
                            if (wn < 0) {
                                if (errno != EAGAIN) {
                                    log_error("client worker[%d]: 写 TUN 失败: %s",
                                              w->id, strerror(errno));
                                }
                            } else if (wn != payload_len) {
                                log_error("client worker[%d]: TUN 短写: %zd/%d",
                                          w->id, wn, payload_len);
                            }
                        }
                        break;

                    case FRAME_PONG:
                        /* 更新共享的 last_pong_time（任何 Worker 都可能收到 PONG） */
                        __atomic_store_n(&w->shared_peer->last_pong_time,
                                        (long)time(NULL), __ATOMIC_SEQ_CST);
                        log_debug("client worker[%d]: 收到 PONG", w->id);
                        break;

                    case FRAME_OK:
                        log_debug("client worker[%d]: 收到延迟 OK 帧",
                                  w->id);
                        break;

                    case FRAME_PING: {
                        /* 服务端发来的 PING，回复 PONG */
                        int pong_len = protocol_encrypt(w->crypto,
                                                        FRAME_PONG,
                                                        NULL, 0,
                                                        ctrl_send_buf,
                                                        sizeof(ctrl_send_buf));
                        if (pong_len > 0) {
                            send(w->udp_fd, ctrl_send_buf, pong_len, 0);
                        }
                        break;
                    }

                    default:
                        log_debug("client worker[%d]: 未知帧类型 0x%02x",
                                  w->id, frame_type);
                        break;
                    }
                } /* end drain loop */
            }
        } /* end for nfds */
    }

    log_info("client worker[%d]: 线程退出", w->id);
    return NULL;
}

/* ========== 客户端入口 ========== */

int client_run(const struct vpn_config *cfg)
{
    if (!cfg) {
        log_error("client_run: 配置为空");
        return -1;
    }

    /* 忽略 SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

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

    /* 配置 TUN 设备 IPv4 地址 */
    if (cfg->tun_ip[0] && cfg->tun_peer[0]) {
        if (tun_configure(tun_name, cfg->tun_ip, cfg->tun_peer) != 0) {
            log_error("client: 配置 TUN 设备 IPv4 失败");
            close(tun_fd);
            return -1;
        }
    }

    /* 配置 TUN 设备 IPv6 地址（如果指定） */
    if (cfg->tun_ip6[0]) {
        int prefix = cfg->tun_ip6_prefix > 0 ? cfg->tun_ip6_prefix : 64;
        if (tun_configure_ipv6(tun_name, cfg->tun_ip6, prefix) != 0) {
            log_error("client: 配置 TUN 设备 IPv6 失败");
            close(tun_fd);
            return -1;
        }
    }

    int mtu = cfg->mtu > 0 ? cfg->mtu : 1400;
    if (tun_set_mtu(tun_name, mtu) != 0) {
        log_error("client: 设置 MTU 失败");
        close(tun_fd);
        return -1;
    }

    /* 确定地址族 */
    int af = cfg->af > 0 ? cfg->af : AF_INET;

    /* 解析远端地址（支持 IPv4 和 IPv6） */
    struct sockaddr_storage remote_addr;
    socklen_t remote_addr_len;
    memset(&remote_addr, 0, sizeof(remote_addr));

    if (af == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&remote_addr;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(cfg->port);
        if (inet_pton(AF_INET6, cfg->addr, &s6->sin6_addr) != 1) {
            log_error("client: 无效的 IPv6 远端地址: %s", cfg->addr);
            close(tun_fd);
            return -1;
        }
        remote_addr_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&remote_addr;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(cfg->port);
        if (inet_pton(AF_INET, cfg->addr, &s4->sin_addr) != 1) {
            log_error("client: 无效的 IPv4 远端地址: %s", cfg->addr);
            close(tun_fd);
            return -1;
        }
        remote_addr_len = sizeof(struct sockaddr_in);
    }

    /* 确定线程数 */
    int num_threads = cfg->threads;
    if (num_threads <= 0) {
        num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_threads <= 0) num_threads = 1;
    }

    log_info("client: 启动 %d 个 Worker 线程, 连接 %s:%d (%s)",
             num_threads, cfg->addr, cfg->port,
             af == AF_INET6 ? "IPv6" : "IPv4");

    /* 初始化共享认证状态 */
    struct shared_peer_state shared_peer;
    if (shared_peer_init(&shared_peer) != 0) {
        log_error("client: 初始化共享认证状态失败");
        close(tun_fd);
        return -1;
    }

    /* 分配 Worker 数组 + 上下文数组 */
    struct worker *workers = (struct worker *)calloc(num_threads,
                                                     sizeof(struct worker));
    struct client_worker_ctx *ctxs = (struct client_worker_ctx *)calloc(
        num_threads, sizeof(struct client_worker_ctx));
    if (!workers || !ctxs) {
        log_error("client: 内存分配失败");
        free(workers);
        free(ctxs);
        shared_peer_destroy(&shared_peer);
        close(tun_fd);
        return -1;
    }

    /* 初始化并启动所有 Worker */
    int started = 0;
    for (int i = 0; i < num_threads; i++) {
        if (worker_init(&workers[i], i, tun_fd, af, encrypt_key, auth_key,
                        &shared_peer) != 0) {
            log_error("client: Worker[%d] 初始化失败", i);
            break;
        }

        /* UDP connect 到远端 */
        if (connect(workers[i].udp_fd, (struct sockaddr *)&remote_addr,
                    remote_addr_len) < 0) {
            log_error("client: Worker[%d] UDP connect 失败: %s",
                      i, strerror(errno));
            worker_cleanup(&workers[i]);
            break;
        }

        /* 初始化上下文并关联到 worker */
        ctxs[i].w = &workers[i];
        memcpy(&ctxs[i].remote_addr, &remote_addr, sizeof(remote_addr));
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
        shared_peer_destroy(&shared_peer);
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
    shared_peer_destroy(&shared_peer);
    close(tun_fd);

    /* 清除栈上密钥材料 */
    OPENSSL_cleanse(encrypt_key, sizeof(encrypt_key));
    OPENSSL_cleanse(auth_key, sizeof(auth_key));

    log_info("client: 已退出");
    return 0;
}
