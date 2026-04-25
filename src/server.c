/*
 * MiniVPN - 服务端模式
 *
 * 运行在远端服务器上：
 * 1. 创建 TUN 设备
 * 2. 启动 N 个 Worker 线程（SO_REUSEPORT 绑定同一端口）
 * 3. epoll 事件循环：
 *    - UDP 可读：recvmmsg 批量接收 → 解密 → AUTH/DATA 处理
 *    - TUN 可读：drain loop 批量读 IP 包 → 加密 → sendmmsg 批量发送
 *
 * 改进:
 * - 共享认证状态 (所有Worker可见)
 * - 抗重放滑动窗口
 * - crypto_ctx 复用
 * - SIGPIPE 忽略
 * - 短写检测
 * - IPv4/IPv6 双栈支持
 * - recvmmsg/sendmmsg 批量 I/O
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

static volatile sig_atomic_t g_server_running = 1;

static void server_signal_handler(int sig)
{
    (void)sig;
    g_server_running = 0;
}

/* ========== 常量 ========== */

#define MAX_EVENTS      64
#define BATCH_SIZE      32    /* recvmmsg/sendmmsg 批量大小 */
#define SRV_PING_INTERVAL 10  /* 服务端主动 PING 间隔 (秒)，保持双向 NAT 映射 */

/* ========== 服务端 Worker 线程函数 ========== */

static void *server_worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    struct epoll_event events[MAX_EVENTS];

    /* ---- recvmmsg 批量接收缓冲区 ---- */
    uint8_t udp_recv_bufs[BATCH_SIZE][MAX_FRAME_SIZE];
    struct sockaddr_storage src_addrs[BATCH_SIZE];
    struct iovec recv_iovs[BATCH_SIZE];
    struct mmsghdr recv_msgs[BATCH_SIZE];

    /* ---- sendmmsg 批量发送缓冲区 ---- */
    uint8_t udp_send_bufs[BATCH_SIZE][MAX_FRAME_SIZE];
    struct iovec send_iovs[BATCH_SIZE];
    struct mmsghdr send_msgs[BATCH_SIZE];

    /* ---- 复用缓冲区 ---- */
    uint8_t tun_buf[MAX_PAYLOAD];          /* TUN 读取复用 */
    uint8_t decrypt_payload[MAX_PAYLOAD];  /* 解密输出复用 */
    uint8_t ctrl_send_buf[MAX_FRAME_SIZE]; /* 控制帧发送 */

    /* 初始化 recvmmsg 结构 */
    memset(recv_msgs, 0, sizeof(recv_msgs));
    for (int k = 0; k < BATCH_SIZE; k++) {
        recv_iovs[k].iov_base = udp_recv_bufs[k];
        recv_iovs[k].iov_len = MAX_FRAME_SIZE;
        recv_msgs[k].msg_hdr.msg_iov = &recv_iovs[k];
        recv_msgs[k].msg_hdr.msg_iovlen = 1;
        recv_msgs[k].msg_hdr.msg_name = &src_addrs[k];
        recv_msgs[k].msg_hdr.msg_namelen = sizeof(src_addrs[k]);
    }

    /* 初始化 sendmmsg 结构 (msg_name 在使用时设置) */
    memset(send_msgs, 0, sizeof(send_msgs));
    for (int k = 0; k < BATCH_SIZE; k++) {
        send_msgs[k].msg_hdr.msg_iov = &send_iovs[k];
        send_msgs[k].msg_hdr.msg_iovlen = 1;
    }

    log_info("server worker[%d]: 线程开始运行", w->id);

    /* Worker 0 负责服务端主动 PING 保活 */
    time_t last_srv_ping_time = time(NULL);

    while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) && g_server_running) {

        /* 服务端主动 PING：只有 Worker 0 在已认证时定期发送 PING 到客户端，
         * 保持 server→client 方向的 NAT 映射活跃 */
        if (w->id == 0 &&
            __atomic_load_n(&w->shared_peer->authenticated, __ATOMIC_SEQ_CST)) {
            time_t now = time(NULL);
            if (now - last_srv_ping_time >= SRV_PING_INTERVAL) {
                struct sockaddr_storage peer;
                shared_peer_get_addr(w->shared_peer, &peer);
                socklen_t peer_len = sockaddr_len(&peer);

                int ping_len = protocol_encrypt(w->crypto, FRAME_PING,
                                                NULL, 0,
                                                ctrl_send_buf,
                                                sizeof(ctrl_send_buf));
                if (ping_len > 0) {
                    ssize_t ps = sendto(w->udp_fd, ctrl_send_buf, ping_len, 0,
                                        (struct sockaddr *)&peer, peer_len);
                    if (ps < 0) {
                        log_error("server worker[%d]: 发送 PING 失败: %s",
                                  w->id, strerror(errno));
                    } else {
                        log_debug("server worker[%d]: 发送 PING 到客户端", w->id);
                    }
                }
                last_srv_ping_time = now;
            }
        }

        int nfds = epoll_wait(w->epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error("server worker[%d]: epoll_wait 失败: %s",
                      w->id, strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == w->udp_fd && (events[i].events & EPOLLIN)) {
                /* ==== UDP 批量接收 (recvmmsg) ==== */

                /* 重置 msg_namelen (recvmmsg 会修改) */
                for (int k = 0; k < BATCH_SIZE; k++)
                    recv_msgs[k].msg_hdr.msg_namelen = sizeof(src_addrs[k]);

                int npkts = recvmmsg(w->udp_fd, recv_msgs, BATCH_SIZE,
                                     MSG_DONTWAIT, NULL);
                if (npkts <= 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        log_error("server worker[%d]: recvmmsg 失败: %s",
                                  w->id, strerror(errno));
                    }
                    continue;
                }

                /* 逐包处理 */
                for (int j = 0; j < npkts; j++) {
                    int n = (int)recv_msgs[j].msg_len;
                    socklen_t addr_len = recv_msgs[j].msg_hdr.msg_namelen;

                    /* 解密帧 */
                    uint8_t frame_type;
                    int payload_len = 0;

                    if (protocol_decrypt(w->crypto, udp_recv_bufs[j], n,
                                         &frame_type, decrypt_payload,
                                         &payload_len) != 0) {
                        char src_str[INET6_ADDRSTRLEN + 8];
                        sockaddr_to_str(&src_addrs[j], src_str,
                                        sizeof(src_str));
                        log_error("server worker[%d]: 解密失败 (%d 字节), 来自 %s"
                                  " (密钥不匹配或数据损坏)",
                                  w->id, n, src_str);
                        continue;
                    }

                    /* 抗重放检查 (AUTH 帧除外) */
                    if (frame_type != FRAME_AUTH) {
                        if (shared_peer_replay_check(w->shared_peer,
                                                     udp_recv_bufs[j]) != 0) {
                            log_debug("server worker[%d]: 检测到重放帧，丢弃",
                                      w->id);
                            continue;
                        }
                    }

                    switch (frame_type) {
                    case FRAME_AUTH: {
                        /* AUTH 帧：验证认证 */
                        char addr_str[INET6_ADDRSTRLEN + 8];
                        sockaddr_to_str(&src_addrs[j], addr_str,
                                        sizeof(addr_str));

                        if (protocol_verify_auth(w->crypto, decrypt_payload,
                                                 payload_len) != 0) {
                            log_error("server worker[%d]: AUTH 验证失败, 来自 %s",
                                      w->id, addr_str);
                            continue;
                        }

                        /* 更新共享认证状态 */
                        shared_peer_update_addr(w->shared_peer, &src_addrs[j]);

                        /* 重置抗重放窗口：客户端重连后 nonce 计数器可能变化，
                         * 旧的重放窗口会错误拒绝新帧 */
                        shared_peer_replay_reset(w->shared_peer);

                        __atomic_store_n(&w->shared_peer->authenticated, 1,
                                        __ATOMIC_SEQ_CST);

                        log_info("server worker[%d]: 客户端已认证: %s",
                                 w->id, addr_str);

                        /* 回复 OK 帧 */
                        int ok_len = protocol_encrypt(w->crypto, FRAME_OK,
                                                      NULL, 0,
                                                      ctrl_send_buf,
                                                      sizeof(ctrl_send_buf));
                        if (ok_len > 0) {
                            ssize_t ok_sent = sendto(w->udp_fd, ctrl_send_buf,
                                                     ok_len, 0,
                                                     (struct sockaddr *)&src_addrs[j],
                                                     addr_len);
                            if (ok_sent < 0) {
                                log_error("server worker[%d]: 发送 OK 帧失败: %s",
                                          w->id, strerror(errno));
                            } else {
                                log_info("server worker[%d]: 已发送 OK 帧到 %s",
                                         w->id, addr_str);
                            }
                        } else {
                            log_error("server worker[%d]: 加密 OK 帧失败",
                                      w->id);
                        }
                        break;
                    }

                    case FRAME_DATA: {
                        /* DATA 帧：写入 TUN */
                        if (!__atomic_load_n(&w->shared_peer->authenticated,
                                             __ATOMIC_SEQ_CST)) {
                            log_debug("server worker[%d]: 收到 DATA 但未认证，丢弃",
                                      w->id);
                            continue;
                        }

                        /* 更新 peer 地址（可能发生 NAT 变更） */
                        shared_peer_update_addr(w->shared_peer, &src_addrs[j]);

                        if (payload_len > 0) {
                            ssize_t wn = write(w->tun_fd, decrypt_payload,
                                               payload_len);
                            if (wn < 0) {
                                if (errno != EAGAIN) {
                                    log_error("server worker[%d]: 写 TUN 失败: %s",
                                              w->id, strerror(errno));
                                }
                            } else if (wn != payload_len) {
                                log_error("server worker[%d]: TUN 短写: %zd/%d",
                                          w->id, wn, payload_len);
                            }
                        }
                        break;
                    }

                    case FRAME_PING: {
                        /* PING 帧：回复 PONG */
                        if (!__atomic_load_n(&w->shared_peer->authenticated,
                                             __ATOMIC_SEQ_CST))
                            continue;

                        /* 更新 peer 地址 */
                        shared_peer_update_addr(w->shared_peer, &src_addrs[j]);

                        int pong_len = protocol_encrypt(w->crypto, FRAME_PONG,
                                                        NULL, 0,
                                                        ctrl_send_buf,
                                                        sizeof(ctrl_send_buf));
                        if (pong_len > 0) {
                            sendto(w->udp_fd, ctrl_send_buf, pong_len, 0,
                                   (struct sockaddr *)&src_addrs[j],
                                   addr_len);
                        }
                        log_debug("server worker[%d]: 收到 PING，已回复 PONG",
                                  w->id);
                        break;
                    }

                    case FRAME_PONG:
                        log_debug("server worker[%d]: 收到 PONG", w->id);
                        break;

                    default:
                        log_debug("server worker[%d]: 未知帧类型 0x%02x",
                                  w->id, frame_type);
                        break;
                    }
                } /* end for npkts */

            } else if (fd == w->tun_fd && (events[i].events & EPOLLIN)) {
                /* ==== TUN 批量读取 + sendmmsg 批量发送 ==== */
                if (!__atomic_load_n(&w->shared_peer->authenticated,
                                     __ATOMIC_SEQ_CST)) {
                    /* 未认证，排空 TUN 数据避免积压 */
                    for (int k = 0; k < BATCH_SIZE; k++) {
                        if (read(w->tun_fd, tun_buf, sizeof(tun_buf)) <= 0)
                            break;
                    }
                    continue;
                }

                /* 获取一次 peer 地址（整个 batch 共用） */
                struct sockaddr_storage peer;
                shared_peer_get_addr(w->shared_peer, &peer);
                socklen_t peer_len = sockaddr_len(&peer);

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
                        log_error("server worker[%d]: 加密失败", w->id);
                        continue;
                    }

                    send_iovs[batch_count].iov_base =
                        udp_send_bufs[batch_count];
                    send_iovs[batch_count].iov_len = enc_len;
                    send_msgs[batch_count].msg_hdr.msg_name = &peer;
                    send_msgs[batch_count].msg_hdr.msg_namelen = peer_len;
                    batch_count++;
                }

                if (batch_count > 0) {
                    int sent = sendmmsg(w->udp_fd, send_msgs,
                                        batch_count, 0);
                    if (sent < 0) {
                        if (errno != EAGAIN) {
                            log_error("server worker[%d]: sendmmsg 失败: %s",
                                      w->id, strerror(errno));
                        }
                    } else if (sent < batch_count) {
                        log_debug("server worker[%d]: sendmmsg 部分发送: %d/%d",
                                  w->id, sent, batch_count);
                    }
                }
            }
        } /* end for nfds */
    }

    log_info("server worker[%d]: 线程退出", w->id);
    return NULL;
}

/* ========== 服务端入口 ========== */

int server_run(const struct vpn_config *cfg)
{
    if (!cfg) {
        log_error("server_run: 配置为空");
        return -1;
    }

    /* 忽略 SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* 注册信号处理 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = server_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 派生密钥（派生后 cfg->secret 中的明文密钥由调用方负责清除） */
    uint8_t encrypt_key[32], auth_key[32];
    if (protocol_derive_keys(cfg->secret, encrypt_key, auth_key) != 0) {
        log_error("server: 密钥派生失败");
        return -1;
    }

    /* 创建 TUN 设备 */
    char tun_name[IFNAMSIZ] = "";
    int tun_fd = tun_create(tun_name, sizeof(tun_name));
    if (tun_fd < 0) {
        log_error("server: 创建 TUN 设备失败");
        return -1;
    }

    /* 配置 TUN 设备 IPv4 地址 */
    if (cfg->tun_ip[0] && cfg->tun_peer[0]) {
        if (tun_configure(tun_name, cfg->tun_ip, cfg->tun_peer) != 0) {
            log_error("server: 配置 TUN 设备 IPv4 失败");
            close(tun_fd);
            return -1;
        }
    }

    /* 配置 TUN 设备 IPv6 地址（如果指定） */
    if (cfg->tun_ip6[0]) {
        int prefix = cfg->tun_ip6_prefix > 0 ? cfg->tun_ip6_prefix : 64;
        if (tun_configure_ipv6(tun_name, cfg->tun_ip6, prefix) != 0) {
            log_error("server: 配置 TUN 设备 IPv6 失败");
            close(tun_fd);
            return -1;
        }
    }

    int mtu = cfg->mtu > 0 ? cfg->mtu : 1400;
    if (tun_set_mtu(tun_name, mtu) != 0) {
        log_error("server: 设置 MTU 失败");
        close(tun_fd);
        return -1;
    }

    /* 确定线程数 */
    int num_threads = cfg->threads;
    if (num_threads <= 0) {
        num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_threads <= 0) num_threads = 1;
    }

    /* 确定地址族 */
    int af = cfg->af > 0 ? cfg->af : AF_INET;

    log_info("server: 启动 %d 个 Worker 线程, 监听 %s:%d (%s)",
             num_threads, cfg->addr, cfg->port,
             af == AF_INET6 ? "IPv6" : "IPv4");

    /* 初始化共享认证状态 */
    struct shared_peer_state shared_peer;
    if (shared_peer_init(&shared_peer) != 0) {
        log_error("server: 初始化共享认证状态失败");
        close(tun_fd);
        return -1;
    }

    /* 分配 Worker 数组 */
    struct worker *workers = (struct worker *)calloc(num_threads,
                                                     sizeof(struct worker));
    if (!workers) {
        log_error("server: 分配 Worker 数组失败");
        shared_peer_destroy(&shared_peer);
        close(tun_fd);
        return -1;
    }

    /* 准备绑定地址（支持 IPv4 和 IPv6） */
    struct sockaddr_storage bind_addr;
    socklen_t bind_addr_len;
    memset(&bind_addr, 0, sizeof(bind_addr));

    if (af == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&bind_addr;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(cfg->port);
        if (strcmp(cfg->addr, "0.0.0.0") == 0 || cfg->addr[0] == '\0') {
            s6->sin6_addr = in6addr_any;
        } else if (inet_pton(AF_INET6, cfg->addr, &s6->sin6_addr) != 1) {
            log_error("server: 无效的 IPv6 监听地址: %s", cfg->addr);
            free(workers);
            shared_peer_destroy(&shared_peer);
            close(tun_fd);
            return -1;
        }
        bind_addr_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&bind_addr;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(cfg->port);
        if (inet_pton(AF_INET, cfg->addr, &s4->sin_addr) != 1) {
            log_error("server: 无效的 IPv4 监听地址: %s", cfg->addr);
            free(workers);
            shared_peer_destroy(&shared_peer);
            close(tun_fd);
            return -1;
        }
        bind_addr_len = sizeof(struct sockaddr_in);
    }

    /* 初始化并启动所有 Worker */
    int started = 0;
    for (int i = 0; i < num_threads; i++) {
        if (worker_init(&workers[i], i, tun_fd, af, encrypt_key, auth_key,
                        &shared_peer) != 0) {
            log_error("server: Worker[%d] 初始化失败", i);
            break;
        }

        /* 绑定 UDP socket 到监听地址 */
        if (bind(workers[i].udp_fd, (struct sockaddr *)&bind_addr,
                 bind_addr_len) < 0) {
            log_error("server: Worker[%d] bind 失败: %s", i, strerror(errno));
            worker_cleanup(&workers[i]);
            break;
        }

        if (worker_start(&workers[i], server_worker_thread) != 0) {
            log_error("server: Worker[%d] 启动失败", i);
            worker_cleanup(&workers[i]);
            break;
        }

        started++;
    }

    if (started == 0) {
        log_error("server: 没有 Worker 成功启动");
        free(workers);
        shared_peer_destroy(&shared_peer);
        close(tun_fd);
        return -1;
    }

    log_info("server: %d 个 Worker 已启动，等待连接...", started);

    /* 主线程等待信号 */
    while (g_server_running) {
        sleep(1);
    }

    log_info("server: 收到退出信号，正在关闭...");

    /* 停止并清理所有 Worker */
    for (int i = 0; i < started; i++) {
        worker_stop(&workers[i]);
        worker_cleanup(&workers[i]);
    }

    free(workers);
    shared_peer_destroy(&shared_peer);
    close(tun_fd);

    /* 清除栈上密钥材料 */
    OPENSSL_cleanse(encrypt_key, sizeof(encrypt_key));
    OPENSSL_cleanse(auth_key, sizeof(auth_key));

    log_info("server: 已退出");
    return 0;
}
