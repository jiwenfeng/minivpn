/*
 * MiniVPN - 服务端模式
 *
 * 运行在远端服务器上：
 * 1. 创建 TUN 设备
 * 2. 启动 N 个 Worker 线程（SO_REUSEPORT 绑定同一端口）
 * 3. epoll 事件循环：
 *    - UDP 可读：解密 → AUTH/DATA 处理
 *    - TUN 可读：读 IP 包 → 加密 → UDP 发送
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
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>

/* ========== 全局信号标志 ========== */

static volatile sig_atomic_t g_server_running = 1;

static void server_signal_handler(int sig)
{
    (void)sig;
    g_server_running = 0;
}

/* ========== epoll 最大事件数 ========== */

#define MAX_EVENTS 64

/* ========== 服务端 Worker 线程函数 ========== */

static void *server_worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    struct epoll_event events[MAX_EVENTS];

    /* 预分配缓冲区 */
    uint8_t udp_recv_buf[MAX_FRAME_SIZE];
    uint8_t udp_send_buf[MAX_FRAME_SIZE];
    uint8_t tun_buf[MAX_PAYLOAD];
    uint8_t decrypt_payload[MAX_PAYLOAD];

    log_info("server worker[%d]: 线程开始运行", w->id);

    while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST) && g_server_running) {
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
                /* ---- UDP 可读：接收并处理 ---- */
                struct sockaddr_in src_addr;
                socklen_t addr_len = sizeof(src_addr);

                ssize_t n = recvfrom(w->udp_fd, udp_recv_buf,
                                     sizeof(udp_recv_buf), 0,
                                     (struct sockaddr *)&src_addr, &addr_len);
                if (n <= 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        log_error("server worker[%d]: recvfrom 失败: %s",
                                  w->id, strerror(errno));
                    }
                    continue;
                }

                /* 解密帧 */
                uint8_t frame_type;
                int payload_len = 0;

                if (protocol_decrypt(w->encrypt_key, udp_recv_buf, (int)n,
                                     &frame_type, decrypt_payload,
                                     &payload_len) != 0) {
                    log_debug("server worker[%d]: 解密失败，丢弃帧", w->id);
                    continue;
                }

                switch (frame_type) {
                case FRAME_AUTH: {
                    /* AUTH 帧：验证认证 */
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &src_addr.sin_addr,
                              addr_str, sizeof(addr_str));

                    if (protocol_verify_auth(w->auth_key, decrypt_payload,
                                             payload_len) != 0) {
                        log_error("server worker[%d]: AUTH 验证失败, 来自 %s:%d",
                                  w->id, addr_str,
                                  ntohs(src_addr.sin_port));
                        continue;
                    }

                    /* 记录 peer 地址，标记已认证 */
                    w->peer_addr = src_addr;
                    w->peer_authenticated = 1;

                    log_info("server worker[%d]: 客户端已认证: %s:%d",
                             w->id, addr_str,
                             ntohs(src_addr.sin_port));

                    /* 回复 OK 帧 */
                    int ok_len = protocol_encrypt(w->encrypt_key, FRAME_OK,
                                                  NULL, 0,
                                                  udp_send_buf,
                                                  sizeof(udp_send_buf));
                    if (ok_len > 0) {
                        sendto(w->udp_fd, udp_send_buf, ok_len, 0,
                               (struct sockaddr *)&src_addr, addr_len);
                        log_debug("server worker[%d]: 已发送 OK 帧", w->id);
                    }
                    break;
                }

                case FRAME_DATA: {
                    /* DATA 帧：写入 TUN */
                    if (!w->peer_authenticated) {
                        log_debug("server worker[%d]: 收到 DATA 但未认证，丢弃",
                                  w->id);
                        continue;
                    }

                    /* 更新 peer 地址（可能发生 NAT 变更） */
                    w->peer_addr = src_addr;

                    if (payload_len > 0) {
                        ssize_t wn = write(w->tun_fd, decrypt_payload,
                                           payload_len);
                        if (wn < 0 && errno != EAGAIN) {
                            log_error("server worker[%d]: 写 TUN 失败: %s",
                                      w->id, strerror(errno));
                        }
                    }
                    break;
                }

                case FRAME_PING: {
                    /* PING 帧：回复 PONG */
                    if (!w->peer_authenticated) continue;

                    /* 更新 peer 地址 */
                    w->peer_addr = src_addr;

                    int pong_len = protocol_encrypt(w->encrypt_key, FRAME_PONG,
                                                    NULL, 0,
                                                    udp_send_buf,
                                                    sizeof(udp_send_buf));
                    if (pong_len > 0) {
                        sendto(w->udp_fd, udp_send_buf, pong_len, 0,
                               (struct sockaddr *)&src_addr, addr_len);
                    }
                    log_debug("server worker[%d]: 收到 PING，已回复 PONG",
                              w->id);
                    break;
                }

                case FRAME_PONG:
                    /* 服务端通常不发 PING，忽略 PONG */
                    log_debug("server worker[%d]: 收到 PONG", w->id);
                    break;

                default:
                    log_debug("server worker[%d]: 未知帧类型 0x%02x",
                              w->id, frame_type);
                    break;
                }

            } else if (fd == w->tun_fd && (events[i].events & EPOLLIN)) {
                /* ---- TUN 可读：读取 IP 包并发送到 peer ---- */
                if (!w->peer_authenticated) {
                    /* 未认证，读取并丢弃 TUN 数据避免积压 */
                    ssize_t n = read(w->tun_fd, tun_buf, sizeof(tun_buf));
                    (void)n;
                    continue;
                }

                ssize_t n = read(w->tun_fd, tun_buf, sizeof(tun_buf));
                if (n <= 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        log_error("server worker[%d]: 读 TUN 失败: %s",
                                  w->id, strerror(errno));
                    }
                    continue;
                }

                /* 加密 IP 包 */
                int enc_len = protocol_encrypt(w->encrypt_key, FRAME_DATA,
                                               tun_buf, (int)n,
                                               udp_send_buf,
                                               sizeof(udp_send_buf));
                if (enc_len <= 0) {
                    log_error("server worker[%d]: 加密失败", w->id);
                    continue;
                }

                /* 发送到 peer */
                ssize_t sn = sendto(w->udp_fd, udp_send_buf, enc_len, 0,
                                    (struct sockaddr *)&w->peer_addr,
                                    sizeof(w->peer_addr));
                if (sn < 0 && errno != EAGAIN) {
                    log_error("server worker[%d]: sendto 失败: %s",
                              w->id, strerror(errno));
                }
            }
        }
    }

    log_info("server worker[%d]: 线程退出", w->id);
    return NULL;
}

/* ========== 服务端入口 ========== */

int server_run(const struct server_config *cfg)
{
    if (!cfg) {
        log_error("server_run: 配置为空");
        return -1;
    }

    /* 注册信号处理 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = server_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 派生密钥 */
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

    /* 配置 TUN 设备 */
    if (tun_configure(tun_name, cfg->tun_ip, cfg->tun_peer) != 0) {
        log_error("server: 配置 TUN 设备失败");
        close(tun_fd);
        return -1;
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

    log_info("server: 启动 %d 个 Worker 线程, 监听 %s:%d",
             num_threads, cfg->listen_addr, cfg->listen_port);

    /* 分配 Worker 数组 */
    struct worker *workers = (struct worker *)calloc(num_threads,
                                                     sizeof(struct worker));
    if (!workers) {
        log_error("server: 分配 Worker 数组失败");
        close(tun_fd);
        return -1;
    }

    /* 准备绑定地址 */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(cfg->listen_port);
    if (inet_pton(AF_INET, cfg->listen_addr, &bind_addr.sin_addr) != 1) {
        log_error("server: 无效的监听地址: %s", cfg->listen_addr);
        free(workers);
        close(tun_fd);
        return -1;
    }

    /* 初始化并启动所有 Worker */
    int started = 0;
    for (int i = 0; i < num_threads; i++) {
        if (worker_init(&workers[i], i, tun_fd, encrypt_key, auth_key) != 0) {
            log_error("server: Worker[%d] 初始化失败", i);
            break;
        }

        /* 绑定 UDP socket 到监听地址 */
        if (bind(workers[i].udp_fd, (struct sockaddr *)&bind_addr,
                 sizeof(bind_addr)) < 0) {
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
    close(tun_fd);

    /* 清除栈上密钥材料 */
    OPENSSL_cleanse(encrypt_key, sizeof(encrypt_key));
    OPENSSL_cleanse(auth_key, sizeof(auth_key));

    log_info("server: 已退出");
    return 0;
}
