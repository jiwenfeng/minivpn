/*
 * MiniVPN - 帧协议 + AES-256-GCM 加解密 + HKDF + 抗重放
 *
 * 帧格式: [Nonce:12B][加密区: Type:1B | Len:2B | Payload | Padding][Tag:16B]
 * 加密区使用 AES-256-GCM, Nonce = 8B递增计数器 + 4B随机
 */

#ifndef MINIVPN_PROTOCOL_H
#define MINIVPN_PROTOCOL_H

#include <stdint.h>
#include <openssl/evp.h>

/* 帧类型 */
#define FRAME_DATA  0x01
#define FRAME_PING  0x02
#define FRAME_PONG  0x03
#define FRAME_AUTH  0x04
#define FRAME_OK    0x05

/* 协议常量 */
#define NONCE_SIZE      12      /* AES-GCM nonce 长度 */
#define TAG_SIZE        16      /* AES-GCM tag 长度 */
#define KEY_SIZE        32      /* AES-256 密钥长度 */
#define MAX_PAYLOAD     1400    /* 最大负载长度 */
#define MAX_PADDING     255     /* 最大随机填充长度 */
#define FRAME_HEADER    3       /* Type:1B + Len:2B */
#define AUTH_NONCE_SIZE 32      /* AUTH 帧的 nonce 长度 */
#define HMAC_SIZE       32      /* HMAC-SHA256 输出长度 */
#define AUTH_TS_SIZE    8       /* AUTH 帧中时间戳 (uint64_t 大端) */

/* 最大帧大小 = Nonce + Type + Len + MaxPayload + MaxPadding + Tag */
#define MAX_FRAME_SIZE  (NONCE_SIZE + FRAME_HEADER + MAX_PAYLOAD + MAX_PADDING + TAG_SIZE)

/* 抗重放滑动窗口大小 (位数)，覆盖最近 2048 个 nonce */
#define REPLAY_WINDOW_SIZE  2048

/* AUTH 帧时间戳容忍范围 (秒) */
#define AUTH_TIME_TOLERANCE 300

/* 随机缓冲区大小 (4KB) */
#define RAND_BUF_SIZE  4096

/*
 * 抗重放滑动窗口
 * 使用 nonce 前 8 字节(计数器部分) 作为序列号
 */
struct replay_window {
    uint64_t max_seq;                                          /* 收到的最大序列号 */
    uint64_t bitmap[REPLAY_WINDOW_SIZE / 64];                  /* 位图 */
};

/*
 * 加密上下文 (每个 Worker 一个，避免反复分配)
 */
struct crypto_ctx {
    EVP_CIPHER_CTX *enc_ctx;     /* 加密上下文 */
    EVP_CIPHER_CTX *dec_ctx;     /* 解密上下文 */
    uint8_t encrypt_key[KEY_SIZE];
    uint8_t auth_key[KEY_SIZE];

    /* 随机数缓冲区 */
    uint8_t rand_buf[RAND_BUF_SIZE];
    int rand_offset;
};

/*
 * 全局初始化: 初始化 nonce 计数器 (在 main 中调用一次)
 * 线程安全：必须在创建线程之前调用
 *
 * @return  0成功, -1失败
 */
int protocol_init(void);

/*
 * 密钥派生：从预共享密钥通过 HKDF-SHA256 派生两个密钥
 *
 * @param secret       预共享密钥字符串
 * @param encrypt_key  输出: 加密密钥 (32字节)
 * @param auth_key     输出: 认证密钥 (32字节)
 * @return             0成功, -1失败
 */
int protocol_derive_keys(const char *secret,
                         uint8_t *encrypt_key, uint8_t *auth_key);

/*
 * 创建加密上下文 (每个 Worker 一个)
 *
 * @param encrypt_key  加密密钥 (32字节)
 * @param auth_key     认证密钥 (32字节)
 * @return             加密上下文, 失败返回 NULL
 */
struct crypto_ctx *crypto_ctx_new(const uint8_t *encrypt_key,
                                  const uint8_t *auth_key);

/*
 * 销毁加密上下文
 */
void crypto_ctx_free(struct crypto_ctx *ctx);

/*
 * 加密一帧: 明文 -> 密文帧 (Nonce + 加密数据 + Tag)
 * 加密区包含: Type(1B) + Len(2B) + Payload + 随机Padding
 *
 * @param ctx          加密上下文
 * @param type         帧类型 (FRAME_DATA 等)
 * @param payload      负载数据 (可为NULL当payload_len=0)
 * @param payload_len  负载长度 (0 ~ MAX_PAYLOAD)
 * @param out          输出缓冲区
 * @param out_size     输出缓冲区大小
 * @return             密文帧总长度, 失败返回-1
 */
int protocol_encrypt(struct crypto_ctx *ctx, uint8_t type,
                     const uint8_t *payload, int payload_len,
                     uint8_t *out, int out_size);

/*
 * 解密一帧: 密文帧 -> 明文
 *
 * @param ctx          加密上下文
 * @param in           密文帧数据
 * @param in_len       密文帧长度
 * @param type         输出: 帧类型
 * @param payload      输出: 负载数据缓冲区 (至少 MAX_PAYLOAD 字节)
 * @param payload_len  输出: 负载长度
 * @return             0成功, -1失败
 */
int protocol_decrypt(struct crypto_ctx *ctx,
                     const uint8_t *in, int in_len,
                     uint8_t *type, uint8_t *payload, int *payload_len);

/*
 * 生成AUTH帧内容: 时间戳(8B) + 随机nonce(32B) + HMAC-SHA256(auth_key, ts||nonce)
 *
 * @param ctx      加密上下文
 * @param out      输出缓冲区 (至少 AUTH_TS_SIZE + AUTH_NONCE_SIZE + HMAC_SIZE 字节)
 * @param out_len  输出: 数据长度
 * @return         0成功, -1失败
 */
int protocol_make_auth(struct crypto_ctx *ctx,
                       uint8_t *out, int *out_len);

/*
 * 验证AUTH帧: 验证时间戳+HMAC
 *
 * @param ctx       加密上下文
 * @param data      AUTH帧数据 (ts + nonce + hmac)
 * @param data_len  数据长度
 * @return          0验证通过, -1失败
 */
int protocol_verify_auth(struct crypto_ctx *ctx,
                         const uint8_t *data, int data_len);

/*
 * 初始化抗重放窗口
 */
void replay_window_init(struct replay_window *rw);

/*
 * 检查 nonce 是否为重放，如果不是则记录
 *
 * @param rw     抗重放窗口
 * @param nonce  12字节 nonce (前8字节为序列号)
 * @return       0=新帧(已记录), -1=重放(丢弃)
 */
int replay_window_check(struct replay_window *rw, const uint8_t *nonce);

#endif /* MINIVPN_PROTOCOL_H */
