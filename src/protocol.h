/*
 * MiniVPN - 帧协议 + AES-256-GCM 加解密 + HKDF
 *
 * 帧格式: [Nonce:12B][加密区: Type:1B | Len:2B | Payload | Padding][Tag:16B]
 * 加密区使用 AES-256-GCM, Nonce = 8B递增计数器 + 4B随机
 */

#ifndef MINIVPN_PROTOCOL_H
#define MINIVPN_PROTOCOL_H

#include <stdint.h>

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

/* 最大帧大小 = Nonce + Type + Len + MaxPayload + MaxPadding + Tag */
#define MAX_FRAME_SIZE  (NONCE_SIZE + FRAME_HEADER + MAX_PAYLOAD + MAX_PADDING + TAG_SIZE)

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
 * 加密一帧: 明文 -> 密文帧 (Nonce + 加密数据 + Tag)
 * 加密区包含: Type(1B) + Len(2B) + Payload + 随机Padding
 *
 * @param encrypt_key  加密密钥 (32字节)
 * @param type         帧类型 (FRAME_DATA 等)
 * @param payload      负载数据 (可为NULL当payload_len=0)
 * @param payload_len  负载长度 (0 ~ MAX_PAYLOAD)
 * @param out          输出缓冲区
 * @param out_size     输出缓冲区大小
 * @return             密文帧总长度, 失败返回-1
 */
int protocol_encrypt(const uint8_t *encrypt_key, uint8_t type,
                     const uint8_t *payload, int payload_len,
                     uint8_t *out, int out_size);

/*
 * 解密一帧: 密文帧 -> 明文
 *
 * @param encrypt_key  加密密钥 (32字节)
 * @param in           密文帧数据
 * @param in_len       密文帧长度
 * @param type         输出: 帧类型
 * @param payload      输出: 负载数据缓冲区 (至少 MAX_PAYLOAD 字节)
 * @param payload_len  输出: 负载长度
 * @return             0成功, -1失败
 */
int protocol_decrypt(const uint8_t *encrypt_key,
                     const uint8_t *in, int in_len,
                     uint8_t *type, uint8_t *payload, int *payload_len);

/*
 * 生成AUTH帧内容: 随机nonce(32B) + HMAC-SHA256(auth_key, nonce)
 *
 * @param auth_key  认证密钥 (32字节)
 * @param out       输出缓冲区 (至少 AUTH_NONCE_SIZE + HMAC_SIZE 字节)
 * @param out_len   输出: 数据长度
 * @return          0成功, -1失败
 */
int protocol_make_auth(const uint8_t *auth_key,
                       uint8_t *out, int *out_len);

/*
 * 验证AUTH帧: 验证 HMAC-SHA256(auth_key, nonce) 是否匹配
 *
 * @param auth_key  认证密钥 (32字节)
 * @param data      AUTH帧数据 (nonce + hmac)
 * @param data_len  数据长度
 * @return          0验证通过, -1失败
 */
int protocol_verify_auth(const uint8_t *auth_key,
                         const uint8_t *data, int data_len);

#endif /* MINIVPN_PROTOCOL_H */
