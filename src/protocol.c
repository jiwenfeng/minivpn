/*
 * MiniVPN - 帧协议 + AES-256-GCM 加解密 + HKDF 实现
 *
 * 依赖: OpenSSL libcrypto (EVP 接口)
 */

#include "protocol.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ========== 内部: Nonce 计数器 ========== */

/* 全局递增计数器 (每个进程唯一)，用于 Nonce 前8字节 */
static uint64_t s_nonce_counter = 0;
static int s_nonce_initialized = 0;

/*
 * 初始化 nonce 计数器为随机起始值，防止进程重启后 nonce 重用
 */
static void nonce_init_once(void)
{
    if (__sync_bool_compare_and_swap(&s_nonce_initialized, 0, 1)) {
        uint64_t random_start = 0;
        if (RAND_bytes((uint8_t *)&random_start, sizeof(random_start)) != 1) {
            /* 回退：使用时间戳作为起始值 */
            random_start = (uint64_t)time(NULL) << 16;
            log_error("nonce_init_once: RAND_bytes 失败，使用时间戳回退");
        }
        s_nonce_counter = random_start;
        log_debug("nonce 计数器初始化完成，起始值: 0x%016llx",
                  (unsigned long long)random_start);
    }
}

/*
 * 生成12字节 Nonce: 8字节递增计数器(大端) + 4字节随机
 */
static int generate_nonce(uint8_t *nonce)
{
    nonce_init_once();
    uint64_t counter = __sync_fetch_and_add(&s_nonce_counter, 1);

    /* 前8字节: 大端序计数器 */
    nonce[0] = (uint8_t)(counter >> 56);
    nonce[1] = (uint8_t)(counter >> 48);
    nonce[2] = (uint8_t)(counter >> 40);
    nonce[3] = (uint8_t)(counter >> 32);
    nonce[4] = (uint8_t)(counter >> 24);
    nonce[5] = (uint8_t)(counter >> 16);
    nonce[6] = (uint8_t)(counter >> 8);
    nonce[7] = (uint8_t)(counter);

    /* 后4字节: 随机 */
    if (RAND_bytes(nonce + 8, 4) != 1) {
        log_error("RAND_bytes 生成 nonce 随机部分失败");
        return -1;
    }

    return 0;
}

/* ========== HKDF-SHA256 手动实现 ========== */

/*
 * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 */
static int hkdf_extract(const uint8_t *salt, int salt_len,
                        const uint8_t *ikm, int ikm_len,
                        uint8_t *prk)
{
    unsigned int out_len = HMAC_SIZE;
    if (HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len,
             prk, &out_len) == NULL) {
        log_error("HKDF-Extract: HMAC 失败");
        return -1;
    }
    return 0;
}

/*
 * HKDF-Expand: OKM = T(1) || T(2) || ...
 *   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
 */
static int hkdf_expand(const uint8_t *prk, int prk_len,
                       const uint8_t *info, int info_len,
                       uint8_t *okm, int okm_len)
{
    int n = (okm_len + HMAC_SIZE - 1) / HMAC_SIZE;
    if (n > 255) {
        log_error("HKDF-Expand: 请求输出过长");
        return -1;
    }

    uint8_t t_prev[HMAC_SIZE];
    int t_prev_len = 0;
    int offset = 0;

    for (int i = 1; i <= n; i++) {
        unsigned int out_len = HMAC_SIZE;
        uint8_t t_cur[HMAC_SIZE];

        /* 构建 HMAC 输入: T(i-1) || info || i */
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) {
            log_error("HKDF-Expand: HMAC_CTX_new 失败");
            return -1;
        }

        if (HMAC_Init_ex(ctx, prk, prk_len, EVP_sha256(), NULL) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        if (t_prev_len > 0) {
            HMAC_Update(ctx, t_prev, t_prev_len);
        }
        if (info_len > 0) {
            HMAC_Update(ctx, info, info_len);
        }
        uint8_t counter = (uint8_t)i;
        HMAC_Update(ctx, &counter, 1);
        HMAC_Final(ctx, t_cur, &out_len);
        HMAC_CTX_free(ctx);

        int copy_len = okm_len - offset;
        if (copy_len > HMAC_SIZE) copy_len = HMAC_SIZE;
        memcpy(okm + offset, t_cur, copy_len);
        offset += copy_len;

        memcpy(t_prev, t_cur, HMAC_SIZE);
        t_prev_len = HMAC_SIZE;
    }

    return 0;
}

/* ========== 公开接口 ========== */

int protocol_derive_keys(const char *secret,
                         uint8_t *encrypt_key, uint8_t *auth_key)
{
    if (!secret || !encrypt_key || !auth_key) {
        log_error("protocol_derive_keys: 参数为空");
        return -1;
    }

    /* salt 使用固定值 (可公开) */
    const uint8_t salt[] = "MiniVPN-HKDF-Salt-v1";
    int salt_len = (int)(sizeof(salt) - 1);

    /* Step 1: Extract */
    uint8_t prk[HMAC_SIZE];
    if (hkdf_extract(salt, salt_len,
                     (const uint8_t *)secret, (int)strlen(secret),
                     prk) != 0) {
        return -1;
    }

    /* Step 2: Expand - 派生 64 字节 (encrypt_key 32B + auth_key 32B) */
    uint8_t okm[KEY_SIZE * 2];
    const uint8_t info[] = "MiniVPN-Keys-v1";
    int info_len = (int)(sizeof(info) - 1);

    if (hkdf_expand(prk, HMAC_SIZE, info, info_len,
                    okm, KEY_SIZE * 2) != 0) {
        return -1;
    }

    memcpy(encrypt_key, okm, KEY_SIZE);
    memcpy(auth_key, okm + KEY_SIZE, KEY_SIZE);

    /* 清除中间敏感数据 */
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(okm, sizeof(okm));

    log_debug("密钥派生完成");
    return 0;
}

int protocol_encrypt(const uint8_t *encrypt_key, uint8_t type,
                     const uint8_t *payload, int payload_len,
                     uint8_t *out, int out_size)
{
    if (!encrypt_key || !out) {
        log_error("protocol_encrypt: 参数为空");
        return -1;
    }
    if (payload_len < 0 || payload_len > MAX_PAYLOAD) {
        log_error("protocol_encrypt: payload 长度无效: %d", payload_len);
        return -1;
    }
    if (payload_len > 0 && !payload) {
        log_error("protocol_encrypt: payload 非空但指针为空");
        return -1;
    }

    /* 生成随机 padding 长度 (0~255) */
    uint8_t pad_len_byte;
    if (RAND_bytes(&pad_len_byte, 1) != 1) {
        log_error("protocol_encrypt: 生成随机 padding 长度失败");
        return -1;
    }
    int pad_len = (int)pad_len_byte;

    /* 明文 = Type(1B) + Len(2B) + Payload + Padding */
    int plaintext_len = FRAME_HEADER + payload_len + pad_len;
    int frame_len = NONCE_SIZE + plaintext_len + TAG_SIZE;

    if (frame_len > out_size) {
        log_error("protocol_encrypt: 输出缓冲区不足: 需要 %d, 有 %d",
                  frame_len, out_size);
        return -1;
    }

    /* 1. 生成 Nonce 并写入输出头部 */
    uint8_t *nonce = out;
    if (generate_nonce(nonce) != 0) {
        return -1;
    }

    /* 2. 构建明文 */
    uint8_t *plaintext = (uint8_t *)malloc(plaintext_len);
    if (!plaintext) {
        log_error("protocol_encrypt: malloc 失败");
        return -1;
    }

    plaintext[0] = type;
    plaintext[1] = (uint8_t)(payload_len >> 8);   /* Len 高字节 (大端) */
    plaintext[2] = (uint8_t)(payload_len & 0xFF);  /* Len 低字节 */

    if (payload_len > 0) {
        memcpy(plaintext + FRAME_HEADER, payload, payload_len);
    }

    /* 填充随机 padding */
    if (pad_len > 0) {
        if (RAND_bytes(plaintext + FRAME_HEADER + payload_len, pad_len) != 1) {
            log_error("protocol_encrypt: 生成 padding 失败");
            free(plaintext);
            return -1;
        }
    }

    /* 3. AES-256-GCM 加密 */
    uint8_t *ciphertext = out + NONCE_SIZE;
    uint8_t *tag = out + NONCE_SIZE + plaintext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("protocol_encrypt: EVP_CIPHER_CTX_new 失败");
        free(plaintext);
        return -1;
    }

    int ret = -1;
    int len = 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, encrypt_key, nonce) != 1)
            break;
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
            break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
            break;

        ret = frame_len;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plaintext, plaintext_len);
    free(plaintext);

    if (ret < 0) {
        log_error("protocol_encrypt: AES-GCM 加密失败");
    }

    return ret;
}

int protocol_decrypt(const uint8_t *encrypt_key,
                     const uint8_t *in, int in_len,
                     uint8_t *type, uint8_t *payload, int *payload_len)
{
    if (!encrypt_key || !in || !type || !payload || !payload_len) {
        log_error("protocol_decrypt: 参数为空");
        return -1;
    }

    /* 最小帧 = Nonce(12) + Type(1) + Len(2) + Tag(16) = 31 */
    int min_frame = NONCE_SIZE + FRAME_HEADER + TAG_SIZE;
    if (in_len < min_frame) {
        log_error("protocol_decrypt: 帧太短: %d < %d", in_len, min_frame);
        return -1;
    }

    const uint8_t *nonce = in;
    int ciphertext_len = in_len - NONCE_SIZE - TAG_SIZE;
    const uint8_t *ciphertext = in + NONCE_SIZE;
    const uint8_t *tag = in + NONCE_SIZE + ciphertext_len;

    /* AES-256-GCM 解密 */
    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_len);
    if (!plaintext) {
        log_error("protocol_decrypt: malloc 失败");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("protocol_decrypt: EVP_CIPHER_CTX_new 失败");
        free(plaintext);
        return -1;
    }

    int ret = -1;
    int len = 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, encrypt_key, nonce) != 1)
            break;
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
            break;
        /* 设置 Tag 并验证 */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                (void *)tag) != 1)
            break;
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            log_error("protocol_decrypt: GCM 认证失败 (数据被篡改?)");
            break;
        }

        /* 解析明文头部 */
        *type = plaintext[0];
        int plen = ((int)plaintext[1] << 8) | (int)plaintext[2];

        /* 验证 payload 长度合法性 */
        if (plen > MAX_PAYLOAD ||
            plen + FRAME_HEADER > ciphertext_len) {
            log_error("protocol_decrypt: payload 长度无效: %d", plen);
            break;
        }

        *payload_len = plen;
        if (plen > 0) {
            memcpy(payload, plaintext + FRAME_HEADER, plen);
        }

        ret = 0;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plaintext, ciphertext_len);
    free(plaintext);

    return ret;
}

int protocol_make_auth(const uint8_t *auth_key,
                       uint8_t *out, int *out_len)
{
    if (!auth_key || !out || !out_len) {
        log_error("protocol_make_auth: 参数为空");
        return -1;
    }

    /* 生成 32 字节随机 nonce */
    if (RAND_bytes(out, AUTH_NONCE_SIZE) != 1) {
        log_error("protocol_make_auth: 生成 nonce 失败");
        return -1;
    }

    /* HMAC-SHA256(auth_key, nonce) */
    unsigned int hmac_len = HMAC_SIZE;
    if (HMAC(EVP_sha256(), auth_key, KEY_SIZE,
             out, AUTH_NONCE_SIZE,
             out + AUTH_NONCE_SIZE, &hmac_len) == NULL) {
        log_error("protocol_make_auth: HMAC 计算失败");
        return -1;
    }

    *out_len = AUTH_NONCE_SIZE + HMAC_SIZE;
    return 0;
}

int protocol_verify_auth(const uint8_t *auth_key,
                         const uint8_t *data, int data_len)
{
    if (!auth_key || !data) {
        log_error("protocol_verify_auth: 参数为空");
        return -1;
    }

    int expected_len = AUTH_NONCE_SIZE + HMAC_SIZE;
    if (data_len != expected_len) {
        log_error("protocol_verify_auth: 数据长度错误: %d != %d",
                  data_len, expected_len);
        return -1;
    }

    /* 重新计算 HMAC */
    uint8_t expected_hmac[HMAC_SIZE];
    unsigned int hmac_len = HMAC_SIZE;
    if (HMAC(EVP_sha256(), auth_key, KEY_SIZE,
             data, AUTH_NONCE_SIZE,
             expected_hmac, &hmac_len) == NULL) {
        log_error("protocol_verify_auth: HMAC 计算失败");
        return -1;
    }

    /* 常量时间比较，防止时序攻击 */
    if (CRYPTO_memcmp(expected_hmac, data + AUTH_NONCE_SIZE, HMAC_SIZE) != 0) {
        log_error("protocol_verify_auth: HMAC 验证失败");
        return -1;
    }

    log_debug("AUTH 验证通过");
    return 0;
}
