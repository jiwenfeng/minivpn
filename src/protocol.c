/*
 * MiniVPN - 帧协议 + AES-256-GCM 加解密 + HKDF + 抗重放 实现
 *
 * 改进:
 * - 修复 nonce 初始化竞态 (protocol_init 在 main 中线程创建前调用)
 * - 添加抗重放滑动窗口
 * - 预分配 EVP_CIPHER_CTX 复用
 * - 随机数缓冲区，减少 RAND_bytes 调用频率
 * - AUTH 帧加入时间戳防重放
 * - OpenSSL 3.0+ 使用 EVP_MAC API，旧版本回退到 HMAC API
 *
 * 依赖: OpenSSL libcrypto (EVP 接口)
 */

#include "protocol.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 * OpenSSL 3.0+ 使用 EVP_MAC API（HMAC_* 已废弃）
 * 旧版本继续使用 HMAC_* API
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>
#define USE_EVP_MAC 1
#else
/* 抑制旧版 OpenSSL 中即将废弃的告警 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/hmac.h>
#define USE_EVP_MAC 0
#endif

/* ========== 全局 Nonce 计数器 ========== */

static uint64_t s_nonce_counter = 0;
static int s_nonce_initialized = 0;

int protocol_init(void)
{
    if (s_nonce_initialized) {
        return 0;
    }

    uint64_t random_start = 0;
    if (RAND_bytes((uint8_t *)&random_start, sizeof(random_start)) != 1) {
        random_start = (uint64_t)time(NULL) << 16;
        log_error("protocol_init: RAND_bytes 失败，使用时间戳回退");
    }
    s_nonce_counter = random_start;
    s_nonce_initialized = 1;
    log_debug("nonce 计数器初始化完成，起始值: 0x%016llx",
              (unsigned long long)random_start);
    return 0;
}

/*
 * 从随机缓冲区获取随机字节 (减少 RAND_bytes 系统调用)
 */
static int rand_buf_get(struct crypto_ctx *ctx, uint8_t *out, int len)
{
    if (!ctx || !out || len <= 0) return -1;

    while (len > 0) {
        int avail = RAND_BUF_SIZE - ctx->rand_offset;
        if (avail <= 0) {
            /* 缓冲区耗尽，重新填充 */
            if (RAND_bytes(ctx->rand_buf, RAND_BUF_SIZE) != 1) {
                log_error("rand_buf_get: RAND_bytes 失败");
                return -1;
            }
            ctx->rand_offset = 0;
            avail = RAND_BUF_SIZE;
        }

        int copy = len < avail ? len : avail;
        memcpy(out, ctx->rand_buf + ctx->rand_offset, copy);
        ctx->rand_offset += copy;
        out += copy;
        len -= copy;
    }
    return 0;
}

/*
 * 生成12字节 Nonce: 8字节递增计数器(大端) + 4字节填0
 */
static int generate_nonce(struct crypto_ctx *ctx, uint8_t *nonce)
{
    (void)ctx;
    uint64_t counter = __atomic_fetch_add(&s_nonce_counter, 1, __ATOMIC_RELAXED);

    /* 前8字节: 大端序计数器 */
    nonce[0] = (uint8_t)(counter >> 56);
    nonce[1] = (uint8_t)(counter >> 48);
    nonce[2] = (uint8_t)(counter >> 40);
    nonce[3] = (uint8_t)(counter >> 32);
    nonce[4] = (uint8_t)(counter >> 24);
    nonce[5] = (uint8_t)(counter >> 16);
    nonce[6] = (uint8_t)(counter >> 8);
    nonce[7] = (uint8_t)(counter);

    /* 后4字节: 填0 (唯一性已由计数器保证) */
    nonce[8] = 0;
    nonce[9] = 0;
    nonce[10] = 0;
    nonce[11] = 0;

    return 0;
}

/*
 * 从12字节 nonce 中提取序列号 (前8字节大端)
 */
static uint64_t nonce_to_seq(const uint8_t *nonce)
{
    return ((uint64_t)nonce[0] << 56) |
           ((uint64_t)nonce[1] << 48) |
           ((uint64_t)nonce[2] << 40) |
           ((uint64_t)nonce[3] << 32) |
           ((uint64_t)nonce[4] << 24) |
           ((uint64_t)nonce[5] << 16) |
           ((uint64_t)nonce[6] << 8)  |
           ((uint64_t)nonce[7]);
}

/* ========== 抗重放滑动窗口 ========== */

void replay_window_init(struct replay_window *rw)
{
    if (!rw) return;
    rw->max_seq = 0;
    memset(rw->bitmap, 0, sizeof(rw->bitmap));
}

int replay_window_check(struct replay_window *rw, const uint8_t *nonce)
{
    if (!rw || !nonce) return -1;

    uint64_t seq = nonce_to_seq(nonce);
    if (seq == 0) return -1;

    /* 读取当前 max_seq */
    uint64_t cur_max = __atomic_load_n(&rw->max_seq, __ATOMIC_ACQUIRE);

    if (seq > cur_max) {
        /* 尝试 CAS 更新 max_seq */
        while (seq > cur_max) {
            if (__atomic_compare_exchange_n(&rw->max_seq, &cur_max, seq,
                                            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                /* 成功更新 max_seq，清除新区间的位 */
                uint64_t diff = seq - cur_max;
                if (diff >= REPLAY_WINDOW_SIZE) {
                    /* 差距太大，清空整个窗口 */
                    for (int i = 0; i < REPLAY_WINDOW_SIZE / 64; i++) {
                        __atomic_store_n(&rw->bitmap[i], 0, __ATOMIC_RELAXED);
                    }
                } else {
                    for (uint64_t i = cur_max + 1; i <= seq; i++) {
                        uint64_t idx = i % REPLAY_WINDOW_SIZE;
                        uint64_t mask = 1ULL << (idx % 64);
                        __atomic_fetch_and(&rw->bitmap[idx / 64], ~mask, __ATOMIC_RELAXED);
                    }
                }
                break;
            }
            /* CAS 失败，cur_max 已更新，重新检查 */
        }
    } else if (cur_max - seq >= REPLAY_WINDOW_SIZE) {
        /* 太旧，超出窗口 */
        return -1;
    }

    /* 原子 test-and-set 位图 */
    uint64_t idx = seq % REPLAY_WINDOW_SIZE;
    uint64_t mask = 1ULL << (idx % 64);
    uint64_t old = __atomic_fetch_or(&rw->bitmap[idx / 64], mask, __ATOMIC_ACQ_REL);
    if (old & mask) {
        /* 已经收到过 */
        return -1;
    }

    return 0;
}

/* ========== HMAC 兼容层 ========== */

#if USE_EVP_MAC

/*
 * 一次性 HMAC-SHA256 计算（OpenSSL 3.0+ EVP_MAC API）
 * 返回 0 成功，-1 失败
 */
static int hmac_sha256_oneshot(const uint8_t *key, int key_len,
                               const uint8_t *data, int data_len,
                               uint8_t *out, unsigned int *out_len)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        log_error("hmac_sha256_oneshot: EVP_MAC_fetch 失败");
        return -1;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        log_error("hmac_sha256_oneshot: EVP_MAC_CTX_new 失败");
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_END
    };

    int ret = -1;
    if (EVP_MAC_init(ctx, key, (size_t)key_len, params) == 1 &&
        EVP_MAC_update(ctx, data, (size_t)data_len) == 1) {
        size_t mac_len = HMAC_SIZE;
        if (EVP_MAC_final(ctx, out, &mac_len, HMAC_SIZE) == 1) {
            *out_len = (unsigned int)mac_len;
            ret = 0;
        }
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

/*
 * 复用预分配 HMAC 上下文的版本（用于 protocol_make_auth / protocol_verify_auth）
 */
static int hmac_sha256_ctx(struct crypto_ctx *cctx,
                           const uint8_t *data, int data_len,
                           uint8_t *out, unsigned int *out_len)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_END
    };

    if (EVP_MAC_init(cctx->hmac_ctx, cctx->auth_key, KEY_SIZE, params) != 1)
        return -1;
    if (EVP_MAC_update(cctx->hmac_ctx, data, (size_t)data_len) != 1)
        return -1;
    size_t mac_len = HMAC_SIZE;
    if (EVP_MAC_final(cctx->hmac_ctx, out, &mac_len, HMAC_SIZE) != 1)
        return -1;
    *out_len = (unsigned int)mac_len;
    return 0;
}

#else /* Legacy HMAC API */

static int hmac_sha256_oneshot(const uint8_t *key, int key_len,
                               const uint8_t *data, int data_len,
                               uint8_t *out, unsigned int *out_len)
{
    *out_len = HMAC_SIZE;
    if (HMAC(EVP_sha256(), key, key_len, data, data_len,
             out, out_len) == NULL) {
        return -1;
    }
    return 0;
}

#endif /* USE_EVP_MAC */

/* ========== HKDF-SHA256 ========== */

/*
 * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 */
static int hkdf_extract(const uint8_t *salt, int salt_len,
                        const uint8_t *ikm, int ikm_len,
                        uint8_t *prk)
{
    unsigned int out_len = HMAC_SIZE;
    if (hmac_sha256_oneshot(salt, salt_len, ikm, ikm_len,
                            prk, &out_len) != 0) {
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

#if USE_EVP_MAC

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        log_error("HKDF-Expand: EVP_MAC_fetch 失败");
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_END
    };

    /* 创建一个 EVP_MAC_CTX，循环内复用 */
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(mac);
    if (!hmac_ctx) {
        EVP_MAC_free(mac);
        log_error("HKDF-Expand: EVP_MAC_CTX_new 失败");
        return -1;
    }

    for (int i = 1; i <= n; i++) {
        uint8_t t_cur[HMAC_SIZE];

        if (EVP_MAC_init(hmac_ctx, (const unsigned char *)prk,
                         (size_t)prk_len, params) != 1) {
            EVP_MAC_CTX_free(hmac_ctx);
            EVP_MAC_free(mac);
            return -1;
        }
        if (t_prev_len > 0) {
            EVP_MAC_update(hmac_ctx, t_prev, (size_t)t_prev_len);
        }
        if (info_len > 0) {
            EVP_MAC_update(hmac_ctx, info, (size_t)info_len);
        }
        uint8_t counter = (uint8_t)i;
        EVP_MAC_update(hmac_ctx, &counter, 1);

        size_t mac_len = HMAC_SIZE;
        if (EVP_MAC_final(hmac_ctx, t_cur, &mac_len, HMAC_SIZE) != 1) {
            EVP_MAC_CTX_free(hmac_ctx);
            EVP_MAC_free(mac);
            return -1;
        }

        int copy_len = okm_len - offset;
        if (copy_len > HMAC_SIZE) copy_len = HMAC_SIZE;
        memcpy(okm + offset, t_cur, copy_len);
        offset += copy_len;

        memcpy(t_prev, t_cur, HMAC_SIZE);
        t_prev_len = HMAC_SIZE;
    }

    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(mac);

#else /* Legacy HMAC API */

    /* 在循环外分配一次 HMAC_CTX，循环内复用 */
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) {
        log_error("HKDF-Expand: HMAC_CTX_new 失败");
        return -1;
    }

    for (int i = 1; i <= n; i++) {
        unsigned int out_len = HMAC_SIZE;
        uint8_t t_cur[HMAC_SIZE];

        /* 构建 HMAC 输入: T(i-1) || info || i */
        if (HMAC_Init_ex(hmac_ctx, prk, prk_len, EVP_sha256(), NULL) != 1) {
            HMAC_CTX_free(hmac_ctx);
            return -1;
        }
        if (t_prev_len > 0) {
            HMAC_Update(hmac_ctx, t_prev, t_prev_len);
        }
        if (info_len > 0) {
            HMAC_Update(hmac_ctx, info, info_len);
        }
        uint8_t counter = (uint8_t)i;
        HMAC_Update(hmac_ctx, &counter, 1);
        HMAC_Final(hmac_ctx, t_cur, &out_len);

        int copy_len = okm_len - offset;
        if (copy_len > HMAC_SIZE) copy_len = HMAC_SIZE;
        memcpy(okm + offset, t_cur, copy_len);
        offset += copy_len;

        memcpy(t_prev, t_cur, HMAC_SIZE);
        t_prev_len = HMAC_SIZE;
    }

    HMAC_CTX_free(hmac_ctx);

#endif /* USE_EVP_MAC */

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

struct crypto_ctx *crypto_ctx_new(const uint8_t *encrypt_key,
                                  const uint8_t *auth_key)
{
    if (!encrypt_key || !auth_key) return NULL;

    struct crypto_ctx *ctx = calloc(1, sizeof(struct crypto_ctx));
    if (!ctx) return NULL;

    memcpy(ctx->encrypt_key, encrypt_key, KEY_SIZE);
    memcpy(ctx->auth_key, auth_key, KEY_SIZE);

    ctx->enc_ctx = EVP_CIPHER_CTX_new();
    ctx->dec_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->enc_ctx || !ctx->dec_ctx) {
        crypto_ctx_free(ctx);
        return NULL;
    }

    /* 预初始化 cipher 和 IV 长度，避免每帧重复设置 */
    EVP_EncryptInit_ex(ctx->enc_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx->enc_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
    EVP_DecryptInit_ex(ctx->dec_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx->dec_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);

    /* 预填充随机缓冲区 */
    if (RAND_bytes(ctx->rand_buf, RAND_BUF_SIZE) != 1) {
        log_error("crypto_ctx_new: 初始化随机缓冲区失败");
        crypto_ctx_free(ctx);
        return NULL;
    }
    ctx->rand_offset = 0;

#if USE_EVP_MAC
    ctx->hmac_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!ctx->hmac_mac) {
        log_error("crypto_ctx_new: EVP_MAC_fetch 失败");
        crypto_ctx_free(ctx);
        return NULL;
    }
    ctx->hmac_ctx = EVP_MAC_CTX_new(ctx->hmac_mac);
    if (!ctx->hmac_ctx) {
        log_error("crypto_ctx_new: EVP_MAC_CTX_new 失败");
        crypto_ctx_free(ctx);
        return NULL;
    }
#endif

    return ctx;
}

void crypto_ctx_free(struct crypto_ctx *ctx)
{
    if (!ctx) return;
    if (ctx->enc_ctx) EVP_CIPHER_CTX_free(ctx->enc_ctx);
    if (ctx->dec_ctx) EVP_CIPHER_CTX_free(ctx->dec_ctx);
#if USE_EVP_MAC
    if (ctx->hmac_ctx) EVP_MAC_CTX_free(ctx->hmac_ctx);
    if (ctx->hmac_mac) EVP_MAC_free(ctx->hmac_mac);
#endif
    OPENSSL_cleanse(ctx->encrypt_key, KEY_SIZE);
    OPENSSL_cleanse(ctx->auth_key, KEY_SIZE);
    OPENSSL_cleanse(ctx->rand_buf, RAND_BUF_SIZE);
    free(ctx);
}

int protocol_encrypt(struct crypto_ctx *ctx, uint8_t type,
                     const uint8_t *payload, int payload_len,
                     uint8_t *out, int out_size)
{
    if (!ctx || !out) {
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

    /* 生成随机 padding 长度 */
    uint8_t pad_len_byte;
    if (rand_buf_get(ctx, &pad_len_byte, 1) != 0) {
        return -1;
    }
    int pad_len;
    if (type == FRAME_DATA) {
        pad_len = (int)(pad_len_byte & 0x0F);  /* 0~15 字节 */
    } else {
        pad_len = (int)pad_len_byte;  /* 0~255 字节 */
    }

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
    if (generate_nonce(ctx, nonce) != 0) {
        return -1;
    }

    /* 2. 构建明文（使用栈缓冲区避免 malloc，最大 3 + 1400 + 255 = 1658） */
    uint8_t plaintext[FRAME_HEADER + MAX_PAYLOAD + MAX_PADDING];
    if (plaintext_len > (int)sizeof(plaintext)) {
        log_error("protocol_encrypt: 明文长度超出栈缓冲区: %d", plaintext_len);
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
        if (rand_buf_get(ctx, plaintext + FRAME_HEADER + payload_len, pad_len) != 0) {
            return -1;
        }
    }

    /* 3. AES-256-GCM 加密 (复用预分配的 enc_ctx) */
    uint8_t *ciphertext = out + NONCE_SIZE;
    uint8_t *tag = out + NONCE_SIZE + plaintext_len;

    EVP_CIPHER_CTX *enc = ctx->enc_ctx;
    int ret = -1;
    int len = 0;

    do {
        if (EVP_EncryptInit_ex(enc, NULL, NULL, ctx->encrypt_key, nonce) != 1)
            break;
        if (EVP_EncryptUpdate(enc, ciphertext, &len, plaintext, plaintext_len) != 1)
            break;
        if (EVP_EncryptFinal_ex(enc, ciphertext + len, &len) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
            break;

        ret = frame_len;
    } while (0);

    if (type != FRAME_DATA) {
        OPENSSL_cleanse(plaintext, plaintext_len);
    }

    if (ret < 0) {
        log_error("protocol_encrypt: AES-GCM 加密失败");
    }

    return ret;
}

int protocol_decrypt(struct crypto_ctx *ctx,
                     const uint8_t *in, int in_len,
                     uint8_t *type, uint8_t *payload, int *payload_len)
{
    if (!ctx || !in || !type || !payload || !payload_len) {
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

    /* AES-256-GCM 解密（使用栈缓冲区避免热路径 malloc） */
    uint8_t plaintext[FRAME_HEADER + MAX_PAYLOAD + MAX_PADDING];
    if (ciphertext_len > (int)sizeof(plaintext)) {
        log_error("protocol_decrypt: 密文长度超出栈缓冲区: %d", ciphertext_len);
        return -1;
    }

    EVP_CIPHER_CTX *dec = ctx->dec_ctx;
    int ret = -1;
    int len = 0;

    do {
        if (EVP_DecryptInit_ex(dec, NULL, NULL, ctx->encrypt_key, nonce) != 1)
            break;
        if (EVP_DecryptUpdate(dec, plaintext, &len, ciphertext, ciphertext_len) != 1)
            break;
        /* 设置 Tag 并验证 */
        if (EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                (void *)tag) != 1)
            break;
        if (EVP_DecryptFinal_ex(dec, plaintext + len, &len) != 1) {
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

    if (ret == 0 && *type != FRAME_DATA) {
        OPENSSL_cleanse(plaintext, ciphertext_len);
    }

    return ret;
}

int protocol_make_auth(struct crypto_ctx *ctx,
                       uint8_t *out, int *out_len)
{
    if (!ctx || !out || !out_len) {
        log_error("protocol_make_auth: 参数为空");
        return -1;
    }

    /* 写入时间戳 (8字节大端) */
    uint64_t ts = (uint64_t)time(NULL);
    out[0] = (uint8_t)(ts >> 56);
    out[1] = (uint8_t)(ts >> 48);
    out[2] = (uint8_t)(ts >> 40);
    out[3] = (uint8_t)(ts >> 32);
    out[4] = (uint8_t)(ts >> 24);
    out[5] = (uint8_t)(ts >> 16);
    out[6] = (uint8_t)(ts >> 8);
    out[7] = (uint8_t)(ts);

    /* 生成 32 字节随机 nonce */
    if (rand_buf_get(ctx, out + AUTH_TS_SIZE, AUTH_NONCE_SIZE) != 0) {
        log_error("protocol_make_auth: 生成 nonce 失败");
        return -1;
    }

    /* HMAC-SHA256(auth_key, ts || nonce) */
    unsigned int hmac_len = HMAC_SIZE;
    int data_len = AUTH_TS_SIZE + AUTH_NONCE_SIZE;
#if USE_EVP_MAC
    if (hmac_sha256_ctx(ctx, out, data_len,
                        out + data_len, &hmac_len) != 0) {
#else
    if (hmac_sha256_oneshot(ctx->auth_key, KEY_SIZE,
                            out, data_len,
                            out + data_len, &hmac_len) != 0) {
#endif
        log_error("protocol_make_auth: HMAC 计算失败");
        return -1;
    }

    *out_len = AUTH_TS_SIZE + AUTH_NONCE_SIZE + HMAC_SIZE;
    return 0;
}

int protocol_verify_auth(struct crypto_ctx *ctx,
                         const uint8_t *data, int data_len)
{
    if (!ctx || !data) {
        log_error("protocol_verify_auth: 参数为空");
        return -1;
    }

    int expected_len = AUTH_TS_SIZE + AUTH_NONCE_SIZE + HMAC_SIZE;
    if (data_len != expected_len) {
        log_error("protocol_verify_auth: 数据长度错误: %d != %d",
                  data_len, expected_len);
        return -1;
    }

    /* 验证时间戳 */
    uint64_t ts = ((uint64_t)data[0] << 56) |
                  ((uint64_t)data[1] << 48) |
                  ((uint64_t)data[2] << 40) |
                  ((uint64_t)data[3] << 32) |
                  ((uint64_t)data[4] << 24) |
                  ((uint64_t)data[5] << 16) |
                  ((uint64_t)data[6] << 8)  |
                  ((uint64_t)data[7]);

    uint64_t now = (uint64_t)time(NULL);
    int64_t diff = (int64_t)(now - ts);
    if (diff < -AUTH_TIME_TOLERANCE || diff > AUTH_TIME_TOLERANCE) {
        log_error("protocol_verify_auth: 时间戳超出范围: diff=%lld 秒",
                  (long long)diff);
        return -1;
    }

    /* 重新计算 HMAC */
    int hmac_input_len = AUTH_TS_SIZE + AUTH_NONCE_SIZE;
    uint8_t expected_hmac[HMAC_SIZE];
    unsigned int hmac_len = HMAC_SIZE;
#if USE_EVP_MAC
    if (hmac_sha256_ctx(ctx, data, hmac_input_len,
                        expected_hmac, &hmac_len) != 0) {
#else
    if (hmac_sha256_oneshot(ctx->auth_key, KEY_SIZE,
                            data, hmac_input_len,
                            expected_hmac, &hmac_len) != 0) {
#endif
        log_error("protocol_verify_auth: HMAC 计算失败");
        return -1;
    }

    /* 常量时间比较，防止时序攻击 */
    if (CRYPTO_memcmp(expected_hmac, data + hmac_input_len, HMAC_SIZE) != 0) {
        log_error("protocol_verify_auth: HMAC 验证失败");
        return -1;
    }

    log_debug("AUTH 验证通过 (时间差: %lld 秒)", (long long)diff);
    return 0;
}
