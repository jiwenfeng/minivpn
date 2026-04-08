/*
 * MiniVPN - 线程安全日志宏
 *
 * 支持3个级别: ERROR(0), INFO(1), DEBUG(2)
 * 通过全局变量 g_log_level 控制输出级别
 * 格式: [时间][级别] 消息
 *
 * 使用 flockfile/funlockfile 确保多线程日志输出不交错
 */

#ifndef MINIVPN_LOG_H
#define MINIVPN_LOG_H

#include <stdio.h>
#include <time.h>

/* 日志级别 */
#define LOG_ERROR 0
#define LOG_INFO  1
#define LOG_DEBUG 2

/* 全局日志级别，在 main.c 中定义 */
extern int g_log_level;

/* 获取当前时间字符串的辅助宏 */
#define LOG_TIME_BUF_SIZE 20

/*
 * 线程安全日志输出宏
 * flockfile/funlockfile 确保单条日志的时间戳和内容不被其他线程打断
 */
#define LOG_PRINT(level_str, ...)                                        \
    do {                                                                 \
        time_t _log_t = time(NULL);                                      \
        struct tm _log_tm;                                               \
        char _log_buf[LOG_TIME_BUF_SIZE];                                \
        localtime_r(&_log_t, &_log_tm);                                  \
        strftime(_log_buf, sizeof(_log_buf), "%Y-%m-%d %H:%M:%S",       \
                 &_log_tm);                                              \
        flockfile(stderr);                                               \
        fprintf(stderr, "[%s][%s] ", _log_buf, level_str);               \
        fprintf(stderr, __VA_ARGS__);                                    \
        fprintf(stderr, "\n");                                           \
        fflush_unlocked(stderr);                                         \
        funlockfile(stderr);                                             \
    } while (0)

/* 各级别日志宏 */
#define log_error(...)                                                   \
    do {                                                                 \
        if (g_log_level >= LOG_ERROR)                                    \
            LOG_PRINT("ERROR", __VA_ARGS__);                             \
    } while (0)

#define log_info(...)                                                    \
    do {                                                                 \
        if (g_log_level >= LOG_INFO)                                     \
            LOG_PRINT("INFO ", __VA_ARGS__);                             \
    } while (0)

#define log_debug(...)                                                   \
    do {                                                                 \
        if (g_log_level >= LOG_DEBUG)                                    \
            LOG_PRINT("DEBUG", __VA_ARGS__);                             \
    } while (0)

#endif /* MINIVPN_LOG_H */
