#ifndef ANTIANALYSISPROOFSAMPLE_COMMON_H
#define ANTIANALYSISPROOFSAMPLE_COMMON_H

#include <android/log.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// log functions
#ifndef LOG_TAG
#define LOG_TAG "CommonLib_Native"
#endif
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG,__VA_ARGS__)

// general defines
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
static const char *PROC_TASK_MEM = "/proc/self/task/%s/mem";
static const char *PROC_TASK_PAGEMAP = "/proc/self/task/%s/pagemap";
static const char *PROC_SELF_PAGEMAP = "/proc/self/pagemap";
static const char *PROC_SELF_MEM = "/proc/self/mem";
static const char *PROC_COMM = "/proc/self/task/%s/comm";
static const char *PROC_SELF_STATUS = "/proc/self/status";
#define LIBC "libc.so"

#define CUSTOM_NATIVE_LIBS_NUM 6
static const char *CUSTOM_NATIVE_LIBS[CUSTOM_NATIVE_LIBS_NUM] = {
        "libhookdetector.so",
        "libdebuggerdetector.so",
        "libemulatordetector.so",
        "librootdetector.so",
        "libvirtualizationdetector.so",
        "libmemorytamperingdetector.so"
};


ssize_t readLine(int fd, char *buf, unsigned int max_len);

void rstrip(char *line);

#ifdef __cplusplus
}
#endif

#endif //ANTIANALYSISPROOFSAMPLE_COMMON_H
