#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <stdio.h>

#include "common/common.h"
#include "genuine/openat.h"

// Log macros
#define LOG_TAG "FileTamperingDetector_Native"

static inline size_t fill_dex2oat_cmdline(char v[]) {
    // dex2oat-cmdline
    static unsigned int m = 0;

    if (m == 0) {
        m = 13;
    } else if (m == 17) {
        m = 19;
    }

    v[0x0] = 'f';
    v[0x1] = 'f';
    v[0x2] = '|';
    v[0x3] = '7';
    v[0x4] = 'i';
    v[0x5] = 'f';
    v[0x6] = '|';
    v[0x7] = '$';
    v[0x8] = 'i';
    v[0x9] = 'f';
    v[0xa] = 'h';
    v[0xb] = 'l';
    v[0xc] = 'h';
    v[0xd] = 'l';
    v[0xe] = 'f';
    for (unsigned int i = 0; i < 0xf; ++i) {
        v[i] ^= ((i + 0xf) % m);
    }
    v[0xf] = '\0';
    return 0xf;
}

static inline size_t fill_dex_file(char v[]) {
    // --dex-file
    static unsigned int m = 0;

    if (m == 0) {
        m = 7;
    } else if (m == 11) {
        m = 13;
    }

    v[0x0] = '.';
    v[0x1] = ')';
    v[0x2] = 'a';
    v[0x3] = 'c';
    v[0x4] = 'x';
    v[0x5] = ',';
    v[0x6] = 'd';
    v[0x7] = 'j';
    v[0x8] = 'h';
    v[0x9] = '`';
    for (unsigned int i = 0; i < 0xa; ++i) {
        v[i] ^= ((i + 0xa) % m);
    }
    v[0xa] = '\0';
    return 0xa;
}

static inline bool isdex(const char *str) {
    const char *dot = strrchr(str, '.');
    return dot != nullptr
           && *++dot == 'd'
           && *++dot == 'e'
           && *++dot == 'x'
           && (*++dot == '\0' || *dot == '\r' || *dot == '\n');
}

static inline bool isodex(const char *str) {
    const char *dot = strrchr(str, '.');
    return dot != nullptr
           && *++dot == 'o'
           && *++dot == 'd'
           && *++dot == 'e'
           && *++dot == 'x'
           && (*++dot == '\0' || *dot == '\r' || *dot == '\n');
}

// Check the command to build the odex, verifying if it contains the --dex-file path variable
static inline bool checkOdex(const char *path) {
    size_t len;
    char *cmdline;
    char buffer[0x400], find[64];

    bool result = false;
    int fd = open(path, (unsigned) O_RDONLY | (unsigned) O_CLOEXEC);
    if (fd == -1) {
        // something whent wrong!
        return false;
    }

    lseek(fd, 0x1000, SEEK_SET);
    read(fd, buffer, 0x400);

    cmdline = buffer;
    len = fill_dex2oat_cmdline(find) + 1;
    for (int i = 0; i < 0x200; ++i, ++cmdline) {
        if (memcmp(cmdline, find, len) == 0) {
            cmdline += len;
            fill_dex_file(find);
            result = (strstr(cmdline, find) != nullptr);
            break;
        }
    }
    close(fd);

    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_FileTamperingDetector_detectOdexTamperingNative(
        JNIEnv *env, jobject thiz, jstring packageNameString) {

    FILE *fp = nullptr;
    char line[PATH_MAX];
    const char *maps = "/proc/self/maps";

    int fd = (int) openAt(AT_FDCWD, maps, O_RDONLY);
    if (fd < 0) {
        LOGE("Cannot open /proc/self/maps");
        return false;
    }

    fp = fdopen(fd, "r");
    if (fp == nullptr) {
        LOGE("Cannot open /proc/self/maps");
        return false;
    }

    bool result = false;
    const char *packageName = env->GetStringUTFChars(packageNameString, nullptr);
    while (fgets(line, PATH_MAX - 1, fp) != nullptr) {
        char *path = line;
        if (strchr(line, '/') == nullptr) {
            continue;
        }
        while (*path != '/') {
            ++path;
        }
        rstrip(path);
        if (strstr(path, packageName) != nullptr && access(path, F_OK) == 0) {
            if (isodex(path) || isdex(path)) {
                if (checkOdex(path)) {
                    result = true;
                    goto exit;
                }
            }
        }
    }

    exit:
    LOGD("* detectOdexTamperingNative : %i", result);

    env->ReleaseStringUTFChars(packageNameString, packageName);
    return result;
}

