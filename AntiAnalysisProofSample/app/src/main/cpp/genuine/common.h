//
// Created by Thom on 2019/3/20.
//

#ifndef BREVENT_COMMON_H
#define BREVENT_COMMON_H

#include <jni.h>
#include <stdbool.h>
#include <android/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_TAG "CustomGenuine_Native"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG,__VA_ARGS__)

int getSdk();

bool has_native_libs();

#ifdef __cplusplus
}
#endif

#endif //BREVENT_COMMON_H
