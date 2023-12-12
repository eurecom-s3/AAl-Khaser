#include <jni.h>
#include <glob.h>
#include <sys/types.h>
#include <android/log.h>

#include "genuine/am-proxy.h"
#include "common/common.h"

// Log macros
#define LOG_TAG "VirtualizationrDetector_Native"

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_VirtualizationDetector_detectAndroidManagerProxyObjectsNative(
        JNIEnv *env, jobject thiz){
    bool result;

    // TODO: verify other managers (not only AM)
    int sdk = android_get_device_api_level();
    result = isAmProxy(env, sdk);

    LOGD("* detectAndroidManagerProxyObjectsNative : %i", result);
    return result;
}