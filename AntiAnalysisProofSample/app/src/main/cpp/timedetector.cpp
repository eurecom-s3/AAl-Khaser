#include <jni.h>
#include <cstdio>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <cstdlib>
#include <time.h>

#include "common/common.h"

#define LOG_TAG "DelayedExecutor_Native"

long getUptime() {
    struct sysinfo sinfo{};
    int error = sysinfo(&sinfo);
    if(error != 0) {
        LOGW("sysinfo error = %d", error);
    }
    return sinfo.uptime;
}

long getMonoliticUptime() {
    struct timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        LOGW("Could not get monotonic time");
        return -1;
    }
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

long getJavaUptime(JNIEnv *env) {
    jclass systemClockClass = env->FindClass("android/os/SystemClock");
    jmethodID uptimeMillisMethod = env->GetStaticMethodID(systemClockClass, "uptimeMillis", "()J");

    long uptimeMillis = env->CallStaticLongMethod(systemClockClass, uptimeMillisMethod);
    return uptimeMillis / 1000;
}

#define MIN_UPTIME_SECONDS (12 * 60)
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_generic_TimeDetector_checkPossibleStrangeUptimeNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    long up1 = getUptime();
    long up2 = getMonoliticUptime();
    long up3 = getJavaUptime(env);

    // Check if they significantly differ
    if (up1 != up2 &&
        ((up1 - up2) >= 2 || (up2 - up1) >= 2)) {
        LOGD("Detected strange uptime diff");
        result = true;
    } else if (up1 != up3 &&
            ((up1 - up3) >= 2 || (up3 - up1) >= 2)) {
        LOGD("Detected strange uptime diff");
        result = true;
    } else if (up3 != up2 &&
               ((up3 - up2) >= 2 || (up2 - up3) >= 2)) {
        LOGD("Detected strange uptime diff");
        result = true;
    }

    if (!result) {
        // Check if uptime is less than 14 mins and not detected boot!
        jclass clazz = env->FindClass(
                "com/experiments/antianalysisproofsample/checkers/generic/DelayedExecutor$BootCompletedReceiver");
        jfieldID field = env->GetStaticFieldID(clazz, "isBootDetected", "Z");
        bool isBootDetected = env->GetStaticBooleanField(clazz, field);

        if (!isBootDetected && up1 < MIN_UPTIME_SECONDS) {
            LOGD("Early boot detected");
            result = true;
        }
    }

    LOGD("* checkPossibleStrangeUptimeNative : %i", result);
    return result;
}

