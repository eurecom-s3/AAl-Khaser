#include <jni.h>
#include <string>
#include <cstdlib>
#include <mntent.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <malloc.h>
#include <pthread.h>
#include <cctype>

#include <android/log.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>

#include <android/log.h>


#include "syscall_arch.h"
#include "common/syscalls.h"
#include "genuine/classloader.h"
#include "genuine/anti-xposed.h"
#include "hook/customsyscalls.h"
#include "common/common.h"

#include "sys/inotify.h"

// Log macros
#define LOG_TAG "HookDetector_Native"

static const int defaultPorts[] = {27042, 27047}; // 27047 -> frida server default port

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_detectXposedHookedMethodNative(
        JNIEnv *env, jobject thiz) {
    // Check if disable Xposed Detection --> At the moment I remove the logic in doAntiXposed function!
    int sdk = android_get_device_api_level();

    bool xposedDetected = detectXposedHooking(env, sdk);

    LOGD("* detectXposedHookedMethodNative : %i", xposedDetected);
    return xposedDetected;
}

bool checkCallStack(C_JNIEnv *env) {
    jclass threadClass = (*env)->FindClass((JNIEnv *) env, "java/lang/Thread");
    jmethodID currentThread = (*env)->GetStaticMethodID((JNIEnv *) env, threadClass, "currentThread", "()Ljava/lang/Thread;");
    jmethodID getStackTrace = (*env)->GetMethodID((JNIEnv *) env, threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    jclass StackTraceElementClass = (*env)->FindClass((JNIEnv *) env, "java/lang/StackTraceElement");
    jmethodID getClassName = (*env)->GetMethodID((JNIEnv *) env, StackTraceElementClass, "getClassName", "()Ljava/lang/String;");

    jobject thread = (*env)->CallStaticObjectMethod((JNIEnv *) env, threadClass, currentThread);
    auto stackTraces = (jobjectArray) (*env)->CallObjectMethod((JNIEnv *) env, thread, getStackTrace);
    int length = (*env)->GetArrayLength((JNIEnv *) env, stackTraces);

    bool xposedDetected = false;
    for (int i = 0; i < length; i++) {
        jobject stackTrace = (*env)->GetObjectArrayElement((JNIEnv *) env, stackTraces, i);
        auto jclassName = (jstring) (*env)->CallObjectMethod((JNIEnv *) env, stackTrace, getClassName);
        const char *className = (*env)->GetStringUTFChars((JNIEnv *) env, jclassName, nullptr);
        auto methodHook = "de.robv.android.xposed.XC_MethodHook";

        if (memcmp(className, methodHook, strlen(methodHook)) == 0) {
            LOGD("Call stack found hook: %s", className);
            xposedDetected = true;
        }
        (*env)->ReleaseStringUTFChars((JNIEnv *) env, jclassName, className);
        if (xposedDetected)
            break;
    }

    return xposedDetected;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_customGenuineXposedDetectorNative(
        JNIEnv *env, jobject thiz) {
    // Check if disable Xposed Detection --> At the moment I remove the logic in doAntiXposed function!
    int sdk = android_get_device_api_level();

    bool xposedDetected = checkClassLoader(env, sdk);
    if (sdk >= 21) {
        xposedDetected |= checkCallStack((C_JNIEnv *) env);
    }

    LOGD("* customGenuineXposedDetectorNative : %i", xposedDetected);
    return xposedDetected;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_isDefaultServerListeningNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    for (int i = 0; i < (int) (sizeof(defaultPorts) / sizeof(int)); i++) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(defaultPorts[i]);
        inet_aton("127.0.0.1", &(sa.sin_addr));

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(sock, (struct sockaddr *) &sa, sizeof sa) != -1) {
            /* Frida server detected. Do something… */
            result = true;
            break;
        }
    }

    LOGD("* isDefaultServerListening : %i", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_isFridaOpenPortNative(
        JNIEnv *env, jobject thiz) {
    /*
     * Mini-portscan to detect frida-server (sending an D-Bus AUTH message) on any local port.
     */

    bool result = false;

    for(int i = 0 ; i <= 65535 ; i++) {
        // int i = 27042;
        // LOGD("Test port %d", i);
        struct sockaddr_in sa;

        int sock = socket(AF_INET , SOCK_STREAM , 0);
        sa.sin_port = htons(i);

        if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {

            // "FRIDA DETECTION [1]: Open Port: %d"
            char res[8];
            memset(res, 0 , 7);

            // send a D-Bus AUTH message. Expected answer is “REJECT"

            send(sock, "\x00", 1, NULL);
            send(sock, "AUTH\r\n", 6, NULL);

            usleep(100);

            bool ret = (recv(sock, res, 6, MSG_DONTWAIT) != -1);
            if (ret) {
                // LOGD("Response %s", res);
                if (strcmp(res, "REJECT") == 0) {
                    /* Frida server detected. Do something… */
                    result = true;
                }
            }
        }

        close(sock);
        if (result)
            break;
    }

    LOGD("* isFridaOpenPort : %i", result);
    return result;
}

#define MAX_LENGTH 256
static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_detectFridaThreadNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;
    DIR *dir = opendir(PROC_TASK);

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            // int fd = openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                readLine(fd, buf, (unsigned int) MAX_LENGTH);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    //Kill the thread. This freezes the app. Check if it is an anticpated behaviour
                    //int tid = my_atoi(entry->d_name);
                    //int ret = my_tgkill(getpid(), tid, SIGSTOP);

                    LOGW("Frida specific thread found.");
                    result = true;
                }
                my_close(fd);
                if (result)
                    break;
            }
        }
        closedir(dir);
    }

    LOGD("* detectFridaThread : %i", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_detectFridaNamedPipeNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    DIR *dir = opendir(PROC_FD);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            struct stat filestat;
            char buf[MAX_LENGTH] = "";
            char filePath[MAX_LENGTH] = "";
            snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);

            lstat(filePath, &filestat);

            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
                if (NULL != my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                    LOGW("Frida specific named pipe found.");
                    result = true;
                    break;
                }
            }

        }
    }
    closedir(dir);

    LOGD("* detectFridaNamedPipe : %i", result);
    return result;
}

// define the class for the framework, such as epic, yahfa, etc...
#define NUMBER_OF_FRAMEWORK_CLASSES 11
const char *FRAMEWORK_CLASSES[NUMBER_OF_FRAMEWORK_CLASSES] = {
        "me/weishu/epic/art/EpicNative",
        "me/weishu/epic/art2/EpicNative",
        "me/weishu/epic/art/EpicBridge",
        "me/weishu/epic/art2/EpicBridge",
        "me/weishu/epic/art/Trampoline",
        "me/weishu/epic/art2/Trampoline",
        "me/weishu/epic/art/Epic",
        "me/weishu/epic/art2/Epic",
        "de/robv/android/xposed/DexposedBridge",
        "lab/galaxy/yahfa/HookMain",
        "lab/galaxy/yahfa/HookAnnotation"
};

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_HookDetector_detectInstrumentationFrameworkClasses(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    for (auto className : FRAMEWORK_CLASSES) {
        jclass clazz = env->FindClass(className);
        if (clazz != nullptr) {
            LOGD("Find instrumentation class %s", className);
            result = true;
            break;
        } else {
            env->ExceptionClear();
        }
    }

    LOGD("* detectInstrumentationFrameworkClasses : %i", result);
    return result;
}
