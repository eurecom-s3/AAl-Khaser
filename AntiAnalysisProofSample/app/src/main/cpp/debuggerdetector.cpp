#include <jni.h>
#include <glob.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <cerrno>
#include <elf.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <fcntl.h>
#include <cctype>

#include <android/log.h>

#include <linux/fcntl.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <asm/unistd.h>

#include "hook/customsyscalls.h"
#include "syscall_arch.h"
#include "common/syscalls.h"
#include "genuine/art.h"
#include "common/common.h"
#include "sys/inotify.h"
#include "genuine/plt.h"

// Log macros
#define LOG_TAG "DebuggerDetector_Native"

static int childPid;
bool monitorPid() {
    int status;

    sleep(2);
    waitpid(childPid, &status, WNOHANG);
    return !(WIFSIGNALED(status) == 1 && WTERMSIG(status) == SIGKILL);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_DebuggerDetector_detectDebuggerFromPtraceNative(JNIEnv *env, jobject thiz) {
    bool result = false;

    // This code prevent a process to attach!
    childPid = fork();
    if (childPid == 0) {
        // Attach child as debugger
        int ppid = getppid();
        int status;

        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0) {
            waitpid(ppid, &status, 0);
            ptrace(PTRACE_CONT, ppid, NULL, NULL);
            kill(getpid(), SIGKILL);
        } else {
            exit(-1);
        }
    } else {
        // parent
        result = monitorPid();
    }

    LOGD("* detectDebuggerFromPtraceNative : %i", result);
    return result;
}

// Vtable structure. Just to make messing around with it more intuitive
struct VT_JdwpAdbState {
    unsigned long x;
    unsigned long y;
    void * JdwpSocketState_destructor;
    void * _JdwpSocketState_destructor;
    void * Accept;
    void * showmanyc;
    void * ShutDown;
    void * ProcessIncoming;
};

/*
 * The ART runtime exports some of the vtables of JDWP-related classes as global symbols
 * (in C++, vtables are tables that hold pointers to class methods).
 * This includes the vtables of the classes JdwpSocketState and JdwpAdbState,
 * which handle JDWP connections via network sockets and ADB, respectively.
 *
 * One way to overwrite the method pointers is to overwrite the address of the function
 * jdwpAdbState::ProcessIncoming with the address of JdwpAdbState::Shutdown.
 * This will cause the debugger to disconnect immediately.
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_DebuggerDetector_messingJdwpDataStructuresNative(
        JNIEnv *env, jobject thiz) {
    // bool result = false;

    // In this way, I can bypass the dlopen restriction from Android N
    // and I do not need the dlopen trick like: https://blog.quarkslab.com/android-runtime-restrictions-bypass.html
    void* pointer = plt_dlsym_library("_ZTVN3art4JDWP12JdwpAdbStateE", "libart.so");

    if (pointer == nullptr) {
        LOGE("Error loading _ZTVN3art4JDWP12JdwpAdbStateE from libart.so");
    } else {
        struct VT_JdwpAdbState *vtable = ( struct VT_JdwpAdbState *) pointer;

        LOGD("Vtable for JdwpAdbState at: %08x\n", vtable);

        // Let the fun begin!
        unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
        unsigned long page = (unsigned long)vtable & ~(pagesize-1);

        mprotect((void *)page, pagesize, PROT_READ | PROT_WRITE);
        vtable->ProcessIncoming = vtable->ShutDown;

        // Reset permissions & flush cache
        mprotect((void *)page, pagesize, PROT_READ);
    }
}

#define MAX_LINE 512
#define MAX_LENGTH 256
static const char *JDWP = "JDWP";
static const char *TRACER_PID = "TracerPid";

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_DebuggerDetector_detectJavaDebuggerNative(JNIEnv *env, jobject thiz) {
    DIR *dir = opendir(PROC_TASK);
    bool result = false;

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_COMM, entry->d_name);
            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                readLine(fd, buf, MAX_LENGTH);
                if (0 == my_strncmp(buf, JDWP, strlen(JDWP))) {
                    result = true;
                }
            }
            my_close(fd);
        }
        closedir(dir);

    }

    LOGD("* detectJavaDebuggerNative : %i", result);
    return result;
}

static inline bool checkTracerPid(int fd) {
    bool result = false;
    char map[MAX_LINE];
    while ((readLine(fd, map, (unsigned int) MAX_LINE)) > 0) {
        if (NULL != my_strstr(map, TRACER_PID)) {
            char *saveptr1;
            my_strtok_r(map, ":", &saveptr1);
            int pid = my_atoi(saveptr1);
            if (pid != 0) {
                result = true;
            }
            break;
        }
    }
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_DebuggerDetector_detectTracerPidNative(JNIEnv *env, jobject thiz) {
    /*
     * Check TracerPid != 0 in /proc/self/status and in each of task /proc/self/task/.../status
     */

    bool result = false;
    int fd = my_openat(AT_FDCWD, PROC_SELF_STATUS, O_RDONLY | O_CLOEXEC, 0);
    if (fd != 0) {
        result = checkTracerPid(fd);
        if(result){
            LOGD("Native Debugger Attached - TracerPid detected in /proc/self/status");
        }
        my_close(fd);
    }

    if (!result) {
        DIR *dir = opendir(PROC_TASK);

        if (dir != nullptr) {
            struct dirent *entry = nullptr;
            while ((entry = readdir(dir)) != nullptr) {
                char filePath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

                int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
                if (fd != 0) {
                    result = checkTracerPid(fd);
                    if(result){
                        LOGD("Native Debugger Attached - TracerPid detected in /proc/self/task/.../status");
                    }
                    my_close(fd);
                }
                if (result)
                    break;
            }
            closedir(dir);
        }
    }

    LOGD("* detectTracerPidNative : %i", result);
    return result;
}

#define TCP_PORT "5D8A" // 23946

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_DebuggerDetector_detectDebuggerDefaultTcpPortNative(JNIEnv *env,
                                                                                                                      jobject thiz){
    bool result = false;
    char buff[MAX_LENGTH];

    FILE *fp;
    const char dir[] = "/proc/net/tcp";
    fp = fopen(dir, "r");
    if(fp == nullptr){
        LOGE("file failed [errno:%d, desc:%s]", errno, strerror(errno));
        return false;
    }

    while(fgets(buff, MAX_LENGTH, fp)){
        if(my_strstr(buff, TCP_PORT) != nullptr){
            LOGI("Line:%s", buff);
            fclose(fp);
            result = true;
        }
    }

    LOGD("* detectDebuggerDefaultTcpPortNative : %i", result);
    return result;
}