#include <jni.h>
#include <string>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <android/log.h>
#include <cstdlib>
#include <mntent.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h> // for waitpid
#include "common/common.h"

// Log macros
#define LOG_TAG "EmulatorDetector_Native"

int global_value = 0;
void* thread_one(void* arg){
    for(;;){
        global_value = 0;
        /*
        global_value = 1;
        __asm__ __volatile__("mov r0, %0;"
                             "mov r1, #1;"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
                             "add r1, r1, #1;" "str r1, [r0];"
        :
        : "r" (&global_value)
        :
        );*/
        for(int j=1;j<33;j++){
            global_value += (j-global_value);
            usleep(1);
        }

    }
    return ((void*)0);
}

int count[33] = {0};
std::string count_string = "";
void* thread_two(void* arg) {
    count_string = "";
    for (int i = 0; i < 5000; i++) {
        count[global_value]++;
        usleep(2);
    }

    sleep(1);
    for(int j=0;j<33;j++){
        count_string += std::to_string(count[j]);
    }
    return ((void*)0);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_EmulatorDetector_checkQemuTasksNative(
        JNIEnv *env, jobject thiz) {
    pthread_t pt[2];
    pthread_create(&pt[0],nullptr,thread_one,nullptr);
    pthread_create(&pt[1],nullptr,thread_two,nullptr);

    sleep(3);
    LOGD("count_string is : %s\n", count_string.c_str());

    // pthread_kill(pt[0], SIGSTOP);
    // pthread_kill(pt[1], SIGSTOP);

    return env->NewStringUTF(count_string.c_str());
}

void handler_sigtrap(int signo) {
    LOGD("Child - Signal handler for SIGTRAP");
    exit(0);
}

void handler_sigbus(int signo) {
    LOGD("Child - Signal handler for SIGBUS");
    exit(0);
}

void setupSigTrap() {
    // BKPT throws SIGTRAP on nexus 5 / oneplus one (and most devices)
    signal(SIGTRAP, handler_sigtrap);
    // BKPT throws SIGBUS on nexus 4
    signal(SIGBUS, handler_sigbus);
}

// This will cause a SIGSEGV on some QEMU or be properly respected
void tryBKPT() {
#if defined(__arm__)
    LOGD("Child launch SIGSEGV arm");
    __asm__ __volatile__ ("bkpt 255");
#elif defined(__aarch64__)
    LOGD("Child launch SIGSEGV aarch64");
    __asm__ __volatile__ ("brk 255");
    LOGD("Child after SIGSEGV");
#elif defined(__i386__) || defined(__i686__)
    __asm__ __volatile__("int %0" : : "i" (255));
#else
    LOGD("Child exit with code 0");
    exit(0);
#endif
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_EmulatorDetector_qemuBkptNative(
        JNIEnv *env, jobject thiz) {
    pid_t child = fork();
    int child_status, status = 0;

    if(child == 0) { // child
        setupSigTrap();
        tryBKPT();
    } else if(child == -1) {
        status = -1;
    } else {
        while ( waitpid(child, &child_status, WNOHANG) == 0 ) {
            sleep(1);
            break;
        }

        if ( WIFEXITED(child_status) || (WIFSTOPPED(child_status) && WSTOPSIG(child_status) == 0)) {
            // Likely a real device
            status = 0;
        } else {
            // Didn't exit properly - very likely an emulator
            status = 2;
        }

        // Ensure child is dead
        kill(child, SIGKILL);
        waitpid(child, nullptr, WEXITED);
    }

    return status;
}

uint32_t * histogram;

#ifdef __amd64__
uint64_t gv = 0;
#else
uint32_t gv = 0;
#endif

const int numberOfIncIns = 50;
int numberOfSamples = 0x100;//Make sure we dont overflow any entry of our histogram by using UINT_MAX

void polling_thread() {
    for(int i = 0; i < numberOfSamples; i++){
        usleep(2);
        histogram[gv]++;
    }
}

// TODO: Check all archs
void* atomicallyIncreasingGlobalVarThread(void * data){

    for(;;){

#ifdef __amd64__
        __asm__ __volatile__ ( "mov %0, %%rbx;"
				"movl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"     "addl $1, (%%rbx);"
				"addl $1, (%%rbx);"
				:
				:"r"(&gv)
				);

#elif __aarch64__
        // TODO: write it as assembly
        for(int i = 0; i < numberOfIncIns; i++){
            usleep(1);
            //LOGD("numberOfSamples: %d - updating histogram with global value index: %d", i, gv);
            gv++;
        }

#elif defined(__arm__)
        __asm__ __volatile__ ("mov r0, %[global];"
		        "mov r1, #1;"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        "add r1, r1, #1;" "str r1, [r0];"
		        :
		        :[global] "r" (&gv)
		        );
// #endif
//#ifdef __i386__
#elif defined(__i386__)
        __asm__ __volatile__ (
        "movl %0, %%ebx;"
        "movl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        "addl $1, (%%ebx);"
        :
        :"c"(&gv)
        );
#endif
        // LOGD("cicle - global value %d", gv);
    }
}

double calculatEntropyValue(){
    double sum = 0.0, ent = 0.0;
    for (int i = 0; i < numberOfIncIns; i++)
        sum += (double)histogram[i];

    for (int i = 0; i < numberOfIncIns; i++){
        double pi = (double)histogram[i] / sum;
        if(pi == 0)
            continue;
        ent += pi * log(pi);
    }
    return -ent/log(sum);
}

void initializeHistogram(){
    //Assume that we have ~numberOfIncIns asm increment instructions
    //so we know that we will have an index into histogram greater than numberOfIncIns
#ifdef __amd64__
    histogram = static_cast<uint32_t *>(malloc(sizeof(uint64_t) * (numberOfIncIns)));
#else
    histogram = static_cast<uint32_t *>(malloc(sizeof(uint32_t) * (numberOfIncIns)));
#endif
    int i;
    for(i =0; i < numberOfIncIns; i++)
        histogram[i] = 0;
}

extern "C"
JNIEXPORT jdouble JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_EmulatorDetector_qemuFingerPrint(
        JNIEnv *env, jobject thiz) {
    initializeHistogram();

    pthread_t threadData;

    if(pthread_create(&threadData, nullptr, atomicallyIncreasingGlobalVarThread, nullptr)) {
        perror("pthread_create()");
    }

    polling_thread();
    double entValue = calculatEntropyValue();
    // pthread_kill(threadData, SIGSTOP);
    free(histogram);

    return entValue;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_EmulatorDetector_detectSelinuxWrongEnforceFile(
        JNIEnv *env, jobject thiz) {
    bool result = false;
    FILE* file = fopen("/sys/fs/selinux/enforce", "r"); // on systems that have sysfs mounted, the mount point is /sys/fs/selinux
    char* line = (char*) calloc(50, sizeof(char));

    if (file == nullptr) {
        LOGD("Unable to read the enforce file");
        // I cannot guess that - result = true;
    } else {

        while (fgets(line, 50, file)) {
            if (strstr(line, "0")) {
                LOGD(" selinux NOT ENFORCING");
                result = true;
            } else {
                LOGD(" selinux ENFORCING");
            }
        }
        if (line) { free(line); }
        fclose(file);
    }

    LOGD("* selinuxEnforceFileStatusChecker : %i", result);
    return result;
}
