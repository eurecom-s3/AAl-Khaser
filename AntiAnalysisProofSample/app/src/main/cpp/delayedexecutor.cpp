#include <jni.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>

#include "common/common.h"

#define LOG_TAG "DelayedExecutor_Native"


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_generic_DelayedExecutor_runMaliciousAfterSocketTimeoutNative(
        JNIEnv *env, jobject thiz, jint timeout) {
    bool result = false;

    const char *host = "8.8.8.8"; // "127.0.0.1";
    const int port = 80; // 2000;

    int sockfd, n;

    struct sockaddr_in serv_addr;
    struct hostent *server;
    struct timeval tv;

    struct timespec tstart={0,0}, tend={0,0};

    tv.tv_sec = timeout;
    tv.tv_usec = 1;

    server = gethostbyname(host);
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    serv_addr.sin_family = AF_INET;

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
    int connectResult = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    clock_gettime(CLOCK_MONOTONIC, &tend);

    double end = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec);
    double start = ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
    LOGD("Connect took about %.5f seconds", end - start);

    if (connectResult == -1 && (end - start) > timeout) {
        jclass clazz = env->GetObjectClass(thiz);
        jmethodID malicious = env->GetMethodID(clazz, "maliciousCode", "()V");
        env->CallVoidMethod(thiz, malicious);
        result = true;
    } else {
        LOGD("Not enougth wait in socket connection");
    }

    return result;
}


