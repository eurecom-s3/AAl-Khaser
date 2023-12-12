#ifndef BREVENT_ANTI_XPOSED_H
#define BREVENT_ANTI_XPOSED_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

// jboolean antiXposed(JNIEnv *env, jclass clazz, int sdk, bool *xposed);

jclass findXposedBridge(JNIEnv *env, jobject classLoader);

jclass findLoadedClass(JNIEnv *env, jobject classLoader, const char *name);

bool disableXposedBridge(JNIEnv *env, jclass classXposedBridge);

bool detectXposedHooking(JNIEnv *env, int sdk);

#ifdef __cplusplus
}
#endif

#endif //BREVENT_ANTI_XPOSED_H
