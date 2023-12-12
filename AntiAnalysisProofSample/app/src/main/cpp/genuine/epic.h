#ifndef EPIC_H
#define EPIC_H

#include <jni.h>
#include <stdbool.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

bool doAntiEpic(JNIEnv *env, jobject classLoader);

void clearHandler(JNIEnv *env, int sdk);

#ifdef __cplusplus
}
#endif

#endif