//
// Created by Thom on 2019/2/16.
//

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include "plt.h"
#include "classloader.h"
#include "common.h"
#include "epic.h"
#include "art.h"
#include "hash.h"
#include "anti-xposed.h"

// Xposed checker
static void inline fill_NewLocalRef(char v[]) {
    // _ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE
    static unsigned int m = 0;

    if (m == 0) {
        m = 47;
    } else if (m == 53) {
        m = 59;
    }

    v[0x0] = '\\';
    v[0x1] = '^';
    v[0x2] = 'K';
    v[0x3] = '5';
    v[0x4] = 'f';
    v[0x5] = 'z';
    v[0x6] = '}';
    v[0x7] = '3';
    v[0x8] = 'A';
    v[0x9] = 'B';
    v[0xa] = 'D';
    v[0xb] = 'K';
    v[0xc] = 'a';
    v[0xd] = 'f';
    v[0xe] = 'T';
    v[0xf] = 'j';
    v[0x10] = 'g';
    v[0x11] = '%';
    v[0x12] = '$';
    v[0x13] = 'X';
    v[0x14] = 'r';
    v[0x15] = 'o';
    v[0x16] = 'U';
    v[0x17] = 'u';
    v[0x18] = 'x';
    v[0x19] = '}';
    v[0x1a] = 'q';
    v[0x1b] = 'L';
    v[0x1c] = 'z';
    v[0x1d] = 'F';
    v[0x1e] = 'd';
    v[0x1f] = 'r';
    v[0x20] = 'm';
    v[0x21] = 'w';
    v[0x22] = 'z';
    v[0x23] = '\x10';
    v[0x24] = 'J';
    v[0x25] = 'A';
    v[0x26] = '[';
    v[0x27] = 'X';
    v[0x28] = 'D';
    v[0x29] = '^';
    v[0x2a] = '\x1b';
    v[0x2b] = 'a';
    v[0x2c] = 'b';
    v[0x2d] = 'k';
    v[0x2e] = 'g';
    v[0x2f] = '`';
    v[0x30] = 'p';
    v[0x31] = '@';
    for (unsigned int i = 0; i < 0x32; ++i) {
        v[i] ^= ((i + 0x32) % m);
    }
    v[0x32] = '\0';
}

static inline jobject newLocalRef(JNIEnv *env, void *object) {
    static jobject (*NewLocalRef)(JNIEnv *, void *) = nullptr;
    if (object == nullptr) {
        return nullptr;
    }
    if (NewLocalRef == nullptr) {
        char v[0x40];
        fill_NewLocalRef(v);
        NewLocalRef = (jobject (*)(JNIEnv *, void *)) plt_dlsym(v, nullptr);
        LOGI("NewLocalRef: %p", NewLocalRef);
    }
    if (NewLocalRef != nullptr) {
        return NewLocalRef(env, object);
    } else {
        return nullptr;
    }
}

static inline void fill_DeleteLocalRef(char v[]) {
    // _ZN3art9JNIEnvExt14DeleteLocalRefEP8_jobject
    static unsigned int m = 0;

    if (m == 0) {
        m = 43;
    } else if (m == 47) {
        m = 53;
    }

    v[0x0] = '^';
    v[0x1] = 'X';
    v[0x2] = 'M';
    v[0x3] = '7';
    v[0x4] = 'd';
    v[0x5] = 't';
    v[0x6] = 's';
    v[0x7] = '1';
    v[0x8] = 'C';
    v[0x9] = 'D';
    v[0xa] = 'B';
    v[0xb] = 'I';
    v[0xc] = 'c';
    v[0xd] = 'x';
    v[0xe] = 'J';
    v[0xf] = 'h';
    v[0x10] = 'e';
    v[0x11] = '#';
    v[0x12] = '\'';
    v[0x13] = 'P';
    v[0x14] = 'p';
    v[0x15] = 'z';
    v[0x16] = 'r';
    v[0x17] = 'l';
    v[0x18] = '|';
    v[0x19] = 'V';
    v[0x1a] = 't';
    v[0x1b] = '\x7f';
    v[0x1c] = '|';
    v[0x1d] = 'r';
    v[0x1e] = 'M';
    v[0x1f] = 'E';
    v[0x20] = 'G';
    v[0x21] = 'g';
    v[0x22] = 's';
    v[0x23] = '\x1c';
    v[0x24] = 'z';
    v[0x25] = 'L';
    v[0x26] = 'H';
    v[0x27] = 'J';
    v[0x28] = 'C';
    v[0x29] = 'O';
    v[0x2a] = 'c';
    v[0x2b] = 'u';
    for (unsigned int i = 0; i < 0x2c; ++i) {
        v[i] ^= ((i + 0x2c) % m);
    }
    v[0x2c] = '\0';
}

static void DeleteLocalRef(JNIEnv *env, jobject object) {
    static void (*DeleteLocalRef)(JNIEnv *, jobject) = nullptr;
    if (DeleteLocalRef == nullptr) {
        char v[0x30];
        fill_DeleteLocalRef(v);
        DeleteLocalRef = (void (*)(JNIEnv *, jobject)) plt_dlsym(v, nullptr);
        LOGI("DeleteLocalRef: %p", DeleteLocalRef);
    }
    if (DeleteLocalRef != nullptr) {
        DeleteLocalRef(env, object);
    }
}

static bool doAntiXposed(JNIEnv *env, jobject object, intptr_t hash) {
    if (!add(hash)) {
        return false;
    }
    LOGI("doAntiXposed, classLoader: %p, hash: %x", object, hash);
    jclass classXposedBridge = findXposedBridge(env, object);
    if (classXposedBridge == nullptr) {
        return false;
    }

    // TODO: Check for disableXposedBridge
    // disableXposedBridge(env, classXposedBridge);

    // EdXposed is based on epic framework! -> Add check for ART instrumentation frameworks!
    // TODO: Check for disable epic framework
    /*if (doAntiEpic(env, object)) {
        LOGI("antied epic");
    }*/

    return true;
}

static inline void fill_dalvik_system_PathClassLoader(char v[]) {
    // dalvik/system/PathClassLoader
    static unsigned int m = 0;

    if (m == 0) {
        m = 23;
    } else if (m == 29) {
        m = 31;
    }

    v[0x0] = 'b';
    v[0x1] = 'f';
    v[0x2] = 'd';
    v[0x3] = '\x7f';
    v[0x4] = 'c';
    v[0x5] = '`';
    v[0x6] = '#';
    v[0x7] = '~';
    v[0x8] = 'w';
    v[0x9] = '|';
    v[0xa] = 'd';
    v[0xb] = 't';
    v[0xc] = '\x7f';
    v[0xd] = '<';
    v[0xe] = 'D';
    v[0xf] = 't';
    v[0x10] = 'b';
    v[0x11] = 'h';
    v[0x12] = 'B';
    v[0x13] = 'n';
    v[0x14] = 'b';
    v[0x15] = 'w';
    v[0x16] = 'v';
    v[0x17] = 'J';
    v[0x18] = 'h';
    v[0x19] = 'i';
    v[0x1a] = 'm';
    v[0x1b] = 'o';
    v[0x1c] = 'y';
    for (unsigned int i = 0; i < 0x1d; ++i) {
        v[i] ^= ((i + 0x1d) % m);
    }
    v[0x1d] = '\0';
}

class PathClassLoaderVisitor : public art::SingleRootVisitor {
public:
    bool xposedDetected;

    PathClassLoaderVisitor(JNIEnv *env, jclass classLoader) : env_(env), classLoader_(classLoader) {
        xposedDetected = false;
    }

    void VisitRoot(art::mirror::Object *root, const art::RootInfo &info ATTRIBUTE_UNUSED) {
        bool hasXposed = false;
        jobject object = newLocalRef(env_, root);
        if (object != nullptr) {
            if (env_->IsInstanceOf(object, classLoader_)) {
                xposedDetected = doAntiXposed(env_, object, (intptr_t) root);
            }
            DeleteLocalRef(env_, object);
        }
    }

private:
    JNIEnv *env_;
    jclass classLoader_;
};

static inline void fill_VisitRoots(char v[]) {
    // _ZN3art9JavaVMExt10VisitRootsEPNS_11RootVisitorE
    static unsigned int m = 0;

    if (m == 0) {
        m = 47;
    } else if (m == 53) {
        m = 59;
    }

    v[0x0] = '^';
    v[0x1] = 'X';
    v[0x2] = 'M';
    v[0x3] = '7';
    v[0x4] = 'd';
    v[0x5] = 't';
    v[0x6] = 's';
    v[0x7] = '1';
    v[0x8] = 'C';
    v[0x9] = 'k';
    v[0xa] = '}';
    v[0xb] = 'm';
    v[0xc] = '[';
    v[0xd] = 'C';
    v[0xe] = 'J';
    v[0xf] = 'h';
    v[0x10] = 'e';
    v[0x11] = '#';
    v[0x12] = '#';
    v[0x13] = 'B';
    v[0x14] = '|';
    v[0x15] = 'e';
    v[0x16] = '~';
    v[0x17] = 'l';
    v[0x18] = 'K';
    v[0x19] = 'u';
    v[0x1a] = 't';
    v[0x1b] = 'h';
    v[0x1c] = 'n';
    v[0x1d] = '[';
    v[0x1e] = 'O';
    v[0x1f] = 'n';
    v[0x20] = 'r';
    v[0x21] = '}';
    v[0x22] = '\x12';
    v[0x23] = '\x15';
    v[0x24] = 'w';
    v[0x25] = 'I';
    v[0x26] = 'H';
    v[0x27] = '\\';
    v[0x28] = '\x7f';
    v[0x29] = 'C';
    v[0x2a] = 'X';
    v[0x2b] = 'E';
    v[0x2c] = 'Y';
    v[0x2d] = 'A';
    v[0x2e] = 'r';
    v[0x2f] = 'D';
    for (unsigned int i = 0; i < 0x30; ++i) {
        v[i] ^= ((i + 0x30) % m);
    }
    v[0x30] = '\0';
}

static bool checkGlobalRef(JNIEnv *env, jclass clazz) {
    char v[0x40];
    fill_VisitRoots(v);
    auto VisitRoots = (void (*)(void *, void *)) plt_dlsym(v, nullptr);
    LOGI("VisitRoots: %p", VisitRoots);
    if (VisitRoots == nullptr) {
        return false;
    }
    JavaVM *jvm;
    env->GetJavaVM(&jvm);
    PathClassLoaderVisitor visitor(env, clazz);
    VisitRoots(jvm, &visitor);

    return visitor.xposedDetected;
}

static inline void fill_SweepJniWeakGlobals(char v[]) {
    // _ZN3art9JavaVMExt19SweepJniWeakGlobalsEPNS_15IsMarkedVisitorE
    static unsigned int m = 0;

    if (m == 0) {
        m = 59;
    } else if (m == 61) {
        m = 67;
    }

    v[0x0] = ']';
    v[0x1] = 'Y';
    v[0x2] = 'J';
    v[0x3] = '6';
    v[0x4] = 'g';
    v[0x5] = 'u';
    v[0x6] = '|';
    v[0x7] = '0';
    v[0x8] = '@';
    v[0x9] = 'j';
    v[0xa] = 'z';
    v[0xb] = 'l';
    v[0xc] = 'X';
    v[0xd] = 'B';
    v[0xe] = 'U';
    v[0xf] = 'i';
    v[0x10] = 'f';
    v[0x11] = '"';
    v[0x12] = '-';
    v[0x13] = 'F';
    v[0x14] = 'a';
    v[0x15] = 'r';
    v[0x16] = '}';
    v[0x17] = 'i';
    v[0x18] = 'P';
    v[0x19] = 'u';
    v[0x1a] = 'u';
    v[0x1b] = 'J';
    v[0x1c] = '{';
    v[0x1d] = '~';
    v[0x1e] = 'K';
    v[0x1f] = 'f';
    v[0x20] = 'N';
    v[0x21] = 'L';
    v[0x22] = 'F';
    v[0x23] = 'D';
    v[0x24] = 'J';
    v[0x25] = 'T';
    v[0x26] = 'm';
    v[0x27] = 'y';
    v[0x28] = 'd';
    v[0x29] = 'x';
    v[0x2a] = 's';
    v[0x2b] = '\x1c';
    v[0x2c] = '\x1b';
    v[0x2d] = 'f';
    v[0x2e] = 'C';
    v[0x2f] = '|';
    v[0x30] = 'S';
    v[0x31] = 'A';
    v[0x32] = '_';
    v[0x33] = 'P';
    v[0x34] = 'R';
    v[0x35] = 'a';
    v[0x36] = 'Q';
    v[0x37] = 'J';
    v[0x38] = 'S';
    v[0x39] = 't';
    v[0x3a] = 'n';
    v[0x3b] = 'p';
    v[0x3c] = 'F';
    for (unsigned int i = 0; i < 0x3d; ++i) {
        v[i] ^= ((i + 0x3d) % m);
    }
    v[0x3d] = '\0';
}

class WeakClassLoaderVisitor : public art::IsMarkedVisitor {
public :
    int xposedDetected;

    WeakClassLoaderVisitor(JNIEnv *env, jclass classLoader) : env_(env), classLoader_(classLoader) {
        xposedDetected = false;
    }

    art::mirror::Object *IsMarked(art::mirror::Object *obj) override {
        jobject object = newLocalRef(env_, obj);
        if (object != nullptr) {
            if (env_->IsInstanceOf(object, classLoader_)) {
                xposedDetected = doAntiXposed(env_, object, (intptr_t) obj);
            }
            DeleteLocalRef(env_, object);
        }
        return obj;
    }

private:
    JNIEnv *env_;
    jclass classLoader_;
};

static bool checkWeakGlobalRef(JNIEnv *env, jclass clazz) {
    char v[0x40];
    fill_SweepJniWeakGlobals(v);
    auto SweepJniWeakGlobals = (void (*)(void *, void *)) plt_dlsym(v, nullptr);
    LOGI("SweepJniWeakGlobals: %p", SweepJniWeakGlobals);
    if (SweepJniWeakGlobals == nullptr) {
        return false;
    }
    JavaVM *jvm;
    env->GetJavaVM(&jvm);
    WeakClassLoaderVisitor visitor(env, clazz);
    SweepJniWeakGlobals(jvm, &visitor);

    return visitor.xposedDetected;
}

bool checkClassLoader(JNIEnv *env, int sdk) {
    if (sdk < 21) {
        return false;
    }

    char v[0x40];
    fill_dalvik_system_PathClassLoader(v);
    jclass clazz = env->FindClass(v);
    if (env->ExceptionCheck()) {
/*#ifdef DEBUG
        env->ExceptionDescribe();
#endif*/
        env->ExceptionClear();
    }
    if (clazz == nullptr) {
        LOGW("No class dalvik/system/PathClassLoader found.\n");
        return false;
    }

    bool xposedDetected = false;
    xposedDetected |= checkGlobalRef(env, clazz);
    xposedDetected |= checkWeakGlobalRef(env, clazz);

    clear();
    env->DeleteLocalRef(clazz);

    return xposedDetected;
}
