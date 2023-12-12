#include <jni.h>
#include <string>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <android/log.h>
#include <cstdlib>
#include <mntent.h>
#include <unistd.h>
#include "common/common.h"

// Log macros
#define LOG_TAG "RootDetector_Native"

const char *const ANDROID_OS_BUILD_TAGS = "ro.build.tags";
const char *const ANDROID_OS_DEBUGGABLE = "ro.debuggable";
const char *const ANDROID_OS_SYS_INITD = "sys.initd";
const char *const SERVICE_ADB_ROOT = "service.adb.root";
const char *const ANDROID_OS_SECURE = "ro.secure";
const char *const ANDROID_OS_BUILD_SELINUX = "ro.build.selinux";


struct mntent *getMntent(FILE *fp, struct mntent *e, char *buf, int buf_len) {
    while (fgets(buf, buf_len, fp) != NULL) {
        // Entries look like "/dev/block/vda /system ext4 ro,seclabel,relatime,data=ordered 0 0".
        // That is: mnt_fsname mnt_dir mnt_type mnt_opts mnt_freq mnt_passno.
        int fsname0, fsname1, dir0, dir1, type0, type1, opts0, opts1;
        if (sscanf(buf, " %n%*s%n %n%*s%n %n%*s%n %n%*s%n %d %d",
                   &fsname0, &fsname1, &dir0, &dir1, &type0, &type1, &opts0, &opts1,
                   &e->mnt_freq, &e->mnt_passno) == 2) {
            e->mnt_fsname = &buf[fsname0];
            buf[fsname1] = '\0';
            e->mnt_dir = &buf[dir0];
            buf[dir1] = '\0';
            e->mnt_type = &buf[type0];
            buf[type1] = '\0';
            e->mnt_opts = &buf[opts0];
            buf[opts1] = '\0';
            return e;
        }
    }
    return NULL;
}

bool isPresentMntOpt(const struct mntent *pMnt, const char *pOpt) {
    char *token = pMnt->mnt_opts;
    const char *end = pMnt->mnt_opts + strlen(pMnt->mnt_opts);
    const size_t optLen = strlen(pOpt);
    while (token != NULL) {
        const char *tokenEnd = token + optLen;
        if (tokenEnd > end) break;
        if (memcmp(token, pOpt, optLen) == 0 &&
            (*tokenEnd == '\0' || *tokenEnd == ',' || *tokenEnd == '=')) {
            return true;
        }
        token = strchr(token, ',');
        if (token != NULL) {
            token++;
        }
    }
    return false;
}

static char *concat2str(const char *pString1, const char *pString2) {
    char *result;
    size_t lengthBuffer = 0;

    lengthBuffer = strlen(pString1) +
                   strlen(pString2) + 1;
    result = static_cast<char *>(malloc(lengthBuffer));
    if (result == NULL) {
        LOGW("malloc failed\n");
        return NULL;
    }
    memset(result, 0, lengthBuffer);
    strcpy(result, pString1);
    strcat(result, pString2);
    return result;
}

static bool isBadPropertyState(const char *key, const char *badValue, bool isObligatoryProperty, bool isExact) {
    if (badValue == NULL) {
        LOGE("badValue may not be NULL");
        return false;
    }
    if (key == NULL) {
        LOGE("key may not be NULL");
        return false;
    }
    char value[PROP_VALUE_MAX + 1];
    int length = __system_property_get(key, value);
    bool result = false;
    /* A length 0 value indicates that the property is not defined */
    if (length > 0) {
        LOGI("property:[%s]==[%s]", key, value);
        if (isExact) {
            if (strcmp(value, badValue) == 0) {
                LOGW("bad value[%s] equals to [%s] in the property [%s]", value, badValue, key);
                result = true;
            }
        } else {
            if (strlen(value) >= strlen(badValue) && strstr(value, badValue) != NULL) {
                LOGW("bad value[%s] found in [%s] in the property [%s]", value, badValue, key);
                result = true;
            }
        }
    } else {
        LOGI("[%s] property not found", key);
        if (isObligatoryProperty) {
            result = true;
        }
    }
    return result;
}

bool isDetectedTestKeys() {
    const char *TEST_KEYS_VALUE = "test-keys";
    return isBadPropertyState(ANDROID_OS_BUILD_TAGS, TEST_KEYS_VALUE, true, false);
}

bool isDetectedDevKeys() {
    const char *DEV_KEYS_VALUE = "dev-keys";
    return isBadPropertyState(ANDROID_OS_BUILD_TAGS, DEV_KEYS_VALUE, true, false);
}

bool isNotFoundReleaseKeys() {
    const char *RELEASE_KEYS_VALUE = "release-keys";
    return !isBadPropertyState(ANDROID_OS_BUILD_TAGS, RELEASE_KEYS_VALUE, false, true);
}

bool checkForProps() {
    const char *BAD_DEBUGGABLE_VALUE = "1";
    const char *BAD_SECURE_VALUE = "0";
    const char *BAD_SYS_INITD_VALUE = "1";
    const char *BAD_SERVICE_ADB_ROOT_VALUE = "1";
    const char *BAD_SERVICE_OS_BUILD_SELINUX = "0";

    bool result = isBadPropertyState(ANDROID_OS_DEBUGGABLE, BAD_DEBUGGABLE_VALUE, true, true) ||
                  isBadPropertyState(SERVICE_ADB_ROOT, BAD_SERVICE_ADB_ROOT_VALUE, false, true) ||
                  isBadPropertyState(ANDROID_OS_SECURE, BAD_SECURE_VALUE, true, true) ||
                  isBadPropertyState(ANDROID_OS_SYS_INITD, BAD_SYS_INITD_VALUE, false, true) ||
                  isBadPropertyState(ANDROID_OS_BUILD_SELINUX, BAD_SERVICE_OS_BUILD_SELINUX, false, false);

    return result;
}

bool checkSuExists() {
    char buf[BUFSIZ];
    char *str = NULL;
    char *temp = NULL;
    size_t size = 1;  // start with size of 1 to make room for null terminator
    size_t strlength;

    FILE *pipe = popen("which su", "r");
    if (pipe == NULL) {
        LOGI("pipe is null");
        return false;
    }

    while (fgets(buf, sizeof(buf), pipe) != NULL) {
        strlength = strlen(buf);
        temp = static_cast<char *>(realloc(str, size + strlength));  // allocate room for the buf that gets appended
        if (temp == NULL) {
            // allocation error
            LOGE("Error (re)allocating memory");
            pclose(pipe);
            if (str != NULL) {
                free(str);
            }
            return false;
        } else {
            str = temp;
        }
        strcpy(str + size - 1, buf);
        size += strlength;
    }
    pclose(pipe);
    LOGW("A size of the result from pipe is [%zu], result:\n [%s] ", size, str);
    if (str != NULL) {
        free(str);
    }
    return size > 1;
}

static bool isAccessedFile(const char *path) {
    int result = access(path, F_OK);
    LOGV("[%s] has been accessed with result: [%d]", path, result);
    return result == 0 ? true : false;
}

static bool isFoundBinaryInPath(const char *path, const char *binary) {
    char *checkedPath = concat2str(path, binary);
    if (checkedPath == NULL) { // malloc failed
        return false;
    }
    bool result = isAccessedFile(checkedPath);
    free(checkedPath);
    if (result) {
        return result;
    }
    return false;
}

static bool isFoundBinaryFromArray(const char *const *array, const char *binary) {
    for (size_t i = 0; array[i]; ++i) {
        if (isFoundBinaryInPath(array[i], binary))
            return true;
    }
    return false;
}

/*
const char * const MG_EXPOSED_FILES[] = {
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/xposed.prop",
        "/cache/recovery/xposed.zip",
        "/system/framework/XposedBridge.jar",
        "/system/bin/app_process64_xposed",
        "/system/bin/app_process32_xposed",
        "/magisk/xposed/system/lib/libsigchain.so",
        "/magisk/xposed/system/lib/libart.so",
        "/magisk/xposed/system/lib/libart-disassembler.so",
        "/magisk/xposed/system/lib/libart-compiler.so",
        "/system/bin/app_process32_orig",
        "/system/bin/app_process64_orig",
        "/system/lib/libmemtrack_real.so",
        "/system/lib64/libmemtrack_real.so",
        "/system/lib/libriru_edxp.so",
        "/system/lib64/libriru_edxp.so",
        "/system/lib/libwhale.edxp.so",
        "/system/lib64/libwhale.edxp.so",
        "/system/framework/edxp.jar",
        0
};

bool isFoundXposed() {
    for (size_t i = 0; EXPOSED_FILES[i]; ++i) {
        bool result = isAccessedFile(MG_EXPOSED_FILES[i]);
        if (result) {
            return result;
        }
    }
    return false;
}

bool isFoundHooks() {
    bool result = false;
    pid_t pid = getpid();
    char maps_file_name[512];
    sprintf(maps_file_name, "/proc/%d/maps", pid);
    LOGI("try to open [%s]", maps_file_name);
    const size_t line_size = BUFSIZ;
    char *line = malloc(line_size);
    if (line == NULL) {
        return result;
    }
    FILE *fp = fopen(maps_file_name, "r");
    if (fp == NULL) {
        free(line);
        return result;
    }
    memset(line, 0, line_size);
    const char *substrate = "com.saurik.substrate";
    const char *xposed = "XposedBridge.jar";
    const char *edxposed = "edxp.jar";
    while (fgets(line, line_size, fp) != NULL) {
        const size_t real_line_size = strlen(line);
        if ((real_line_size >= strlen(substrate) && strstr(line, substrate) != NULL) ||
            (real_line_size >= strlen(xposed) && strstr(line, xposed) != NULL) ||
            (real_line_size >= strlen(edxposed) && strstr(line, edxposed) != NULL)) {
            GR_LOGI("found in [%s]: [%s]", maps_file_name, line);
            result = true;
            break;
        }
    }
    free(line);
    fclose(fp);
    return result;
}*/


// --------------------------------------
// JNI Entrypoints
// --------------------------------------

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_RootDetector_checkForBinaryNative(
        JNIEnv *env, jobject thiz, jstring filename) {

    const char *file = env->GetStringUTFChars(filename, 0);

    // read paths
    jclass clazz = env->GetObjectClass(thiz);
    jfieldID binaryPathsField = env->GetStaticFieldID(clazz, "BINARY_PATHS", "[Ljava/lang/String;");
    auto binaryPaths =
            static_cast<jobjectArray>(env->GetStaticObjectField(clazz, binaryPathsField));
    int stringCount = env->GetArrayLength(binaryPaths);

    bool result = false;
    for (int i=0; i<stringCount; i++) {
        auto binaryPath = (jstring) (env->GetObjectArrayElement(binaryPaths, i));
        const char *path = env->GetStringUTFChars(binaryPath, nullptr);
        if (isFoundBinaryInPath(path, file))
            result = true;
        env->ReleaseStringUTFChars(binaryPath, path);
        if (result)
            break;
    }

    LOGD("* checkForBinaryNative(%s): %d\n", file, result);
    env->ReleaseStringUTFChars(filename, file);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_RootDetector_checkForPropsNative(
        JNIEnv *env, jobject thiz) {
    bool result = checkForProps();
    LOGD("* checkForPropsNative: %d\n", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_RootDetector_checkForRWPathsNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;
    FILE *file = fopen("/proc/mounts", "r");
    char mntent_strings[BUFSIZ];
    if (file == NULL) {
        LOGE("setmntent");
        return result;
    }

    jclass clazz = env->GetObjectClass(thiz);
    jfieldID readOnlyPathsField =
            env->GetStaticFieldID(clazz, "READ_ONLY_PATHS", "[Ljava/lang/String;");
    auto readOnlyPaths =
            static_cast<jobjectArray>(env->GetStaticObjectField(clazz, readOnlyPathsField));
    int stringCount = env->GetArrayLength(readOnlyPaths);

    struct mntent ent = {nullptr};
    while (NULL != getMntent(file, &ent, mntent_strings, sizeof(mntent_strings))) {
        for (size_t i = 0; i < stringCount; i++) {
            auto readOnlyPath = (jstring) (env->GetObjectArrayElement(readOnlyPaths, i));
            const char *path = env->GetStringUTFChars(readOnlyPath, nullptr);

            if (strcmp((&ent)->mnt_dir, path) == 0 &&
                isPresentMntOpt(&ent, "rw")) {
                LOGI("%s %s %s %s\n", (&ent)->mnt_fsname, (&ent)->mnt_dir, (&ent)->mnt_opts,
                        (&ent)->mnt_type);
                result = true;
            }

            env->ReleaseStringUTFChars(readOnlyPath, path);
            if (result) {
                break;
            }
        }
        memset(&ent, 0, sizeof(ent));
    }
    fclose(file);

    LOGD("* checkForRWPathsNative: %d\n", result);
    return result;
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_RootDetector_checkTestKeysNative(
        JNIEnv *env, jobject thiz) {
    bool result = isDetectedTestKeys() || isDetectedDevKeys() || isNotFoundReleaseKeys();
    LOGD("* checkTestKeysNative: %d\n", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_environment_RootDetector_checkSuExistsNative(
        JNIEnv *env, jobject thiz) {
    bool result = checkSuExists();
    LOGD("* checkSuExistsNative: %d\n", result);
    return result;
}


