#include <jni.h>
#include <string>
#include <cstdlib>
#include <mntent.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <elf.h>
#include <map>
#include <dirent.h>
#include <cstring>
#include <malloc.h>
#include <pthread.h>
#include <cctype>

#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>

#include <android/log.h>

#include "syscall_arch.h"
#include "common/syscalls.h"
#include "hook/customsyscalls.h"
#include "genuine/plt.h"
#include "genuine/inline.h"
#include "common/common.h"

#include "sys/inotify.h"

// Log macros
#define LOG_TAG "MemoryTamperingDetector_Native"

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectHookInStackTraceNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    jclass threadClass = env->FindClass("java/lang/Thread");
    jmethodID currentThread = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
    jmethodID getStackTrace = env->GetMethodID(threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");

    jclass StackTraceElementClass = env->FindClass("java/lang/StackTraceElement");
    jmethodID getClassName = env->GetMethodID(StackTraceElementClass, "getClassName", "()Ljava/lang/String;");
    jmethodID getMethodName = env->GetMethodID(StackTraceElementClass, "getMethodName", "()Ljava/lang/String;");

    jobject thread = env->CallStaticObjectMethod(threadClass, currentThread);
    auto stackTraces = (jobjectArray) env->CallObjectMethod(thread, getStackTrace);
    int length = env->GetArrayLength(stackTraces);
    for (int i = 0; i < length; i++) {
        jobject stackTrace = env->GetObjectArrayElement(stackTraces, i);
        auto jclassName = (jstring) env->CallObjectMethod(stackTrace, getClassName);
        auto jmethodName = (jstring) env->CallObjectMethod(stackTrace, getMethodName);
        const char *className = env->GetStringUTFChars(jclassName, nullptr);
        const char *methodName = env->GetStringUTFChars(jmethodName, nullptr);

        auto classSubstrate = "com.saurik.substrate.MS$2";
        auto methodSubstrate = "invoke";
        auto classXposed1 = "de.robv.android.xposed.XposedBridge";
        auto methodXposed1 = "main";
        auto methodXposed2 = "handleHookedMethod";
        auto classXposed2 = "de.robv.android.xposed.XC_MethodHook";

        if (strcmp(className, classSubstrate) == 0 &&
                strcmp(methodName, methodSubstrate) == 0) {
            // Substrate
            result = true;
        }

        if (strcmp(className, classXposed1) == 0 &&
                strcmp(methodName, methodXposed1) == 0) {
            // Xposed on the device
            result = true;
        }

        if (strcmp(className, classXposed1) == 0 &&
                strcmp(methodName, methodXposed2) == 0) {
            // Hooked method by Xposed
            result = true;
        }

        if (strcmp(className, classXposed2) == 0) {
            // LOGD("Call stack found hook: %s", className);
            result = true;
        }

        env->ReleaseStringUTFChars(jclassName, className);
        env->ReleaseStringUTFChars(jmethodName, methodName);

        if (result)
            break;
    }

    LOGD("* detectHookInStackTraceNative : %i\n", result);
    return result;
}

#define MAX_LINE 512
#define MAX_LENGTH 256

#ifdef _32_BIT
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#elif _64_BIT
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#endif

typedef struct stExecSection {
    int execSectionCount;
    unsigned long offset[2];
    unsigned long address[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;

// Include more libs as your need, but beware of the performance bottleneck especially
// when the size of the libraries are > few MBs
#define NUM_LIBS 6
static const char *libstocheck[NUM_LIBS] = {
        "libmemorytamperingdetector.so",
        "libhookdetector.so",
        "libemulatordetector.so",
        "librootdetector.so",
        "libz.so",
        LIBC};
static execSection *elfSectionArr[NUM_LIBS] = {
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr};

static inline void retrievePathsFromProcMaps(char **filepaths) {
    int fd = 0;
    char map[MAX_LINE];
    int counter = 0;
    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {
        while ((readLine(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {
                    char tmp[MAX_LENGTH] = "";
                    char path[MAX_LENGTH] = "";
                    char buf[5] = "";
                    sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                    if (buf[2] == 'x') {
                        size_t size = my_strlen(path) + 1;
                        filepaths[i] = static_cast<char *>(malloc(size));
                        my_strlcpy(filepaths[i], path, size);
                        counter++;
                    }
                }
            }
            if (counter == NUM_LIBS)
                break;
        }
        my_close(fd);
    }
}

static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *) buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        seed += (unsigned long) (*buf++);
    return seed;
}

static inline bool
scanExecutableSegments(char *map, execSection *pElfSectArr, const char *libraryName) {
    bool manipulationDetected = false;

    if (pElfSectArr == nullptr) {
        return false;
    }

    unsigned long start, end;
    char buf[MAX_LINE] = "";
    char path[MAX_LENGTH] = "";
    char tmp[100] = "";

    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);

    if (buf[2] == 'x') {
        if (buf[0] == 'r') {
            uint8_t *buffer = NULL;

            buffer = (uint8_t *) start;
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                if (start + pElfSectArr->offset[i] + pElfSectArr->memsize[i] > end) {
                    if (pElfSectArr->startAddrinMem != 0) {
                        buffer = (uint8_t *) pElfSectArr->startAddrinMem;
                        pElfSectArr->startAddrinMem = 0;
                        break;
                    }
                }
            }

            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                unsigned long output = checksum(buffer + pElfSectArr->address[i],
                                                pElfSectArr->memsize[i]);
                if (output != pElfSectArr->checksum[i]) {
                    LOGW("Executable Section Manipulated, "
                         "maybe due to Frida or other hooking framework.");
                    manipulationDetected = true;
                    break;
                }
            }
        } else {
            char ch[10] = "", ch1[10] = "";
            __system_property_get("ro.build.version.release", ch);
            __system_property_get("ro.system.build.version.release", ch1);
            int version = my_atoi(ch);
            int version1 = my_atoi(ch1);
            if (version < 10 || version1 < 10) {
                LOGW("Suspicious to get XOM in version < Android10");
                manipulationDetected = true;
            } else {
                if (0 == my_strncmp(libraryName, LIBC, my_strlen(LIBC))) {
                    //If it is not readable, then most likely it is not manipulated by Frida
                    LOGD("LIBC Executable Section not readable!");

                } else {
                    LOGW("Suspicious to get XOM for non-system library on Android 10 and above");
                    manipulationDetected = true;
                }
            }
        }
    } else {
        if (buf[0] == 'r') {
            pElfSectArr->startAddrinMem = start;
        }
    }

    return manipulationDetected;
}

static inline bool checksumOfLibrary(const char *filePath, execSection **pTextSection) {
    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);

    unsigned long memsize[2] = {0};
    unsigned long address[2] = {0};
    unsigned long offset[2] = {0};
    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));

        // Typically PLT and Text Sections are executable sections which are protected
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
            offset[execSectionCount] = sectHdr.sh_offset;
            address[execSectionCount] = sectHdr.sh_addr;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {
                break;
            }
        }
    }
    if (execSectionCount == 0) {
        LOGW("No executable section found. Suspicious");
        my_close(fd);
        return false;
    }
    //This memory is not released as the checksum is checked in a thread
    *pTextSection = static_cast<execSection *>(malloc(sizeof(execSection)));

    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        auto *buffer = static_cast<uint8_t *>(malloc(memsize[i] * sizeof(uint8_t)));
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->address[i] = address[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
    }

    my_close(fd);
    return true;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectRuntimeMemory2DiskDifferencesNative(
        JNIEnv *env, jobject thiz) { // e.g., due to frida
    // Init runtime objects
    char *filePaths[NUM_LIBS];
    for (auto & filePath : filePaths) {
        filePath = nullptr;
    }
    retrievePathsFromProcMaps(filePaths);

    for (int i = 0; i < NUM_LIBS; i++) {
        if (filePaths[i] != nullptr) {
            checksumOfLibrary(filePaths[i], &elfSectionArr[i]);
            free(filePaths[i]);
        }
    }

    // Start detection
    bool result = false;

    int fd = 0;
    char map[MAX_LINE];

    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {
        while ((readLine(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (elfSectionArr[i] != nullptr) {
                    if (my_strstr(map, libstocheck[i]) != nullptr) {
                        if (scanExecutableSegments(map, elfSectionArr[i], libstocheck[i])) {
                            result = true;
                            break;
                        }
                    }
                }
            }
        }
    } else {
        LOGE("Error opening /proc/self/maps. That's usually a bad sign.");
    }
    my_close(fd);

    LOGD("* detectRuntimeMemory2DiskDifferencesNative : %i", result);
    return result;
}

bool findStringInMemory(unsigned long start, unsigned long end, const char *bytes, unsigned int len) {
    char *pmem = (char*)start;
    int matched = 0;

    while ((unsigned long)pmem < (end - len)) {
        if(*pmem == bytes[0]) {
            matched = 1;
            char *p = pmem + 1;
            while (*p == bytes[matched] && (unsigned long)p < end && matched < len) {
                matched ++;
                p ++;
            }
            if (matched >= len) {
                return true;
            }
        }
        pmem ++;
    }
    return false;
}

static inline void fill_frida_trg(char v[]) {
    // LIBFRIDA => 76 73 66 70 82 73 68 65
    v[0x0] = 0x48;
    v[0x1] = 0x4c;
    v[0x2] = 0x44;
    v[0x3] = 0x41;
    v[0x4] = 82;
    v[0x5] = 0x48;
    v[0x6] = 0x46;
    v[0x7] = 0x42;
    for (unsigned int i = 0; i < 0x9; ++i) {
        v[i] ^= ((i + 0x4) % 0x8);
    }
    v[0x8] = '\0';
}

bool scanRuntimeSegmentsForFridaString(char * map) {
    char trg[9];
    char buf[512];
    unsigned long start, end;

    sscanf(map, "%lx-%lx %s", &start, &end, buf);
    fill_frida_trg(trg);

    if (buf[0] == 'r' && buf[2] == 'x') {
        return (findStringInMemory(start, end, trg, 9) == 1);
    }

    return false;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectRuntimeMemoryFridaStringNative(
        JNIEnv *env, jobject thiz) { // e.g., due to frida
    bool result = false;

    int fd;
    if ((fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {
        char map[MAX_LINE];
        while ((readLine(fd, map, (unsigned int) MAX_LINE)) > 0) {
            // LOGD("readLine result: %s", map);
            if (scanRuntimeSegmentsForFridaString(map)) {
                LOGW("Suspicious frida string found in memory!");
                result = true;
                break;
            }
        }
        close(fd);
    } else {
        LOGE("Error opening /proc/self/maps. That's usually a bad sign.");
    }

    LOGD("* detectRuntimeMemoryFridaStringNative : %i", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectPltHookingNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    for (int i = 0; i < CUSTOM_NATIVE_LIBS_NUM; i++) {
        // NB: for libc some function are wrapper of others and this could break such control!
        if (detectPltHooking(CUSTOM_NATIVE_LIBS[i])) {
            result = true;
            goto exit;
        }
    }

    exit:
    LOGD("* detectPltHookingNative : %i\n", result);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectInlineHookingNative(
        JNIEnv *env, jobject thiz) {
    bool result = false;

    for (int i = 0; i < CUSTOM_NATIVE_LIBS_NUM; i++) {
        if (detectInlineHooking(CUSTOM_NATIVE_LIBS[i])) {
            result = true;
            goto exit;
        }
    }

    exit:
    LOGD("* detectInlineHookingNative : %i\n", result);
    return result;
}

// The following function verify if there is a breakpoint somewhere in the executable memory segment
// Note: this could have false positive because I do not disassemble the opcodes into the instructions (x86 and x86_64)
/*bool detectBreakPoint(const char * libraryName) {
    bool result = false;

    CustomLibrary customLibrary = retrieveAllLibraryFunctionNames(libraryName);
    if (customLibrary.nFuncions == 0) {
        return false;
    }

    // See: https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-tbl-39
    ElfW(Ehdr) *elfhdr = (ElfW(Ehdr) *) customLibrary.baseAddress;
    for (int i = 0; i < elfhdr->e_phnum; i++) {
        // from: https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html
        // addr == info->dlpi_addr + info->dlpi_phdr[x].p_vaddr
        auto ph_address = customLibrary.baseAddress + elfhdr->e_phoff + (i * sizeof(ElfW(Phdr))); // first 3384025088
        ElfW(Phdr) *ph_t = (ElfW(Phdr) *) ph_address;

        // Ignore non executable memory portions
        if (!(ph_t->p_flags & PF_X)) {
            continue;
        }

        auto offset = customLibrary.baseAddress + ph_t->p_vaddr;
        // offset += sizeof(ElfW(Ehdr)) + sizeof(ElfW(Phdr)) * elfhdr->e_phnum;
        LOGD("offset %ud", offset);

        auto *p = (u_int8_t *) offset;
        for (int j = 0; j < ph_t->p_memsz; j++) {
            // https://developer.arm.com/documentation/102140/0200/Breakpoints
            // TODO: Cherk arm64
#if defined(__arm__) || defined(__aarch64__)
            if(*p == 0x01 && *(p+1) == 0xde) {
                LOGD("Find thumb bpt %p", p);
                return true;
            } else if (*p == 0xf0 && *(p+1) == 0xf7 && *(p+2) == 0x00 && *(p+3) == 0xa0) {
                LOGD("Find thumb2 bpt %p", p);
                return true;
            } else if (*p == 0x01 && *(p+1) == 0x00 && *(p+2) == 0x9f && *(p+3) == 0xef) {
                LOGD("Find arm bpt %p", p);
                return true;
            }
#elif defined(__i386__) || defined(__i686__)
// See: http://ref.x86asm.net/coder32.html#x0FC8
            if(*p == 0xcc || (*p == 0xcd && *(p+1) == 0x03) || *p == 0xce) {
                LOGD("Find x86 breakpoin %p", p);
                result = true;
                goto dealloc;
            }
#endif
            p++;
        }
    }

    // free customLibrary strings!
    dealloc:
    for (int i = 0; i < customLibrary.nFuncions; i++) {
        free(customLibrary.libraryFunctions[i].name);
    }
    free(customLibrary.libraryFunctions);

    exit:
    return result;
}*/

// The following function verify if there is a breakpoit as first instruction of the call
bool detectBreakPoint(const char * libraryName) {
    bool result = false;

    CustomLibrary customLibrary = retrieveAllLibraryFunctionNames(libraryName);
    if (customLibrary.nFuncions == 0) {
        return false;
    }

    for (int i = 0; i < customLibrary.nFuncions; i++) {
        auto *p = (uint8_t *) (customLibrary.libraryFunctions[i].pointer);
#if defined(__arm__) || defined(__aarch64__)
            if(*p == 0x01 && *(p+1) == 0xde) {
                LOGD("Find thumb bpt %p", p);
                result = true;
                goto dealloc;
            } else if (*p == 0xf0 && *(p+1) == 0xf7 && *(p+2) == 0x00 && *(p+3) == 0xa0) {
                LOGD("Find thumb2 bpt %p", p);
                result = true;
                goto dealloc;
            } else if (*p == 0x01 && *(p+1) == 0x00 && *(p+2) == 0x9f && *(p+3) == 0xef) {
                LOGD("Find arm bpt %p", p);
                result = true;
                goto dealloc;
            }
#elif defined(__i386__) || defined(__i686__)
// See: http://ref.x86asm.net/coder32.html#x0FC8
            // LOGD("first byte %u in function %s", *p, customLibrary.libraryFunctions[i].name);
            if(*p == 0xcc || (*p == 0xcd && *(p+1) == 0x03) /* || *p == 0xce*/) {
                LOGD("Find x86 breakpoin at address %p in function %s", p, customLibrary.libraryFunctions[i].name);
                result = true;
                goto dealloc;
            }
#endif
        //}

    }

    // free customLibrary strings!
    dealloc:
    for (int i = 0; i < customLibrary.nFuncions; i++) {
        free(customLibrary.libraryFunctions[i].name);
    }
    free(customLibrary.libraryFunctions);

    exit:
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectBreakPointNative(
        JNIEnv *env, jobject thiz) {

    bool result = false;

    //for (auto & i : CUSTOM_NATIVE_LIBS) {
    for (int i = 0; i < CUSTOM_NATIVE_LIBS_NUM; i++) {
        if (detectBreakPoint(CUSTOM_NATIVE_LIBS[i])) {
            result = true;
            goto exit;
        }
    }

    exit:
    LOGD("* detectBreakPointNative : %i\n", result);
    return result;
}

#define MAX_WATCHERS 200
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

static inline bool detectFileAccessMemoryDump() {
    bool result = false;

    int length, i = 0;
    int fd;
    int wd[MAX_WATCHERS] = {0,};
    int read_length = 0;
    char buffer[EVENT_BUF_LEN];

    /*creating the INOTIFY instance*/
    fd = my_inotify_init1(0);
    LOGD("Notify Init:%d\n",fd);

    if (fd > 0) {
        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_PAGEMAP, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_MEM, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_MAPS, IN_ACCESS | IN_OPEN);

        DIR *dir = opendir(PROC_TASK);
        if (dir != NULL) {
            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                char memPath[MAX_LENGTH] = "";
                char pagemapPath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(memPath, sizeof(memPath), PROC_TASK_MEM, entry->d_name);
                snprintf(pagemapPath, sizeof(pagemapPath), PROC_TASK_PAGEMAP, entry->d_name);
                wd[i++] = my_inotify_add_watch(fd, memPath, IN_ACCESS | IN_OPEN);
                wd[i++] = my_inotify_add_watch(fd, pagemapPath, IN_ACCESS | IN_OPEN);

            }
            closedir(dir);
        }
        LOGD("Completed adding inotify watch\n");

        length = read(fd, buffer, EVENT_BUF_LEN);
        LOGD("inotify read %d\n", length);

        if (length > 0) {
            /*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
            while (read_length < length) {
                struct inotify_event *event = (struct inotify_event *) buffer + read_length;

                if (event->mask & IN_ACCESS) {
                    // Possible strange access detected! (e.g., memory dumping)
                    LOGW("Unexpected file access.. Take action\n");
                    result = true;
                    break;
                } else if (event->mask & IN_OPEN) {
                    // Possible strange access detected! (e.g., memory dumping)
                    LOGW("Unexpected file open.. Take action\n");
                    result = true;
                    break;
                }
                LOGD("EVENT!!!!:%s\n", event->name);
                read_length += EVENT_SIZE + event->len;
            }
        }

        for (int j = 0; j < i; j++) {
            if (wd[j] != 0) {
                my_inotify_rm_watch(fd, wd[j]);
            }
        }

        close(fd);
    } else {
        LOGW("iNotify init failed\n");
    }

    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_experiments_antianalysisproofsample_checkers_tampering_MemoryTamperingDetector_detectFileAccessMemoryDumpNative(
        JNIEnv *env, jobject thiz) {
    bool result = detectFileAccessMemoryDump();

    LOGD("* detectFileAccessMemoryDumpNative : %i\n", result);
    return result;
}
