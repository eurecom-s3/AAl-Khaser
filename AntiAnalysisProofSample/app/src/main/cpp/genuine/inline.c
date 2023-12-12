#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include "inline.h"
#include "common.h"
#include "plt.h"

#define DEBUG_HOOK 0

// This function check the functions prologue
bool isInlineHooked(void *symbol) {
    if (symbol == NULL) {
        return false;
    }

#if defined(__arm__)
// https://developer.arm.com/docs/ddi0597/b/base-instructions-alphabetic-order/ldr-literal-load-register-literal
// A1, !(P == 0 && W == 1), we don't check P and W
// cond 010P U0W1 1111 _Rt_ xxxx xxxx xxxx
#define IS_LDR_PC_A1(x) (((x) & 0xfe5ff000u) == 0xe41ff000u)
// T2
// 1111 1000 U101 1111 | _Rt_ xxxx xxxx xxxx
#define IS_LDR_PC_T2(x) (((x) & 0xf000ff7fu) == 0xf000f85fu)

// https://developer.arm.com/docs/ddi0597/b/base-instructions-alphabetic-order/b-branch
// A1
// cond 100 xxxx xxxx xxxx xxxx xxxx xxxx
#define IS_B_A1(x) (((x) & 0xff000000u) == 0xea000000u)
// T2
// 1110 0xxx xxxx xxxx
#define IS_B_T2(x) (((x) & 0xf800u) == 0xe000u)
// T4
// 1111 0Sxx xxxx xxxx | 10J1 Jxxx xxxx xxxx
//        -- imm10 --- |       --- imm11 ---
#define IS_B_T4(x) (((x) & 0xd000f800u) == 0x9000f000u)

// https://developer.arm.com/docs/ddi0597/b/base-instructions-alphabetic-order/nop-no-operation
// T1, hint should be 0000, we don't check
// 1011 1111 hint 0000
#define IS_NOP_T1(x) (((x) & 0xff0fu) == 0xbf00u)

// https://developer.arm.com/docs/ddi0597/b/base-instructions-alphabetic-order/mov-movs-register-move-register
// cydia use `mov r8, r8` for Nop
// T1, Mmmm is Rm, Dddd is Rd
// 0100 0110 DMmm mddd
#define _IS_MOV_T1(x) (((x) & 0xff00u) == 0x4600u)
#define _RM_MOV_T1(x) ((((x) & 0x78u) >> 3u))
#define _RD_MOV_T1(x) ((((x) & 0x80u) >> 4u) | ((x) & 7u))
#define IS_MOV_T1_RR(x) (_IS_MOV_T1(x) && _RM_MOV_T1(x) == _RD_MOV_T1(x))

// https://developer.arm.com/docs/ddi0597/b/base-instructions-alphabetic-order/bx-branch-and-exchange
// cydia use `bx`
// T1
// 0100	0111 0Rmm m000
#define IS_BX_T1(x) (((x) & 0xff87u) == 0x4700u)
#define RM_BX_T1(x) (((x) & 0x0078u) >> 3u)
#define IS_BX_PC_T1(x) ((x) == 0x4778u)

    uintptr_t address = (uintptr_t) symbol;
    if ((address & 1U) == 0) {
        uint32_t *value32 = (uint32_t *) address;
        if (IS_LDR_PC_A1(*value32)) {
#ifdef DEBUG_HOOK
            LOGW("(arm ldr pc) symbol: %p, value: %08x", symbol, *value32);
#endif
            return true;
        }
        if (IS_B_A1(*value32)) {
#ifdef DEBUG_HOOK
            LOGW("(arm b) symbol: %p, value: %08x", symbol, *value32);
#endif
            return true;
        }
        LOGI("(arm) symbol: %p, value: %08x", symbol, *value32);
    } else {
        address = address & ~1U;
        uint16_t *value16 = (uint16_t *) address;
        uint32_t *value32 = (uint32_t *) address;
        if (IS_LDR_PC_T2(*value32)) {
#ifdef DEBUG_HOOK
            LOGW("(thumb ldr pc) symbol: %p, address: %p, value: %08x",
                 symbol, address, *value32);
#endif
            return true;
        }
        if (IS_B_T4(*value32)) {
#ifdef DEBUG_HOOK
            LOGW("(thumb b) symbol: %p, address: %p, value: %08x",
                 symbol, address, *value32);
#endif
            return true;
        }
        if (IS_B_T2(*value16)) {
#ifdef DEBUG_HOOK
            LOGW("(thumb b) symbol: %p, address: %p, value: %04x",
                 symbol, address, *value16);
#endif
            return true;
        }
        if (IS_NOP_T1(*value16) || IS_MOV_T1_RR(*value16)) {
#ifdef DEBUG_HOOK
            LOGW("(thumb nop) symbol: %p, address: %p, value: %04x",
                 symbol, address, *value16);
#endif
            address += 2;
            value16 = (uint16_t *) address;
            value32 = (uint32_t *) address;
        }
        if (IS_LDR_PC_T2(*value32)) {
#ifdef DEBUG_HOOK
            LOGW("(thumb ldr pc) symbol: %p, address: %p, value: %08x",
                 symbol, address, *value32);
#endif
            return true;
        }
        if (IS_BX_PC_T1(*value16) && IS_LDR_PC_A1(*(value32 + 1))) {
#ifdef DEBUG_HOOK
            LOGW("(thumb bx + arm ldr pc) symbol: %p, address: %p, value: %08x %08x",
                 symbol, address, *value32, *(value32 + 1));
#endif
            return true;
        }
        LOGI("(thumb) symbol: %p, address: %p, value: %08x %08x",
             symbol, address, *value32, *(value32 + 1));
    }
#endif

#if defined(__aarch64__)

// https://developer.arm.com/docs/ddi0596/latest/base-instructions-alphabetic-order/b-branch
// 0001 01xx xxxx xxxx xxxx xxxx xxxx xxxx
//        ------------ imm26 -------------
// NB: 0x14000000 is 00101***
#define IS_B(x) (((x) & 0xfc000000u) == 0x14000000u)

// https://developer.arm.com/docs/ddi0596/latest/base-instructions-alphabetic-order/ldr-literal-load-register-literal
// 0101 1000 xxxx xxxx xxxx xxxx xxxR tttt
//           -------- imm19 --------
#define IS_LDR_X(x) (((x) & 0xff000000u) == 0x58000000u)
#define X_LDR(x) ((x) & 0x1fu)

// https://developer.arm.com/docs/ddi0596/latest/base-instructions-alphabetic-order/adrp-form-pc-relative-address-to-4kb-page
// 1xx1 0000 xxxx xxxx xxxx xxxx xxxR dddd
//  lo       -------- immhi --------
#define IS_ADRP_X(x) (((x) & 0x9f000000u) == 0x90000000u)
#define X_ADRP(x) ((x) & 0x1fu)

// https://developer.arm.com/docs/ddi0596/latest/base-instructions-alphabetic-order/br-branch-to-register
// 1101 0110 0001 1111 0000 00Rn nnn0 0000
#define IS_BR_X(x) (((x) & 0xfffffc0f) == 0xd61f0000u)
#define X_BR(x) (((x) & 0x3e0u) >> 0x5u)

// https://developer.arm.com/docs/ddi0596/latest/base-instructions-alphabetic-order/movz-move-wide-with-zero
// 1op1 0010 1hwx xxxx xxxx xxxx xxxR dddd
//              ------ imm16 -------
// for op, 00 -> MOVN, 10 -> MOVZ, 11 -> MOVK
#define IS_MOV_X(x) (((x) & 0x9f800000u) == 0x92800000u)
#define X_MOV(x) ((x) & 0x1fu)

    uint32_t *value32 = symbol;
    if (IS_B(*value32)) {
#ifdef DEBUG_HOOK
        LOGW("(arm64 b) symbol: %p, value: %08x", symbol, *value32);
#endif
        return true;
    }
    if (IS_LDR_X(*value32) && IS_BR_X(*(value32 + 1))) {
        uint32_t x = X_LDR(*value32);
        if (x == X_BR(*(value32 + 1))) {
#ifdef DEBUG_HOOK
            LOGW("(arm64 ldr+br x%d) symbol: %p, value: %08x %08x",
                 x, symbol, *value32, *(value32 + 1));
#endif
            return true;
        }
    }
    if (IS_ADRP_X(*value32) && IS_BR_X(*(value32 + 1))) {
        uint32_t x = X_ADRP(*value32);
        if (x == X_BR(*(value32 + 1))) {
#ifdef DEBUG_HOOK
            LOGW("(arm64 adrp+br x%d) symbol: %p, value: %08x %08x",
                 x, symbol, *value32, *(value32 + 1));
#endif
            return true;
        }
    }
    if (IS_MOV_X(*value32)) {
        uint32_t x = X_MOV(*value32);
        for (int i = 1; i <= 4; ++i) {
            if (IS_BR_X(*(value32 + i))) {
                if (x != X_BR(*(value32 + i))) {
                    break;
                }
#ifdef DEBUG_HOOK
                for (int k = 0; k < i; ++k) {
                    LOGW("(arm64 mov x%d) symbol: %p, value: %08x",
                         x, symbol + sizeof(uint32_t) * k, *(value32 + k));
                }
                LOGW("(arm64  br x%d) symbol: %p, value: %08x",
                     x, symbol + sizeof(uint32_t) * i, *(value32 + i));
#endif
                return true;
            } else if (IS_MOV_X(*(value32 + i))) {
                if (x != X_MOV(*(value32 + i))) {
                    break;
                }
            }
        }
    }
    LOGI("(arm64) symbol: %p, value: %08x %08x", symbol, *value32, *(value32 + 1));
#endif

// Note: it checks only for simple jmp int the function prologue!

#if defined(__i386__) || defined(__x86_64__) || defined(__amd64__)
// ref: https://c9x.me/x86/html/file_module_x86_id_147.html
// ref: http://ref.x86asm.net/coder64.html

// jmp: e9; ea; eb; ff
#define IS_JMP(x) (((x) & 0xffu) == 0xe9u) || (((x) & 0xffu) == 0xeau) || (((x) & 0xffu) == 0xebu)

// je/jz: 84; 74; e3
#define IS_JE(x) (((x) & 0xffu) == 0x84u) || (((x) & 0xffu) == 0x74u) || (((x) & 0xffu) == 0xe3u)

// jn* : 71->7f; 81->8f
#define IS_JN(x) ((((x) & 0xffu) >= 0x71u) && (((x) & 0xffu) <= 0x7fu)) || \
    ((((x) & 0xffu) >= 0x81u) && (((x) & 0xffu) <= 0x8fu))

    uint8_t *value8 = (uint8_t *) symbol;
    return IS_JMP(*value8) || IS_JE(*value8) || IS_JN(*value8);

#endif

    return false;
}

bool detectInlineHooking(const char * libraryName) {
    bool result = false;

    CustomLibrary customLibrary = retrieveAllLibraryFunctionNames(libraryName);
    if (customLibrary.nFuncions == 0) {
        goto exit;
    }

    for (int i = 0; i < customLibrary.nFuncions; i++) {
        // POC: ignore some functions
        if(customLibrary.libraryFunctions[i].name == NULL ||
            customLibrary.libraryFunctions[i].name[0] == '\0' ||
            strstr(customLibrary.libraryFunctions[i].name, "cxxabi") != NULL ||
            strncmp("_Z", customLibrary.libraryFunctions[i].name, 2) == 0 ||
            strncmp("__cxa", customLibrary.libraryFunctions[i].name, 5) == 0) {
            continue;
        }

        // LOGD("Invoking isInlineHooked for function %s", customLibrary.libraryFunctions[i].name);
        if (isInlineHooked(customLibrary.libraryFunctions[i].pointer)) {
            LOGD("Detected inline hook in function %s of library %s", customLibrary.libraryFunctions[i].name, customLibrary.libraryName);
            result = true;
            goto dealloc;
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
}


/*#ifdef DEBUG_HOOK_IO
bool setRead(void *symbol) {
    uintptr_t address = (uintptr_t) symbol;
    uintptr_t page_size = (uintptr_t) getpagesize();
    uintptr_t base = address & ~(page_size - 1);
    // inline check read at most 20 bytes
    uintptr_t end = (address + 20 + page_size - 1) & -page_size;
#ifdef DEBUG
    LOGI("set r+x from %p to %p", base, end);
#endif
    if (mprotect((void *) base, end - base, PROT_READ | PROT_EXEC)) {
#ifdef DEBUG
        LOGW("cannot mprotect: %s", strerror(errno));
#endif
        return false;
    } else {
        return true;
    }
}
#endif*/
