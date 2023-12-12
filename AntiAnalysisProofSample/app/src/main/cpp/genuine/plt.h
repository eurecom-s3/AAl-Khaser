//
// Created by Thom on 2019/2/16.
//

#ifndef BREVENT_PLT_H
#define BREVENT_PLT_H

#include <elf.h>
#include <link.h>
#include <android/log.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLT_CHECK_PLT_APP ((unsigned short) 0x1u)
#define PLT_CHECK_PLT_ALL ((unsigned short) 0x2u)
#define PLT_CHECK_NAME    ((unsigned short) 0x4u)
#define PLT_CHECK_SYM_ONE ((unsigned short) 0x8u)

typedef struct Symbol {
    unsigned short check;
    unsigned short size;
    size_t total;
    ElfW(Addr) *symbol_plt;
    ElfW(Addr) *symbol_sym;
    const char *symbol_name;
    const char *dlpi_name;
    const char *target_library;
    char **names;
} Symbol;

typedef struct LibraryFunction {
    char *name;
    ElfW(Addr) *pointer;
    ElfW(Word) size;
} LibraryFunction;

typedef struct CustomLibrary {
    const char *libraryName;
    const char *libraryPath;
    ElfW(Addr) baseAddress;
    int nFuncions;
    struct LibraryFunction *libraryFunctions;
} CustomLibrary;

int dl_iterate_phdr_symbol(Symbol *symbol);

void *plt_dlsym(const char *name, size_t *total);

void *plt_dlsym_library(const char *name, const char *targetLibrary);

struct CustomLibrary retrieveAllLibraryFunctionNames(const char * libraryName);

bool isPltHooked(const char *name, bool all, const char *target_library);

bool detectPltHooking(const char *libraryName);

#ifdef __cplusplus
}
#endif

#endif //BREVENT_PLT_H
