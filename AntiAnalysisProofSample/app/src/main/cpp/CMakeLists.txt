# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Declares and names the project.

project("antianalysisproofsample")

set(can_use_assembler TRUE)
enable_language(ASM)

##Start - Comment this block generating non-obfuscated builds
#set(OLLVM_PATH ${CMAKE_HOME_DIRECTORY}/../../../../../o-llvm-binary/ollvm-tll/build/bin_Darwin)
#set(OLLVM_C_COMPILER ${OLLVM_PATH}/clang)
#set(OLLVM_CXX_COMPILER ${OLLVM_PATH}/clang++)
#
#set(OLLVM_C_FLAGS "-mllvm -sub -mllvm -bcf -mllvm -fla")
#
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OLLVM_C_FLAGS}")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OLLVM_C_FLAGS}")
#set(CMAKE_C_COMPILER ${OLLVM_C_COMPILER})
#set(CMAKE_CXX_COMPILER ${OLLVM_CXX_COMPILER})
##End - Comment this block generating non-obfuscated builds

if(${ANDROID_ABI} STREQUAL "armeabi-v7a" OR ${ANDROID_ABI} STREQUAL "x86")
    add_definitions("-D_32_BIT")
elseif(${ANDROID_ABI} STREQUAL "arm64-v8a" OR ${ANDROID_ABI} STREQUAL "x86_64")
    add_definitions("-D_64_BIT")
endif()

add_library(rootdetector SHARED rootdetector.cpp)
add_library(emulatordetector SHARED emulatordetector.cpp)
add_library(hookdetector SHARED hookdetector.cpp)
add_library(debuggerdetector SHARED debuggerdetector.cpp)
add_library(memorytamperingdetector SHARED memorytamperingdetector.cpp)
add_library(virtualizationdetector SHARED virtualizationdetector.cpp)
add_library(filetamperingdetector SHARED filetamperingdetector.cpp)
add_library(delayedexecutor SHARED delayedexecutor.cpp)
add_library(timedetector SHARED timedetector.cpp)

add_library(genuine
        STATIC
        genuine/am-proxy.c
        genuine/anti-xposed.c
        genuine/classloader.cpp
        genuine/common.c
        genuine/epic.c
        genuine/epic-field.c
        genuine/epic-method.c
        genuine/hash.c
        genuine/inline.c
        genuine/openat.c
        genuine/path.c
        genuine/plt.c)
add_library(hook
        STATIC
        hook/customsyscalls.c)
add_library(libcommon
        STATIC
        common/common.c)

# target_include_directories(libcommon PRIVATE arch/${ANDROID_ABI})
# target_include_directories(rootdetector PRIVATE arch/${ANDROID_ABI})
# target_include_directories(emulatordetector PRIVATE arch/${ANDROID_ABI})
target_include_directories(hookdetector PRIVATE arch/${ANDROID_ABI})
target_include_directories(debuggerdetector PRIVATE arch/${ANDROID_ABI})
target_include_directories(memorytamperingdetector PRIVATE arch/${ANDROID_ABI})
# target_include_directories(virtualizationdetector PRIVATE arch/${ANDROID_ABI})

find_library(log-lib log )

target_link_libraries(rootdetector
        ${log-lib}
        libcommon)
target_link_libraries(emulatordetector
        ${log-lib}
        libcommon)
target_link_libraries(hookdetector
        ${log-lib}
        libcommon
        hook
        genuine)
target_link_libraries(memorytamperingdetector
        ${log-lib}
        libcommon
        hook
        genuine)
target_link_libraries(debuggerdetector
        ${log-lib}
        libcommon
        hook
        genuine)
target_link_libraries(virtualizationdetector
        ${log-lib}
        libcommon
        genuine)
target_link_libraries(filetamperingdetector
        ${log-lib}
        libcommon
        genuine)
target_link_libraries(delayedexecutor
        ${log-lib}
        libcommon)
target_link_libraries(timedetector
        ${log-lib}
        libcommon)

# add_custom_command( TARGET hookdetector
#         POST_BUILD
#         COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -R .comment -g -S -d --strip-unneeded ${CMAKE_HOME_DIRECTORY}/../../../build/intermediates/cmake/${CMAKE_BUILD_TYPE}/obj/${ANDROID_ABI}/libhookdetector.so
#         COMMENT "Stripped native library")
