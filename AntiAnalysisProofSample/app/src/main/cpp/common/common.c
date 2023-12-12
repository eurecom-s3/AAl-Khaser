#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <android/log.h>

//#include <elf.h>
//#include <link.h>

#include "common.h"

ssize_t readLine(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;
    memset(buf, 0, max_len);

    do {
        ret = read(fd, &b, 1);
        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }
        if (b == '\n') {
            return bytes_read;
        }
        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);
    return bytes_read;
}

void rstrip(char *line) {
    char *path = line;
    if (line != NULL) {
        while (*path && *path != '\r' && *path != '\n') {
            ++path;
        }
        if (*path) {
            *path = '\0';
        }
    }
}
