#ifndef ANTIANALYSISPROOFSAMPLE_CUSTOMSYSCALLS_H
#define ANTIANALYSISPROOFSAMPLE_CUSTOMSYSCALLS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These functions are copied from glibc, android libc, apple libc open source code.
 * This is to avoid easy bypass through libc functions
 */

size_t my_strlcpy(char *dst, const char *src, size_t siz);

size_t my_strlen(const char *s);

int my_strncmp(const char *s1, const char *s2, size_t n);

char* my_strstr(const char *s, const char *find);

void*  my_memset(void*  dst, int c, size_t n);

int my_strcmp(const char *s1, const char *s2);

int my_atoi(const char *s);

char * my_strtok_r(char *s, const char *delim, char **last);

#ifdef __cplusplus
}
#endif

#endif //ANTIANALYSISPROOFSAMPLE_CUSTOMSYSCALLS_H
