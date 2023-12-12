//
// Created by Thom on 2019/3/20.
//

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <sys/system_properties.h>
#include "common.h"
// #include "handle-error.h"
#include "plt.h"

static inline void fill_ro_build_version_sdk(char v[]) {
    // ro.build.version.sdk
    static unsigned int m = 0;

    if (m == 0) {
        m = 19;
    } else if (m == 23) {
        m = 29;
    }

    v[0x0] = 's';
    v[0x1] = 'm';
    v[0x2] = '-';
    v[0x3] = 'f';
    v[0x4] = 'p';
    v[0x5] = 'o';
    v[0x6] = 'k';
    v[0x7] = 'l';
    v[0x8] = '\'';
    v[0x9] = '|';
    v[0xa] = 'n';
    v[0xb] = '~';
    v[0xc] = '~';
    v[0xd] = 'g';
    v[0xe] = '`';
    v[0xf] = '~';
    v[0x10] = '?';
    v[0x11] = 'a';
    v[0x12] = 'd';
    v[0x13] = 'j';
    for (unsigned int i = 0; i < 0x14; ++i) {
        v[i] ^= ((i + 0x14) % m);
    }
    v[0x14] = '\0';
}

int getSdk() {
    static int sdk = 0;
    if (sdk == 0) {
        char v1[0x20];
        char prop[PROP_VALUE_MAX] = {0};
        fill_ro_build_version_sdk(v1);
        __system_property_get(v1, prop);
        sdk = (int) strtol(prop, NULL, 10);
    }
    return sdk;
}

