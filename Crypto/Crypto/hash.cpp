//
//  hash.cpp
//  Crypto
//
//  Created by Marc DENTY on 29/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include "hash.h"

char* Hash::hash(const char* message) {
    gcry_md_write (hd, message, strlen(message));
    gcry_md_final (hd);
    u_char* digest = gcry_md_read (hd, algo);
    size_t size = gcry_md_get_algo_dlen(algo);
    char *hexString = (char*)malloc(size * 2 + 3);
    if(hexString) {
        toHexString(digest, hexString, size);
        return hexString;
    } else {
        printf("malloc failed in hash function\n");
        return NULL;
    }
}
