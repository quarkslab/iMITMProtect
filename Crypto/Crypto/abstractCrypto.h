//
//  abstractCrypto.h
//  Crypto
//
//  Created by Marc DENTY on 22/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__abstractCrypto__
#define __Crypto__abstractCrypto__

#include <iostream>
#include <gcrypt.h>
#include <string.h>
#include "base64.h"

class abstractCrypto {
    static bool initDone;
public:
    char* getLibVersion(char* version) {
        strcpy(version, gcry_check_version(NULL));
        printf("Using libgcrypt version %s\n", version);
        return version;
    }
    
    abstractCrypto() {
        if(!initDone) {
            if(CRYPTO_DEBUG) printf("Init libgcrypt\n");
            initDone = true;
            gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
            gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
            gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
            gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
            gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        } else {
            if(CRYPTO_DEBUG) printf("Init libgcrypt already done\n");            
        }
    }
    
    void check_error(gcry_error_t err)
    {
        if (err)
        {
            fprintf (stderr, "Failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
            exit(1);
        }
    }
    
    void toHexString(const u_char* binary, char* hexString, size_t size) {
        int j=0;
        for (int i=0; i<size; ++i) {
            int h = ((binary[i] & 0xF0) >> 4);
            int l = (binary[i] & 0xF);
            hexString[j++] = h<10 ? ('0'+h) : ('A'+h-10) ;
            hexString[j++] = l<10 ? ('0'+l) : ('A'+l-10) ;
        }
        hexString[j] = 0;
    }
    
    /**
     * You must free() the returned pointer !!!
     */
    char* toBase64(const u_char* binary, size_t size) {
        size_t b64Len = size * 4/3 + 4;
        char* b64 = (char*) malloc(b64Len);
        if(b64) {
            memset(b64, 0, b64Len);
            if(-1 == base64Encode(binary, size, b64, b64Len)) {
                free(b64);
                b64 = NULL;
                if(CRYPTO_DEBUG) printf("base64 encode failed\n");
            }
            return b64;
        } else {
            if(CRYPTO_DEBUG) printf("base64 encode malloc failed\n");
            return NULL;
        }
    }
    
    /**
     * You must free() the returned pointer !!!
     */
    u_char* fromBase64(const char* b64, size_t* size) {
        size_t biLen = strlen(b64) * 3/4 + 4;
        u_char* bi = (u_char*) malloc(biLen);
        if(bi) {
            memset(bi, 0, biLen);
            *size = base64Decode(b64, bi, biLen);
            if(-1 == *size) {
                free(bi);
                bi = NULL;
                if(CRYPTO_DEBUG) printf("base64 decode failed\n");
            }
            return bi;
        } else {
            if(CRYPTO_DEBUG) printf("base64 decode malloc failed\n");
            return NULL;
        }
    }
    
    void print_sexp(gcry_sexp_t exp);
};

#endif /* defined(__Crypto__abstractCrypto__) */
