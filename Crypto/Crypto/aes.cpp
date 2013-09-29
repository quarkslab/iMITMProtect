//
//  aes.cpp
//  Crypto
//
//  Created by Marc DENTY on 23/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include "aes.h"
#include "Debug.h"

void aes::generateKey() {
    //Symmetric key generation (128 bit)
    if(CRYPTO_DEBUG) printf("Generating symmetric key (%d bit)...\n", bits);
    
    //Use secure random number generation
    gcry_randomize(key, keyLength, GCRY_STRONG_RANDOM);
    gcry_randomize(iv, blkLength, GCRY_STRONG_RANDOM);

    setKey(key);
}

size_t aes::encrypt(unsigned char *plainText, size_t dataLength, unsigned char *cipherText, size_t cipherTextBufferLen) {
    Debug d("encrypt");
    gcry_error_t err;
    err = gcry_cipher_setiv(hd, iv, blkLength);
    check_error(err);
    err = gcry_cipher_setctr(hd, iv, blkLength);
    check_error(err);
    memset(cipherText, 0xAA, cipherTextBufferLen);
    err = gcry_cipher_encrypt(
                                    hd, // gcry_cipher_hd_t
                                    cipherText,    // void *
                                    cipherTextBufferLen,    // size_t
                                    plainText,    // const void *
                                    dataLength);   // size_t
    check_error(err);
    unsigned char* p = cipherText + cipherTextBufferLen;
    size_t len = cipherTextBufferLen;
    while(*--p == 0xAA) {
        --len;
        *p = 0;
    }
    return len;
}

void aes::decrypt(unsigned char *cipherText, unsigned char *plainText, size_t plainTextBufferLen) {
    Debug d("decrypt");
    gcry_error_t err;
    
    err = gcry_cipher_setiv(hd, iv, blkLength);
    check_error(err);
    err = gcry_cipher_setctr(hd, iv, blkLength);
    check_error(err);
    err = gcry_cipher_decrypt(
                                           hd, // gcry_cipher_hd_t
                                           plainText,    // void *
                                           plainTextBufferLen,    // size_t
                                           cipherText,    // const void *
                                           plainTextBufferLen);   // size_t
    check_error(err);
}