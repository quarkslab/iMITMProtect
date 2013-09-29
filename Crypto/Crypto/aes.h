//
//  aes.h
//  Crypto
//
//  Created by Marc DENTY on 23/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__aes__
#define __Crypto__aes__

#include <iostream>
#import "abstractCrypto.h"

class aes : public abstractCrypto {
private:
    int bits;
    unsigned char* key;
    unsigned char* iv;
    gcry_cipher_hd_t hd;
    size_t keyLength;
    size_t blkLength;

public:
    aes() {
        bits = 256;
        keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
        blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
        key = (u_char*) malloc(keyLength);
        iv = (u_char*) malloc(blkLength);
        
        gcry_error_t err = gcry_cipher_open(
                                     &hd, // gcry_cipher_hd_t *
                                     GCRY_CIPHER_AES256,       // int
                                     GCRY_CIPHER_MODE_CTR,     // int
                                     GCRY_CIPHER_SECURE);      // unsigned int
        check_error(err);
    }
    virtual ~aes() {
        if(key) free(key);
        if(iv) free(iv);
        gcry_cipher_close(hd);
    }
    
    void setKey(const u_char* k) {
        if(k) {
            memcpy(key, k, keyLength);
            gcry_error_t err = gcry_cipher_setkey(hd, key, keyLength);
            check_error(err);
        }
    }
    void dumpKey() {
        if(CRYPTO_DEBUG) {
            printf("Key : ");
            for(int i=0; i<keyLength; ++i) {
                printf("%02x", key[i]);
            }
            printf("\n");
        }
    }
    void dumpNonce() {
        if(CRYPTO_DEBUG) {
            printf("Nonce : ");
            for(int i=0; i<blkLength; ++i) {
                printf("%02x", iv[i]);
            }
            printf("\n");
        }
    }
    void setIV(unsigned char* nonce) {
        if(nonce) {
            memcpy(iv, nonce, blkLength);
        }
    }
    unsigned char* getKey() { return key; }
    unsigned char* getIV() { return iv; }
    
    size_t getKeyLen() { return keyLength; }
    size_t getNonceLen() { return blkLength; }
    
    void generateKey();
    size_t encrypt(unsigned char* plainText, size_t dataLength, unsigned char* cipherText, size_t cipherTextBufferLen);
    void decrypt(unsigned char* cipherText, unsigned char* plainText, size_t plainTextBufferLen);


};

#endif /* defined(__Crypto__aes__) */
