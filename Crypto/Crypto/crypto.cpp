//
//  crypto.cpp
//  Crypto
//
//  Created by Marc DENTY on 28/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include "crypto.h"

char* Crypto::decryptAndVerifyMessage(const char* whole, rsa* crypter, rsa* signer) {
    // parse base 64 input
    size_t wholeSize = strlen(whole);
    size_t nonceLen;
    size_t keyLen;
    size_t messageLen;
    size_t signatureLen;
    int state = 0;
    int len = 0;
    for(int i=0; i<wholeSize; ++i) {
        ++len;
        if(whole[i] == '\n') {
            switch (state) {
                case 0:
                    nonceLen = len;
                    break;
                case 1:
                    keyLen = len;
                    break;
                case 2:
                    messageLen = len;
                    break;
                case 3:
                    signatureLen = len;
                    break;
                default:
                    printf("unknown case detected : %d\n", state);
                    break;
            }
            state ++;
            len = 0;
        }
    }
    char nonce[nonceLen];
    char key[keyLen];
    char message[messageLen];
    char signature[signatureLen];
    state = 0;
    len = 0;
    for(int i=0; i<wholeSize; ++i) {
        char c = whole[i];
        c = (c == '\n' ? 0 : c);
        switch (state) {
            case 0:
                nonce[len] = c;
                break;
            case 1:
                key[len] = c;
                break;
            case 2:
                message[len] = c;
                break;
            case 3:
                signature[len] = c;
                break;
            default:
                printf("unknown case detected : %d\n", state);
                break;
        }
        if(c == 0) {
            state ++;
            len = 0;
        } else {
            ++len;
        }
    }
    if(CRYPTO_DEBUG) {
        printf("nonce=%s\n", nonce);
        printf("key=%s\n", key);
        printf("message=%s\n", message);
        printf("signature=%s\n", signature);
    }
    // End parsing base 64 file
    
    //verify message signature
    if(! signer->verify(message, signature)) {
        if(CRYPTO_DEBUG) printf("signature is KO\n");
    }
    
    aes aes;
    // decrypt nonce
    size_t size;
    u_char buffer[512];
    u_char* nonceCrypted = fromBase64(nonce, &size);
    if(nonceCrypted == NULL) return NULL;
    size = crypter->decrypt(nonceCrypted, size, buffer, 512);
    aes.setIV(buffer);
    free(nonceCrypted);
    
    //decrypt session key
    u_char* keyCrypted = fromBase64(key, &size);
    if(keyCrypted == NULL) return NULL;
    size = crypter->decrypt(keyCrypted, size, buffer, 512);
    aes.setKey(buffer);
    free(keyCrypted);
    
    aes.dumpKey();
    aes.dumpNonce();

    
    //decrypt message
    u_char* messageCrypted = fromBase64(message, &size);
    if(messageCrypted == NULL) return NULL;
    u_char* plainText = (u_char*)malloc(size);
    if(plainText == NULL) {
        free(messageCrypted);
        if(CRYPTO_DEBUG) printf("cannot allocate memory for plain text\n");
        return NULL;
    }
    aes.decrypt(messageCrypted, plainText, size);
    plainText[size] = 0;
    free(messageCrypted);
    return (char*) plainText;
}


char* Crypto::cryptAndSignMessage(const char* message, rsa* crypter, rsa* signer) {
    size_t messageLen = strlen(message);
    size_t cipherTextLen = messageLen + 257;
    u_char* cipherText = (u_char*)malloc(cipherTextLen);
    if(cipherText == NULL) {
        if(CRYPTO_DEBUG) printf("cannot allocate memory for aes cipher text\n");
        return NULL;
    }
    // Generate session key
    aes aes;
    aes.generateKey();
    aes.dumpKey();
    aes.dumpNonce();
    
    //Encrypt message with session key
    size_t messageSize = aes.encrypt((u_char*)message, strlen(message), cipherText, cipherTextLen);
    char* messageBase64 = toBase64(cipherText, messageSize);
    free(cipherText);
    if(messageBase64 == NULL) {
        return NULL;
    }
    
    
    //Encrypt session key
    u_char buffer[512];
    size_t size = crypter->encrypt(aes.getKey(), aes.getKeyLen(), buffer, 512);
    char* cipherKeyBase64 = toBase64(buffer, size);
    if(cipherKeyBase64 == NULL) {
        return NULL;
    }
    
    //Encrypt nonce
    size = crypter->encrypt(aes.getIV(), aes.getNonceLen(), buffer, 512);
    char* cipherNonceBase64 = toBase64(buffer, size);
    if(cipherNonceBase64 == NULL) {
        return NULL;
    }

    //Sign message
    char* signatureBase64 = signer->sign(messageBase64);
    if(signatureBase64 == NULL) {
        return NULL;
    }
    
    //Generate the whole thing
    char* whole = (char*)malloc(strlen(messageBase64) + strlen(cipherKeyBase64) + strlen(cipherNonceBase64) + strlen(signatureBase64) + 4);
    if(whole) {
        sprintf(whole, "%s\n%s\n%s\n%s\n", cipherNonceBase64, cipherKeyBase64, messageBase64, signatureBase64);
        free(cipherKeyBase64);
        free(cipherNonceBase64);
        free(messageBase64);
        free(signatureBase64);
        return whole;
    } else {
        free(cipherKeyBase64);
        free(cipherNonceBase64);
        free(messageBase64);
        free(signatureBase64);
        if(CRYPTO_DEBUG) printf("Cannot allocate memory for concatenation/n");
        return NULL;
    }
}
