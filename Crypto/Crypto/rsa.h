//
//  rsa.h
//  Crypto
//
//  Created by Marc DENTY on 22/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__rsa__
#define __Crypto__rsa__

#include <iostream>
#include <gcrypt.h>
#import "abstractCrypto.h"

//#define ALG "elg"
#define ALG "rsa"
#define PADDING "pkcs1"
#define HASH "sha256"
//#define PADDING "oaep"

typedef struct {
    size_t nLen;
    size_t eLen;
    size_t dLen;
    size_t pLen;
    size_t qLen;
    size_t uLen;

    u_char n[256];
    u_char e[16];
    u_char d[256];
    u_char p[128];
    u_char q[128];
    u_char u[128];
} PRIVATE_KEY;

typedef struct {
    size_t nLen;
    size_t eLen;

    u_char n[256];
    u_char e[16];
} PUBLIC_KEY;

class rsa : public abstractCrypto {
private:
    int bits;
    gcry_sexp_t pubk, seck;
    char* base64ToHexNumber(const char* base64Encoded);
    void fillFromElement(gcry_sexp_t key, const char* token, u_char* element, size_t* elementSize);
    u_char* loadBase64File(const char* file);
    
public:
    rsa() {
        
    }
    
    virtual ~rsa() {
        
    }
    void setPublicKey(PUBLIC_KEY* pkey);
    void setPrivateKey(PRIVATE_KEY* skey);

    void generateKeys(unsigned int bits);
    size_t encrypt(unsigned char* plainText, size_t dataLength, unsigned char* cipherText, size_t cipherTextBufferLen);
    size_t decrypt(unsigned char* cipherText, size_t cipherTextLen, unsigned char* plainText, size_t plainTextBufferLen);
    char* sign(const char* message);
    bool verify(const char* message, const char* signature);

    void fillFromPublicKey(PUBLIC_KEY* skey);
    void fillFromPrivateKey(PRIVATE_KEY* skey);
    void savePrivateKey(const char* file);
    void savePublicKey(const char *file);
    
    bool loadPrivateKey(const char* file);
    bool loadPublicKey(const char* file);

};

#endif /* defined(__Crypto__rsa__) */
