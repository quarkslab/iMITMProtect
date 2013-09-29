//
//  crypto.h
//  Crypto
//
//  Created by Marc DENTY on 28/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__crypto__
#define __Crypto__crypto__

#include <iostream>
#import  "rsa.h"
#import  "aes.h"

class Crypto : public abstractCrypto {
    
public:
    Crypto() {}
    virtual ~Crypto() {}
    
    
    char* cryptAndSignMessage(const char* message, rsa* crypter, rsa* signer);
    char* decryptAndVerifyMessage(const char* message, rsa* crypter, rsa* signer);
    
};

#endif /* defined(__Crypto__crypto__) */
