//
//  Debug.h
//  Crypto
//
//  Created by Marc DENTY on 23/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__Debug__
#define __Crypto__Debug__

#include <iostream>

class Debug {
private:
    char* sInfo;
    
public:
    
    Debug(const char* info) {
        if(CRYPTO_DEBUG) {
            sInfo = strdup(info);
            printf("Entering %s\n", info);
        }
    }
    virtual ~Debug() {
        if(CRYPTO_DEBUG) {
            printf("Exiting %s\n", sInfo);
            free(sInfo);
        }
    }
};
#endif /* defined(__Crypto__Debug__) */
