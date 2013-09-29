//
//  hash.h
//  Crypto
//
//  Created by Marc DENTY on 29/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#ifndef __Crypto__hash__
#define __Crypto__hash__

#include <iostream>
#import  "abstractCrypto.h"

class Hash : public abstractCrypto {
    gcry_md_hd_t hd;
    int algo;
public:
    Hash(int algo) {
        this->algo = algo;
        gcry_error_t ret = gcry_md_open (&hd, algo, GCRY_MD_FLAG_SECURE);
        check_error(ret);
        ret = gcry_md_enable (hd, algo);
        check_error(ret);
    }
    
    virtual ~Hash() {
        gcry_md_close(hd);
    }

    char* hash(const char* message);
    char* hash(const u_char* message, size_t len);
};

#endif /* defined(__Crypto__hash__) */
