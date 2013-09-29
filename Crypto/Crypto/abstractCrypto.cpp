//
//  abstractCrypto.cpp
//  Crypto
//
//  Created by Marc DENTY on 22/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include "abstractCrypto.h"

bool abstractCrypto::initDone = false;

void abstractCrypto::print_sexp(gcry_sexp_t exp)
{
	if(CRYPTO_DEBUG){
        char *str;
        size_t size = 2000;
        int i;
        
        str = (char *) malloc(sizeof(char)*size);
        
        size = gcry_sexp_sprint(exp, GCRYSEXP_FMT_ADVANCED, str, 2000);
        printf("size = %zd\n", size);
        for(i = 0; i < size; i++)
            printf("%c", str[i]);
        printf("\n");
        
        free(str);
    }
}
