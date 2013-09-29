 //
//  rsa.cpp
//  Crypto
//
//  Created by Marc DENTY on 22/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include "rsa.h"
#include "base64.h"
#include "hash.h"
#include <sys/stat.h>
#include <sys/types.h>

char* rsa::base64ToHexNumber(const char* base64Encoded) {
    size_t len = strlen(base64Encoded);
    u_char* binaryKey = (u_char*) malloc(len);
    char* hexString = NULL;
    if(binaryKey) {
        size_t size = base64Decode(base64Encoded, binaryKey, len);
        size_t hexStringSize = 2*size + 1;
        hexString = (char*)malloc(hexStringSize);
        if(hexString) {
            toHexString(binaryKey, hexString, size);
            hexString[size + 1] = 0;
        }
    }
    free(binaryKey);
    return hexString;
}

void rsa::savePrivateKey(const char *file) {
    PRIVATE_KEY skey;
    fillFromPrivateKey(&skey);
    char* b64SKey = toBase64((const u_char*)&skey, sizeof(PRIVATE_KEY));
    if(b64SKey) {
        FILE* f = fopen(file, "w");
        fwrite(b64SKey, 1, strlen(b64SKey), f);
        fclose(f);
        free(b64SKey);
    }
}

void rsa::savePublicKey(const char *file) {
    PUBLIC_KEY pkey;
    fillFromPublicKey(&pkey);
    char* b64PKey = toBase64((const u_char*)&pkey, sizeof(PUBLIC_KEY));
    if(b64PKey) {
        FILE* f = fopen(file, "w");
        fwrite(b64PKey, 1, strlen(b64PKey), f);
        fclose(f);
        free(b64PKey);
    }
    
}

u_char* rsa::loadBase64File(const char *file) {
    struct stat st;
    if(0==stat(file, &st)) {
        char* b64 = (char*)malloc(st.st_size + 1);
        if(b64) {
            FILE* f = fopen(file, "r");
            fread(b64, 1, st.st_size, f);
            *(b64 + st.st_size) = 0;
            fclose(f);
            size_t len;
            u_char* k = fromBase64(b64, &len);
            free(b64);
            return k;
        } else {
            if(CRYPTO_DEBUG) printf("malloc failed in loadBase64File(%s) : cannot allocate %lld bytes\n", file, st.st_size+1);
            return NULL;
        }
    } else {
        if(CRYPTO_DEBUG) printf("stat failed in loadBase64File(%s)\n", file);
        return NULL;
    }
    
}

bool rsa::loadPrivateKey(const char *file) {
    u_char* k = loadBase64File(file);
    if(k) {
        setPrivateKey((PRIVATE_KEY*)k);
        free(k);
        return true;
    }
    return false;
}

bool rsa::loadPublicKey(const char *file) {
    u_char* k = loadBase64File(file);
    if(k) {
        setPublicKey((PUBLIC_KEY*)k);
        free(k);
        return true;
    }
    return false;
}


void rsa::setPublicKey(PUBLIC_KEY* pkey) {
    size_t errorff;
    int ret = gcry_sexp_build(&pubk, &errorff, "(public-key (rsa (n%b) (e%b)))",
                              pkey->nLen, pkey->n,
                              pkey->eLen, pkey->e);
    check_error(ret);
}

void rsa::setPrivateKey(PRIVATE_KEY* skey) {
    size_t errorff;
    
    int ret = gcry_sexp_build(&seck, &errorff, "(private-key (rsa (n%b) (e%b) (d%b) (p%b) (q%b) (u%b)))",
                              skey->nLen, skey->n,
                              skey->eLen, skey->e,
                              skey->dLen, skey->d,
                              skey->pLen, skey->p,
                              skey->qLen, skey->q,
                              skey->uLen, skey->u
                              );
    check_error(ret);
    print_sexp(seck);
}

void rsa::fillFromElement(gcry_sexp_t key, const char* token, u_char* element, size_t* elementSize) {
	gcry_sexp_t n = gcry_sexp_find_token(key, token, 0);
    gcry_mpi_t plain;
    if(n) {
        plain = gcry_sexp_nth_mpi (n, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release(n);
    } else {
        plain = gcry_sexp_nth_mpi (n, 0, GCRYMPI_FMT_USG);
    }
    gcry_mpi_print (GCRYMPI_FMT_USG, element, 4096, elementSize, plain);
}

void rsa::fillFromPrivateKey(PRIVATE_KEY* skey) {
    memset(skey, 0, sizeof(PRIVATE_KEY));
    fillFromElement(seck, "n", skey->n, &skey->nLen);
    fillFromElement(seck, "e", skey->e, &skey->eLen);
    fillFromElement(seck, "d", skey->d, &skey->dLen);
    fillFromElement(seck, "p", skey->p, &skey->pLen);
    fillFromElement(seck, "q", skey->q, &skey->qLen);
    fillFromElement(seck, "u", skey->u, &skey->uLen);
}

void rsa::fillFromPublicKey(PUBLIC_KEY* skey) {
    memset(skey, 0, sizeof(PUBLIC_KEY));
    fillFromElement(pubk, "n", skey->n, &skey->nLen);
    fillFromElement(pubk, "e", skey->e, &skey->eLen);
}



void rsa::generateKeys(unsigned int bits) {
    gcry_sexp_t gkey, par;
    //    size_t errorff;
    char str[96];
    sprintf(str, "(genkey (%s (nbits 4:%d)))", ALG, bits);
    if(CRYPTO_DEBUG) printf("s-exp for genkey : %s\n", str);
	int ret = gcry_sexp_new(&gkey, str, strlen(str), 1);
	check_error(ret);
    ret = gcry_pk_genkey(&par, gkey);
	check_error(ret);
    
	pubk = gcry_sexp_find_token(par, "public-key", 0);
	seck = gcry_sexp_find_token(par, "private-key", 0);
    
    gcry_sexp_release(gkey);
    gcry_sexp_release(par);
}

size_t rsa::encrypt(unsigned char* plainText, size_t dataLength, unsigned char* cipherText, size_t cipherTextBufferLen) {
    /*
	 * Preparing data for encrypting
	 */
    size_t errorff;
    gcry_sexp_t raw_data, enc_data, raw_enc_data;
    
	if(CRYPTO_DEBUG) printf("S-expression to encrypt:\n");
	
	gcry_error_t ret = gcry_sexp_build(&raw_data, &errorff, "(data (flags %s) (value %b))", PADDING, dataLength, plainText);
	check_error(ret);
	print_sexp(raw_data);
    
	/*
	 * Encrypting data
	 */
	if(CRYPTO_DEBUG) printf("Encrypting data.....\n");
	ret = gcry_pk_encrypt(&enc_data, raw_data, pubk);
    gcry_sexp_release(raw_data);
	check_error(ret);
	if(CRYPTO_DEBUG) printf("Encryption finished!\n");
    
	if(CRYPTO_DEBUG) printf("Encrypted data:\n");
	print_sexp(enc_data);
    raw_enc_data = gcry_sexp_find_token(enc_data, ALG, 0);
    print_sexp(raw_enc_data);
    gcry_sexp_release(enc_data);
    
    memset(cipherText, 0, cipherTextBufferLen);
    gcry_sexp_t _plain = gcry_sexp_find_token(raw_enc_data, "a", 0);
    gcry_mpi_t plain;
    if(_plain) {
        plain = gcry_sexp_nth_mpi (_plain, 1, GCRYMPI_FMT_USG);
        if(CRYPTO_DEBUG) printf("_plain is not null\n");
        gcry_sexp_release(_plain);
    } else {
        plain = gcry_sexp_nth_mpi (raw_enc_data, 0, GCRYMPI_FMT_USG);
        if(CRYPTO_DEBUG) printf("_plain is null\n");
    }
    gcry_sexp_release(raw_enc_data);
    size_t nwritten;
    ret = gcry_mpi_print (GCRYMPI_FMT_STD, cipherText, cipherTextBufferLen, &nwritten, plain);
    check_error(ret);
    gcry_mpi_release(plain);
    return nwritten;
}

size_t rsa::decrypt(unsigned char* cipherText, size_t cipherTextLen, unsigned char* plainText, size_t plainTextBufferLen) {
    size_t errorff;
    gcry_sexp_t dec_data, to_dec_func, raw_enc_data;
    
    gcry_error_t ret = gcry_sexp_build(&raw_enc_data, &errorff, "(%s (a %b))", ALG, cipherTextLen, cipherText);
	check_error(ret);
    
    if(strcmp(ALG, "rsa") == 0) {
        ret = gcry_sexp_build(&to_dec_func, &errorff, "(enc-val (flags %s) %S)", PADDING, raw_enc_data);
    } else {
        ret = gcry_sexp_build(&to_dec_func, &errorff, "(enc-val %S)", raw_enc_data);
    }
    gcry_sexp_release(raw_enc_data);
	check_error(ret);
	if(CRYPTO_DEBUG) printf("S-expression to decrypt:\n");
	print_sexp(to_dec_func);
    
    if(CRYPTO_DEBUG) printf("Decrypting data...\n");
	ret = gcry_pk_decrypt(&dec_data, to_dec_func, seck);
    gcry_sexp_release(to_dec_func);
	check_error(ret);
	if(CRYPTO_DEBUG) printf("Decryption finished!\n");
	print_sexp(dec_data);
    
    memset(plainText, 0, plainTextBufferLen);
    gcry_sexp_t _plain = gcry_sexp_find_token(dec_data, "value", 0);
    gcry_mpi_t plain;
    if(_plain) {
        plain = gcry_sexp_nth_mpi (_plain, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release(_plain);
    } else {
        plain = gcry_sexp_nth_mpi (dec_data, 0, GCRYMPI_FMT_USG);
    }
    gcry_sexp_release(dec_data);
    size_t nwritten;
    ret = gcry_mpi_print (GCRYMPI_FMT_USG, plainText, plainTextBufferLen, &nwritten, plain);
    check_error(ret);
    gcry_mpi_release(plain);
    if(CRYPTO_DEBUG) printf("Plain text is %s, written %zd\n", plainText, nwritten);
    return nwritten;
}

static int
do_encode_md (const u_char * md, size_t mdlen, int algo, gcry_sexp_t * r_hash,
              int raw_value)
{
    gcry_sexp_t hash;
    int rc;
    
    if (!raw_value)
    {
        const char *s;
        char tmp[16+1];
        int i;
        
        s = gcry_md_algo_name (algo);
        if (s && strlen (s) < 16)
        {
            for (i=0; i < strlen (s); i++)
                tmp[i] = tolower (s[i]);
            tmp[i] = '\0';
        }
        
        if(CRYPTO_DEBUG) printf("Algo name is %s\n", tmp);
        
        rc = gcry_sexp_build (&hash, NULL,
                              "(data (flags pkcs1) (hash %s %b))",
                              tmp, (int)mdlen, md);
    }
    else
    {
        gcry_mpi_t mpi;
        
        rc = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, md, mdlen, NULL);
        if (! rc)
        {
            rc = gcry_sexp_build (&hash, NULL,
                                  "(data (flags raw) (value %m))",
                                  mpi);
            gcry_mpi_release (mpi);
        }
        
    }
    
    *r_hash = hash;
    return rc;
}

char* rsa::sign(const char *message) {
    gcry_sexp_t sign_parms, sig;
    size_t errof;
    gcry_error_t rc;
    
    Hash hash(GCRY_MD_SHA256);
    char* h = hash.hash(message);
    if(CRYPTO_DEBUG) printf("Signature\n");
    if(CRYPTO_DEBUG) printf("message = %s\n", message);
    if(CRYPTO_DEBUG) printf("hash = %s\n", h);
    //size_t hash_len = gcry_md_get_algo_dlen( GCRY_MD_SHA256 );
    
    rc = gcry_sexp_build (&sign_parms, &errof,
                          "(data (flags raw) (value %b))\n", strlen(h), h);
    check_error(rc);
    
    free(h);
    
    rc = gcry_pk_sign (&sig, sign_parms, seck);
    check_error(rc);
    if(CRYPTO_DEBUG) printf("Signature SEXP from gcry_pk_sign\n");
    print_sexp(sig);
    
    gcry_sexp_release(sign_parms);
    
    gcry_sexp_t _plain = gcry_sexp_find_token(sig, "s", 0);
    gcry_mpi_t sig_mpi;
    if(_plain) {
        sig_mpi = gcry_sexp_nth_mpi (_plain, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release(_plain);
    } else {
        sig_mpi = gcry_sexp_nth_mpi (sig, 0, GCRYMPI_FMT_USG);
    }
    gcry_sexp_release(sig);
    
    size_t nwritten;
    u_char signature[1024];
    rc = gcry_mpi_print (GCRYMPI_FMT_USG, signature, 1024, &nwritten, sig_mpi);
    check_error(rc);
    
    
    return toBase64(signature, nwritten);
}

bool rsa::verify(const char* message, const char* signature) {
    gcry_error_t rc;
    gcry_sexp_t sign_parms, sign;
    size_t errof;
    
    Hash hash1(GCRY_MD_SHA256);
    char* h1 = hash1.hash(message);
    if(CRYPTO_DEBUG) printf("Verification de signature\n");
    if(CRYPTO_DEBUG) printf("message = %s\n", message);
    if(CRYPTO_DEBUG) printf("hash = %s\n", h1);
    rc = gcry_sexp_build (&sign_parms, &errof,
                          "(data (flags raw) (value %b))\n", strlen(h1), h1);
    check_error(rc);
    free(h1);
    
    size_t size;
    u_char* sig = fromBase64(signature, &size);
    rc = gcry_sexp_build(&sign, &errof, "(sig-val (rsa (s %b)))", size, sig);
    free(sig);
    check_error(rc);
    
    if(CRYPTO_DEBUG) printf("Signature SEXP from base64\n");
    print_sexp(sign);
    
    rc = gcry_pk_verify (sign, sign_parms, pubk);
    
    gcry_sexp_release(sign);
    gcry_sexp_release(sign_parms);
    if(rc != 0) {
        check_error(rc);
        return false;
    }
    return true;
}
