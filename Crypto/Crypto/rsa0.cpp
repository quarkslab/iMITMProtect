//
//  rsa.c
//  Crypto
//
//  Created by Marc DENTY on 22/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#define TAM_DADO 20
#define ALG "rsa"
#define BITS "256"
//#define PADDING "pkcs1"
#define PADDING "oaep"

#define GCRYPT_NO_DEPRECATED

#include <gcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include "rsa0.h"

void checa_erro(gcry_error_t err)
{
	if (err)
	{
		fprintf (stderr, "Failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		exit(1);
	}
}

void print_sexp(gcry_sexp_t exp)
{
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

void die( const char *str ){
    fprintf( stderr, "[ERROR] %s\n",str );
    exit(1);
}

void sexpToChar( gcry_sexp_t s_exp, char * txtexp, int lenght ) {
    if( gcry_sexp_sprint( s_exp, GCRYSEXP_FMT_ADVANCED, txtexp, lenght ) == 0 )
        die( "conversion error of text" );
}

int rsaTest()
{
	const char *version;
	gcry_sexp_t pubk, seck, par, enc_data, dec_data, to_dec_func, raw_data, raw_enc_data, gkey;
    char *dado;
	int i;
	size_t errorff;
	gcry_error_t ret;
    
	version = gcry_check_version(NULL);
	printf("Using libgcrypt version %s\n", version);
    
	/*
	 * Initialize libgcrypt
	 */
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
	/*
	 * Create a data block to be encrypted
	 */
    
	dado = (char*) malloc(sizeof(char)*TAM_DADO);
    
	printf("Creating data block:.\n");
    /*
	for(i = 0; i < TAM_DADO; i++)
	{
		dado[i] = (unsigned char) i;
		printf("[%X]", dado[i]);
	}*/
    strcpy(dado, "Fuck Yeah !");
    
	printf("\n");
	fflush(stdout);
    
	/*
	 * Generate keys
	 */
    
	ret = gcry_sexp_build(&gkey, &errorff, "(genkey (%s (nbits %s)))", ALG, BITS);
	checa_erro(ret);
    
	printf("S-expression of keys:\n");
	print_sexp(gkey);
	printf("Generating key pair....\n");
    
	ret = gcry_pk_genkey(&par, gkey);
	checa_erro(ret);
	printf("Keys generated!\nThe key pair is:\n");
	print_sexp(par);
    
	pubk = gcry_sexp_find_token(par, "public-key", 0);
	seck = gcry_sexp_find_token(par, "private-key", 0);
    
	printf("Public key:\n");
	print_sexp(pubk);
    
	printf("Private key:\n");
	print_sexp(seck);
    
	/*
	 * Preparing data for encrypting
	 */
    
	printf("S-expression to encrypt:\n");
	
	ret = gcry_sexp_build(&raw_data, &errorff, "(data (flags %s) (value %b))", PADDING, TAM_DADO, dado);
	checa_erro(ret);
	print_sexp(raw_data);
    
	/*
	 * Encrypting data
	 */
	printf("Encrypting data.....\n");
	ret = gcry_pk_encrypt(&enc_data, raw_data, pubk);
	checa_erro(ret);
	printf("Encryption finished!\n");
    
	printf("Encrypted data:\n");
	print_sexp(enc_data);
    
	/*
	 * Decrypting data
	 */
	printf("Isolating encrypted data:\n");
	raw_enc_data = gcry_sexp_find_token(enc_data, ALG, 0);
	print_sexp(raw_enc_data);
    
	ret = gcry_sexp_build(&to_dec_func, &errorff, "(enc-val (flags %s) %S)", PADDING, raw_enc_data);
	checa_erro(ret);
	printf("S-expression to decrypt:\n");
	print_sexp(to_dec_func);
	
	printf("Decrypting data...\n");
	ret = gcry_pk_decrypt(&dec_data, to_dec_func, seck);
	checa_erro(ret);
	printf("Decryption finished!\n");
	print_sexp(dec_data);
    
    char __plain[256];
    memset(__plain, 0, 256);
    
    memset(__plain, 0, 256);
    gcry_sexp_t _plain = gcry_sexp_find_token(dec_data, "value", 0);
    gcry_mpi_t plain;
    if(_plain) {
        plain = gcry_sexp_nth_mpi (_plain, 1, GCRYMPI_FMT_USG);
        printf("_plain is not null\n");
        gcry_sexp_release(_plain);
    } else {
        plain = gcry_sexp_nth_mpi (dec_data, 0, GCRYMPI_FMT_USG);
        printf("_plain is null\n");
        
    }
    size_t nwritten;
    gcry_mpi_print (GCRYMPI_FMT_USG, (unsigned char*)__plain, 256, &nwritten, plain);
    printf("Plain text is %s, written %zd\n", __plain, nwritten);

	/*
	 * Free memory
	 */
	printf("Freeing memory.\n");
	fflush(stdout);
	gcry_sexp_release(par);
	gcry_sexp_release(gkey);
	gcry_sexp_release(seck);
	gcry_sexp_release(pubk);
	gcry_sexp_release(raw_data);
	gcry_sexp_release(raw_enc_data);
	gcry_sexp_release(to_dec_func);
	gcry_sexp_release(enc_data);
	gcry_sexp_release(dec_data);
    
	gcry_control(GCRYCTL_TERM_SECMEM);
    
	printf("Done!\n");
	fflush(stdout);
	free(dado);
    
	return 0;
}