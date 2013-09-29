//
//  main.cpp
//  Crypto
//
//  Created by Marc DENTY on 21/09/13.
//  Copyright (c) 2013 Xvolks. All rights reserved.
//

#include <iostream>
#import  "crypto.h"


int main(int argc, const char * argv[])
{
    std::cout << "Hello, World!\n";
    
    char version[64];    
    rsa myRSA;
    myRSA.getLibVersion(version);
    printf( "Libgcrypt Test.\nVersion: %s\n", version );
    
    //Loading my key pair from disk or generate it.
    char* home = getenv("HOME");
    char pubKey[512];
    char secKey[512];
    strcpy(pubKey, home);
    strcat(pubKey, "/pubKey.dat");
    strcpy(secKey, home);
    strcat(secKey, "/secKey.dat");
    if(myRSA.loadPublicKey(pubKey) && myRSA.loadPrivateKey(secKey)) {
        printf("RSA keys loaded from disk\n");
    } else {
        myRSA.generateKeys(2048);
        myRSA.savePrivateKey(secKey);
        myRSA.savePublicKey(pubKey);
    }    

    // Generate random key pair simulating an other user
    rsa rsaOpponent;
    rsaOpponent.generateKeys(2048);
    
    //Crypt the message
    Crypto c;
    char* cryptedMessage = c.cryptAndSignMessage("Ceci est un message ultra secret !!!\n", &rsaOpponent, &myRSA);
    printf("message encrypté : %s", cryptedMessage);
    
    //Decrypt the message
    Crypto c1;
    char* plain = c1.decryptAndVerifyMessage(cryptedMessage, &rsaOpponent, &myRSA);
    printf("message en clair : %s", plain);
    
    free(plain);
    free(cryptedMessage);
    printf("Program end\n");
    return 0;
}
