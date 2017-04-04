/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* kEncryptPP-A, this version does:
* 1. Gets a random secure key + 0*16 iv
* 2. Gets a AES-CBC encrypter 
* 3. StreamTransformationFilter does the actual encryption w/ padding for you
*
***************************************************************************************************/
#include <iostream>
#include <iomanip>
#include <string>

#include "hex.h"
#include "sha.h"
#include "base64.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "osrng.h"

int main(int argc, char* argv[]) {
    /* Set up data structures */
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::MAX_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());

    byte iv[CryptoPP::AES::BLOCKSIZE];
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;

    /* Encrypt the plaintext into ciphertext using CBC */
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, CryptoPP::AES::MAX_KEYLENGTH, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1 );
    
    /* No more crypto allowed! */
    stfEncryptor.MessageEnd();

    for( int i = 0; i < ciphertext.size(); i++ ) {
        std::cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));
    }

    return 0;
}
