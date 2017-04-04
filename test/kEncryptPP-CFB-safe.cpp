/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* kEncryptPP-CFB-safe, this version does:
* 1. Sets key and iv to 0*32, and 0*16 respectively.
* 2. Gets an AES-CFB Encrypter
* 3. StreamTransformationFilter does the actual encryption w/ padding (unnessary in CFB) for you
*
***************************************************************************************************/
#include <iostream>
#include <iomanip>
#include <string>
#include <stdio.h>

#include "hex.h"
#include "sha.h"
#include "base64.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"

int main(int argc, char* argv[]) {
  /* Set up data structures */
    byte key[CryptoPP::AES::MAX_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];

    // Very zero, much security :doge:
    memset(key, 0x00, CryptoPP::AES::MAX_KEYLENGTH);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;

    /* Encrypt the plaintext into ciphertext using CFB */
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, CryptoPP::AES::MAX_KEYLENGTH, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cfbEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1 );

    /* No more crypto allowed! */
    stfEncryptor.MessageEnd();

    for (int i = 0; i < ciphertext.size(); i++) {
        std::cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));
    }

    return 0;
}
