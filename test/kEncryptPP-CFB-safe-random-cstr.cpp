/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* kEncryptPP-CFB-random, this version does:
* 1. Gets a random secure key + 0*16 iv
* 2. Gets a AES-CFB encrypter 
* 3. StreamTransformationFilter does the actual encryption w/ padding (unnessary in CFB) for you
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

    char plaintext[] = "Hello! How are you.";
    int messageLen = (int)strlen(plaintext) + 1;

    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, CryptoPP::AES::MAX_KEYLENGTH, iv);
    cfbEncryption.ProcessData((byte*)plaintext, (byte*)plaintext, messageLen);

    for (int i = 0; i < messageLen; i++) {
        std::cout << std::hex << (0xFF & static_cast<byte>(plaintext[i]));
    }

    return 0;
}
