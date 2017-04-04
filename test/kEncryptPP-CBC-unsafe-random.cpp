/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* kEncryptPP-CBC-random, this version does:
* 1. Gets a random secure key + 0*16 iv
* 2. Gets a reference AES-CBC encrypter
* 3. Sets an external encryption cipher to that reference 
* 4. StreamTransformationFilter does the actual encryption w/ padding for you
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

#include "windows.h"

#pragma comment (lib, "user32")

int main(int argc, char* argv[]) {

    MessageBox(NULL, "Encrypting...\n",NULL, NULL);

    /* Set up data structures */
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::MAX_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());

    byte iv[CryptoPP::AES::BLOCKSIZE];
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);


    HANDLE hFile = CreateFile("test1.txt", FILE_READ_DATA, FILE_SHARE_READ, 
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwCount;
    DWORD dwBlockLen = 40;
    PBYTE pbBuffer = (BYTE*)malloc(dwBlockLen);
    ReadFile(hFile, pbBuffer, dwBlockLen, &dwCount, NULL); // Read up to dwBlockLen from the source file.

    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;

    /* Encrypt the plaintext into ciphertext using CBC */
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1 );
    
    /* No more crypto allowed! */
    stfEncryptor.MessageEnd();

    for (int i = 0; i < ciphertext.size(); i++) {
        std::cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));
    }

    return 0;
}
