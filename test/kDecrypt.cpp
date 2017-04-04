/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* Basic Microsoft CrytoAPI Decryption Flow
* 
* Usage:
*     Usage: kDecrypt.exe <src file> <dst file> <dec:keylen> <hex:keydata>
***************************************************************************************************/  

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <stdlib.h>

#include "easy_cryptoapi.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "crypt32")

//#define KEYLENGTH  0x01000000
//#define ENCRYPT_ALGORITHM CALG_AES_256 
#define ENCRYPT_BLOCK_SIZE 128 
#define CSP_TYPE MS_ENH_RSA_AES_PROV 
#define CSP_NAME PROV_RSA_AES

BOOL kDecrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR keyLen, LPTSTR keyData);
BOOL str_to_hex(LPTSTR pszStrIn, PBYTE pbOut, DWORD dwOutSize);

int _tmain(int argc, _TCHAR* argv[]) {
    LPTSTR infileName = argv[1];
    LPTSTR outfileName = argv[2]; 
    LPTSTR keyLen = argv[3];
    LPTSTR keyData = argv[4];

    if(argc < 4) {
        _tprintf(TEXT("Usage: kDecrypt.exe <src file> <dst file> <dec:keylen> <hex:keydata>\n"));
        _gettch();
        return 1;
    }

    kDecrypt(infileName, outfileName, keyLen, keyData);

    return 0;
}

/************************************************************************************
* Four step decryption flow
* 1. Open source and destination files
* 2. Acquire CSP
* 3. Import the session key
* 4. Decrypt the source with the session key to the dest
*************************************************************************************/
BOOL kDecrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR keyLen, LPTSTR keyData) { 
    HCRYPTPROV hCryptProv = NULL; 
    HCRYPTKEY hKey = NULL; 
    PBYTE pbKeyBlob;
    DWORD dwKeyBlobLen = atoi(keyLen);

    HANDLE hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA,FILE_SHARE_READ, 
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hDestinationFile = CreateFile(pszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ,
                                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL);
    
    if(CryptAcquireContext(&hCryptProv, NULL, CSP_TYPE, CSP_NAME, 0)) {
        _tprintf(TEXT("[GOOD] A cryptographic provider has been acquired. \n"));
    } else {
        MyHandleError(TEXT("[FAIL] Cryptographic provider not acquired. \n"), GetLastError());
        return FALSE;
    }

    pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen);
    str_to_hex(keyData, pbKeyBlob, dwKeyBlobLen);
    if (ImportSessionKey(hCryptProv, hKey, pbKeyBlob, dwKeyBlobLen)) {
        _tprintf(TEXT("[GOOD] Successfully imported session. \n"));
    } else {
        MyHandleError(TEXT("[FAIL] Import session failed. \n"), GetLastError());
        return FALSE;
    }

    if (DecryptWithSessionKey(hSourceFile, hDestinationFile, hKey, ENCRYPT_BLOCK_SIZE)) {
        _tprintf(TEXT("[GOOD] Successfully decrypted file. \n"));
    } else {
        MyHandleError(TEXT("[FAIL] Decryption failed. \n"), GetLastError());
        return FALSE;
    }

    CloseHandle(hSourceFile);
    CloseHandle(hDestinationFile);
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    return TRUE;
} 


BOOL str_to_hex(LPTSTR pszStrIn, PBYTE pbOut, DWORD dwOutSize) {
    //TODO(eugenek): Only works if pbOutSize is even
    for (int i = 0; i < dwOutSize; i++) {
        sscanf(pszStrIn, "%2hhx", &pbOut[i]);
        pszStrIn += 2;
    }

    return TRUE;
}
