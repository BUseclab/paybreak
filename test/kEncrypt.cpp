/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* Basic Microsoft CrytoAPI Encryption Flow
* 
* Usage:
*   Usage: kEncrypt.exe <src file> <dst file> <UseUserKey:yes|no> [password]
*
* TODO:
*   eugenek: Fix up the main argparsing
***************************************************************************************************/  

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

#include "easy_cryptoapi.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "crypt32")

#define KEYLENGTH  0x01000000
#define ENCRYPT_ALGORITHM CALG_AES_256 
#define ENCRYPT_BLOCK_SIZE 128 
#define CSP_TYPE MS_ENH_RSA_AES_PROV 
#define CSP_NAME PROV_RSA_AES

BOOL kEncrypt(LPTSTR szSource, LPTSTR szDestination, LPTSTR szPassword, BOOL UseUserKey);

int _tmain(int argc, _TCHAR* argv[]) {
    LPTSTR infileName = argv[1];
    LPTSTR outfileName = argv[2]; 
    LPTSTR pszPassword = NULL;
    BOOL UseUserKey = FALSE;

    if(argc < 4) {
        _tprintf(TEXT("Usage: kEncrypt.exe <src file> <dst file> <UseUserKey:yes|no> [password]\n"));
        _tprintf(TEXT("Enter 'no' if you don't want to use your Windows user key.\n"));
        _tprintf(TEXT("If you want to use your user key, then type 'yes' for it.\n"));
        _gettch();
        return 1;
    }

    if (strcmp(argv[3], "no") != 0) {
        UseUserKey = TRUE;
    }

    if(argc >= 5) {
        pszPassword = argv[4];
    }

    MessageBox(NULL, "Encrypting...\n",NULL, NULL);

    kEncrypt(infileName, outfileName, pszPassword, UseUserKey);

    return 0;
}

/************************************************************************************
* Five step encryption flow
* 1. Open source and destination files
* 2. Acquire CSP
* 3. Generate a session key
* 4. Export the session key (so we can decrypt it later)
* 5. Encrypt the source with the session key to the dest
*************************************************************************************/
BOOL kEncrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword, BOOL UseUserKey) { 
    HCRYPTPROV hCryptProv = NULL; 
    HCRYPTKEY hKey = NULL; 
    HCRYPTKEY hXchgKey = NULL; 
    HCRYPTHASH hHash = NULL; 

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

    if(!pszPassword || !pszPassword[0]) {  // No password given
        if (GenSessionKeyWithRandom(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH, CRYPT_EXPORTABLE, hKey)) {
            _tprintf(TEXT("[GOOD] Generated random session key \n"));
        } else {
            MyHandleError(TEXT("[FAIL] Random session not generated. \n"), GetLastError());
            return FALSE;
        }
    } else { 
        if (GenSessionKeyWithPassword(pszPassword, hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH, CRYPT_EXPORTABLE,
         hHash, hKey)) {
            _tprintf(TEXT("[GOOD] Generated passworded session key \n"));
        } else {
            MyHandleError(TEXT("[FAIL] Passworded session not generated \n"), GetLastError());
            return FALSE;
        }
    }

    if (ExportSessionKey(hDestinationFile, hCryptProv, hKey, hXchgKey, UseUserKey)) {
        _tprintf(TEXT("[GOOD] Successfully exported session. \n"));
    } else {
        MyHandleError(TEXT("[FAIL] Export session failed. \n"), GetLastError());
        return FALSE;
    }

    if (EncryptWithSessionKey(hSourceFile, hDestinationFile, hKey, ENCRYPT_BLOCK_SIZE)) {
        _tprintf(TEXT("[GOOD] Successfully encrypted file. \n"));
    } else {
        MyHandleError(TEXT("[FAIL] Encryption failed. \n"), GetLastError());
        return FALSE;
    }

    CloseHandle(hSourceFile);
    CloseHandle(hDestinationFile);
    CryptReleaseContext(hCryptProv, 0);
    CryptDestroyKey(hKey);
    CryptDestroyKey(hXchgKey);
    CryptDestroyHash(hHash);
    return TRUE;
} 

