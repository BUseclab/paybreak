/**************************************************************************************************
* Easy Windows Crypto
* Eugene Kolo | eugene@kolobyte.com | 2015
*
* Wrapper library for symmetric crypto using Microsoft CryptoAPI.
* Example program is found in test/kEncrypt.cpp and test/kDecrypt.cpp.
*
* Proper garbage collection of any crypto handles is the responsibility of the user.
* Refer to MSDN CryptoAPI documentation for more information.
*
* NOTE:
*   + Some functions write files for you. This behaviour might be annoying.
*
* TODO:
*   eugenek: I think these should return a DWORD, not a BOOL. Or they should return BOOL + edit
*    LastError?
*   eugenek: Take file writing out of everything.
**************************************************************************************************/

#include "easy_cryptoapi.h"

BOOL GenSessionKeyWithRandom(HCRYPTPROV hCryptProv, ALG_ID Algid, DWORD dwKeySize,
    DWORD settings, HCRYPTKEY& hKey) {
    if (!CryptGenKey(hCryptProv, Algid, dwKeySize | settings, &hKey)) {
        MyHandleError(TEXT("[FAIL] Session key not created. \n"), GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL GenSessionKeyWithPassword(LPTSTR pszPassword, HCRYPTPROV hCryptProv, ALG_ID Algid,
    DWORD dwKeySize, DWORD settings, HCRYPTKEY& hHash, HCRYPTKEY& hKey) {

    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { // TODO(eugenek): Don't force MD5
        MyHandleError(TEXT("[FAIL] Hash object not created. \n"), GetLastError());
        return FALSE;
    }

    if (!CryptHashData(hHash, (BYTE*)pszPassword, lstrlen(pszPassword), 0)) {
        MyHandleError(TEXT("[FAIL] Password not hashed. \n"), GetLastError());
        return FALSE;
    }

    if (!CryptDeriveKey(hCryptProv, Algid, hHash, dwKeySize | settings, &hKey)) {
        MyHandleError(TEXT("[FAIL] Derive key failed. \n"), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL ExportSessionKey(HANDLE hDstFile, HCRYPTPROV hCryptProv, HCRYPTKEY hKey, HCRYPTKEY& hXchgKey,
    BOOL UseUserKey) {
    PBYTE pbKeyBlob = NULL;
    DWORD dwKeyBlobLen;
    DWORD dwCount;

    if (UseUserKey) { // Use Window's users asymmetric key-pair
        if(!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey)) {
            MyHandleError(TEXT("[FAIL] Couldn't get winuser's asymmetric key pair \n"), GetLastError());
            return FALSE;
        }
    } else { // Generate a new asymmetric key-pair
        if(!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hXchgKey)) {
            MyHandleError(TEXT("[FAIL] Could not generate new asymetric key pair \n"), GetLastError());
            return FALSE;
        }
    }

    // Export the session key's size
    if(!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwKeyBlobLen)) {
        MyHandleError(TEXT("[FAIL] Failed exporting session key's size \n"), GetLastError());
        return FALSE;
    }

    // Export the session key's data
    pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen);
    if(!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
        MyHandleError(TEXT("[FAIL] Failed exporting session key's data \n"), GetLastError());
        return FALSE;
    }

    free(pbKeyBlob);
    return TRUE;
}

BOOL ImportSessionKey(HCRYPTPROV hCryptProv, HCRYPTKEY& hKey, PBYTE pbKeyBlob, DWORD dwKeyBlobLen) {
    if(!CryptImportKey(hCryptProv, pbKeyBlob, dwKeyBlobLen, 0, 0, &hKey)) {
        MyHandleError(TEXT("[FAIL] Failed importing session key's data \n"), GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL EncryptWithSessionKey(HANDLE hSourceFile, HANDLE hDestinationFile, HCRYPTKEY hKey, DWORD dwBlockSize) {
    DWORD dwBlockLen = 1000 - 1000 % dwBlockSize;
    DWORD dwBufferLen;

    if (dwBlockSize > 1) { // Extra space for padding
        dwBufferLen = dwBlockLen + dwBlockSize;
    } else {
        dwBufferLen = dwBlockLen;
    }

    // Encrypt the data
    PBYTE pbBuffer = (BYTE*)malloc(dwBufferLen);
    BOOL fEOF = FALSE;
    DWORD dwCount;
    do {
        ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL); // Read up to dwBlockLen B from the source file.
        if (dwCount < dwBlockLen) { // Are we done?
            fEOF = TRUE;
        }

        if (!CryptEncrypt(hKey, NULL, fEOF,0, pbBuffer, &dwCount, dwBufferLen)) {
            MyHandleError(TEXT("[FAIL] Failed encrypting data \n"), GetLastError());
            return FALSE;
        }
        WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL); // Write the encrypted data to the destination file
    } while(!fEOF);

    free(pbBuffer);
    return TRUE;
}

BOOL DecryptWithSessionKey(HANDLE hSourceFile, HANDLE hDestinationFile, HCRYPTKEY hKey, DWORD dwBlockSize) {
    DWORD dwBlockLen = 1000 - 1000 % dwBlockSize;
    DWORD dwBufferLen = dwBlockLen;

    // Decrypt the data
    PBYTE pbBuffer = (BYTE*)malloc(dwBufferLen);
    BOOL fEOF = FALSE;
    DWORD dwCount;
    do {
        ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL); // Read up to dwBlockLen B from the source file.
        if(dwCount <= dwBlockLen) { // Are we done?
            fEOF = TRUE;
        }
        if (!CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount)) {
            MyHandleError(TEXT("[FAIL] Failed decrypting data \n"), GetLastError());
            return FALSE;
        }
        WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL); // Write the encrypted data to the destination file
    } while(!fEOF);

    free(pbBuffer);
    return TRUE;
}


void MyHandleError(LPTSTR psz, int nErrorNumber) {
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}
