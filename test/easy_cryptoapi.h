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
* TODO:
*   eugenek: I think these should return a DWORD, not a BOOL. Or they should return BOOL + edit
*    LastError?
*   eugenek: Take file writing out of everything.
**************************************************************************************************/

#pragma once
#ifndef EASYCRYPTOAPI_H_
#define EASYCRYPTOAPI_H_

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

/** GenSessionKeyWithRandom
* Generates a random cryptographic session key.
*
* _IN_    HCRYPTPROV hCryptProv - Crypto provider created by CryptAcquireContext
* _IN_    ALG_ID Algid - Crypto algo to use
* _IN_    DWORD dwKeySize - Size of key to generate
* _IN_    DWORD settings - A mask of what settings to generate the sesion key with.
*                          0x00000000 is typically fine.
* _OUT_   HCRYPTKEY hKey - Crypto Key container containing the exportable random crypto session key
* _IN_
* _RET_   TRUE if successful */
BOOL GenSessionKeyWithRandom(HCRYPTPROV hCryptProv, ALG_ID Algid, DWORD dwKeySize, DWORD settings,
    HCRYPTKEY& hKey);


/** GenSessionKeyWithPassword
* Generates a cryptographic session key seeded with the password. As required by CryptDeriveKey, a
password is hashed and then used as the seed for CryptDeriveKey.
*
* @note: Hash is defaulted to MD5 // TODO(eugenek): perhaps make it user input.
*
* _IN_    LPTSTR pszPassword - Password to hash and seed the session key with
* _IN_    HCRYPTPROV hCryptProv - Crypto provider created by CryptAcquireContext
* _IN_    ALG_ID Algid - Crypto algo to use
* _IN_    DWORD dwKeySize - Size of key to generate
* _IN_    DWORD settings - A mask of what settings to generate the sesion key with.
*                          0x00000000 is typically fine.
* _IO_    HCRYPTKEY hHash - Initially empty hash object used for hashing `pszPassword`
* _OUT_   HCRYPTKEY hKey - Generated session key container
* _RET_   TRUE if successful */
BOOL GenSessionKeyWithPassword(LPTSTR pszPassword, HCRYPTPROV hCryptProv, ALG_ID Algid,
    DWORD dwKeySize, DWORD settings, HCRYPTKEY& hHash, HCRYPTKEY& hKey);


/** ExportSessionKey
* Encrypts a session key (`hKey`) using an exchange key (`hXchgKey`) and exports
* the session key as a `SIMPLEBLOB` to a destination file.
*
* _IN_    HANDLE hDstFile - File to export the encrypted session key blob to
* _IN_    HCRYPTPROV hCryptProv - Must be the same crypto provider created for GenSession* calls
* _IN_    HCRYPTKEY hKey - Session key to encrypt and export
* _IO_    HCRYPTKEY hXchgKey - Initially empty, gets set differently depending on the `UserUserKey`
*                              switch
* _IN_    BOOL UseUserKey - Set TRUE to use the Window's user asymmetric key pair as the `hXchgKey`
* _RET_   TRUE if successful */
BOOL ExportSessionKey(HANDLE hDstFile, HCRYPTPROV hCryptProv, HCRYPTKEY hKey, HCRYPTKEY& hXchgKey,
  BOOL UseUserKey);


/** ImportSessionKey
* Imports a session key (`hKey`) into the CSP (`hCryptProv`) using an exported session key
*
* _IN_    HCRYPTPROV hCryptProv - Must be the same crypto provider created for GenSession* calls
* _IO_    HCRYPTKEY hKey - Imported session key tied to the CSP goes here
* _IN_    PBYTE pbKeyBlob - Pointer to byte array containing the session key to import
* _IN_    DWORD dwKeyBlobLen - Length of the session key to import
* _RET_   TRUE if successful */
BOOL ImportSessionKey(HCRYPTPROV hCryptProv, HCRYPTKEY& hKey, PBYTE pbKeyBlob, DWORD dwKeyBlobLen);


/** EncryptWithSessionKey
* Encrypts a `hSourceFile` using the crypto session in `hkey` to the `hDestinationFile`
*
* @note: Undefined behaviour for hSourceFile == hDestinationFile
*
* _IN_    HANDLE hSourceFile - Handle to file to encrypt
* _IN_    HANDLE hDestinationFile - Handle to file to write the encrypted data to
* _IN_    HCRYPTKEY hKey - Session key to encrypt with
* _IN_    DWORD dwBlockSize - Block size of the crypto algo being used
* _RET_   TRUE if successful */
BOOL EncryptWithSessionKey(HANDLE hSourceFile, HANDLE hDestinationFile, HCRYPTKEY hKey,
    DWORD dwBlockSize);


/** DecryptWithSessionKey
* Decrypts a `hSourceFile` using the crypto session in `hKey` to the `hDestinationFile`
*
* @note: Undefined behaviour for hSourceFile == hDestinationFile
*
* _IN_    HANDLE hSourceFile - Handle to file to decrypt
* _IN_    HANDLE hDestinationFile - Handle to file to write the decrypted data to
* _IN_    HCRYPTKEY hKey - Session key to decrypt with
* _IN_    DWORD dwBlockSize - Block size of the crypto algo being used
* _RET_   TRUE if successful */
BOOL DecryptWithSessionKey(HANDLE hSourceFile, HANDLE hDestinationFile, HCRYPTKEY hKey,
    DWORD dwBlockSize);

VOID MyHandleError(LPTSTR psz, int nErrorNumber);

#endif //EASYCRYPTOAPI_H_
