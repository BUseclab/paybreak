/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* Hook and trampoline into the MS Crypto API - Replaces Real_Crypt* with Fake_Crypt*
* Record calls, and trampoline back to the real functions.
* Recorded calls are logged in `C:\CryptoHookLog.dll`
*
***************************************************************************************************/

#include <stdio.h>
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
#include "detours/detours.h"
#include <tchar.h>
#include "antiransom.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")

static DWORD g_dwKeyBlobLen_Exfil = 0;
static PBYTE g_pbKeyBlob_Exfil = NULL;
static BOOL recursive = FALSE;
static BOOL recursive2 = FALSE;

// Works for Crypto++563-Debug
const DWORD NEEDLE_SIZE = 32;
char NEEDLE[NEEDLE_SIZE] = {0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x24, 0x89, 0x4D, 0xF4, 0x8B, 0x45, 0xF4, 0x8B, 0x55, 0x0C,
                            0x89, 0x14, 0x24, 0x89, 0xC1, 0xE8, 0x8A, 0x02, 0x00, 0x00, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x00};

/* This is a hack to not find the needle in this DLL's memory */
int dudd1 = 0x123123;
int dudd2 = 0x123123;
int dudd3 = 0x123123;
int dudd4 = 0x123123;
char NEEDLE_END = 0xF4;

/***********************************************************************************************/
/* Our trampoline functions */
/***********************************************************************************************/
/* Crypto API functions */
BOOL WINAPI Fake_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptDecrypt] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTKEY hKey = %x\n", hKey);
    fprintf(fd, "\t HCRYPTHASH hHash = %x\n", hHash);
    fprintf(fd, "\t BOOL Final = %x\n", Final);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t BYTE* pbData = %x, *pbdata = %s\n", pbData, "BROKEN");
    fprintf(fd, "\t DWORD* pdwDataLen = %x, *pdwDataLen = ", pdwDataLen);
    if (pdwDataLen != NULL) {
        fprintf(fd, "%x", *pdwDataLen);
    } else {
        fprintf(fd, "NULL");
    }
    fprintf(fd, "\n");

    fclose(fd);
    return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI Fake_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptSetKeyParam] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTKEY hKey = %x\n", hKey);
    fprintf(fd, "\t DWORD dwParam = %x\n", dwParam);
    fprintf(fd, "\t BYTE* pbData = %x, *pbData = ", pbData);
    if (pbData != NULL) {
        fprintf(fd, "%x", "This requires extra work, as pbData depends on the value of dwParam");
    } else {
        fprintf(fd, "NULL");
    }
    fprintf(fd, "\n");
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

    // Print out some key params
    DWORD dwCount;
    BYTE pbData2[16];
    CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV
    CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
    fprintf(fd, "KP_IV =  ");
    for (int i = 0 ; i < dwCount ; i++) {
        fprintf(fd, "%02x ",pbData2[i]);
    }

    fclose(fd);
    return Real_CryptSetKeyParam(hKey, dwParam, pbData, dwFlags);

}

// BOOL WINAPI Fake_CryptDestroyKey(HCRYPTKEY hKey) {
//     FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
//     std::string mytime = CurrentTime();

//     fprintf(fd, "[CryptDestroyKey] %s\n", mytime.c_str());

//     // TODO(eugenek): This is broken, for some reason dwCount doesn't get updated correctly.
//     // DWORD dwCount;
//     // BYTE pbData2[16];
//     // CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV    
//     // CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
//     // fprintf(fd, "KP_IV =  ");
//     // for (int i = 0 ; i < dwCount ; i++) {
//     //     fprintf(fd, "%02x ",pbData2[i]);
//     // }

//     if (recursive == FALSE) {
//         recursive = TRUE;

//         Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil);
//         fprintf(fd, "\t ExfilKeyLen = %d\n", g_dwKeyBlobLen_Exfil);
        
//         g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
    
//         // Get the export blob
//         if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
//             MyHandleError(TEXT("[FAIL] Exfil key data failed \n"), GetLastError());
//             fprintf(fd, "[FAIL] no-alloca Exfil key data failed \n");
//         }
    
//         fprintf(fd, "\t no-alloca ExfilKeyData = ");
//         for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
//            fprintf(fd, "%02x", g_pbKeyBlob_Exfil[i]);
//         }
//         fprintf(fd, "\n");
    
//         recursive = FALSE;
//     }

//     fclose(fd);
//     return Real_CryptDestroyKey(hKey);
// }


BOOL WINAPI Fake_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen, DWORD dwBufLen) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptEncrypt] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTKEY hKey = %x\n", hKey);
    fprintf(fd, "\t HCRYPTHASH hHash = %x\n", hHash);
    fprintf(fd, "\t BOOL Final = %x\n", Final);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t BYTE* pbData = %x, *pbdata = %s\n", pbData, "BROKEN");
    fprintf(fd, "\t DWORD* pdwDataLen = %x, *pdwDataLen = %s\n", pdwDataLen, "BROKEN");
    fprintf(fd, "\t DWORD dwBufLen = %x\n", dwBufLen);
    fclose(fd);

    DWORD dwCount;
    BYTE pbData2[16];
    CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV
    CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
    fprintf(fd, "KP_IV =  ");
    for (int i = 0 ; i < dwCount ; i++) {
        fprintf(fd, "%02x ",pbData2[i]);
    }

    if (recursive == FALSE) {
        recursive = TRUE;
        FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
        if (pbData == NULL) {
            // CryptEncrypt being used to get allocation size for cipher data
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key length failed \n");
            }
            fprintf(fd, "\t ExfilKeyLen = %d\n", g_dwKeyBlobLen_Exfil);
        }
        else if (g_dwKeyBlobLen_Exfil != NULL) {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key data failed \n");
            }
            fprintf(fd, "\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                fprintf(fd, "%02x",g_pbKeyBlob_Exfil[i]);
            }
            fprintf(fd, "\n");
        }
        else {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] no-alloca Exfil key length failed \n"), GetLastError());
                fprintf(fd, "[FAIL] no-alloca Exfil key length failed \n");
            }

            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

            // Get the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed \n"), GetLastError());
                fprintf(fd, "[FAIL] no-alloca Exfil key data failed \n");
            }

            // Print the export blob
            fprintf(fd, "\t no-alloca ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                fprintf(fd, "%02x", g_pbKeyBlob_Exfil[i]);
            }
            fprintf(fd, "\n");

            //free(pbKeyBlob);
        }
        fclose(fd);
        recursive = FALSE;
    }

    return Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI Fake_CryptAcquireContext(HCRYPTPROV* phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType,
  DWORD dwFlags) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptAcquireContext] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV* phProv = %x, *phProv = %s\n", phProv, "OUTPUT, so probably can't deref NULL");
    fprintf(fd, "\t LPCTSTR pszContainer = %s\n", pszContainer);
    fprintf(fd, "\t LPCTSTR pszProvider = %s\n", pszProvider);
    fprintf(fd, "\t DWORD dwProvType = %x\n", dwProvType);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

    fclose(fd);
    return Real_CryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI Fake_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags,
  HCRYPTHASH* phHash) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptCreateHash] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV hProv = %x\n", hProv);
    fprintf(fd, "\t ALG_ID Algid = %x\n", Algid);
    fprintf(fd, "\t HCRYPTKEY hKey = %x\n", hKey);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t HCRYPTHASH* phHash = %x, *phHash = %s\n", phHash, "OUTPUT, so probably can't deref NULL");

    fclose(fd);
    return Real_CryptCreateHash(hProv, Algid, hKey,dwFlags, phHash);
}

BOOL WINAPI Fake_CryptHashData(HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen, DWORD dwFlags) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptHashData] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTHASH hHash = %x\n", hHash);
    fprintf(fd, "\t BYTE* pbData = %x, *pbData = ", pbData);
    if (pbData != NULL) {
        for (int i = 0; i < dwDataLen; i++) {
            fprintf(fd, "%x", pbData[i]);
        }
    } else {
        fprintf(fd, "NULL");
    }
    fprintf(fd, "\n");
    fprintf(fd, "\t DWORD dwDataLen = %x\n", dwDataLen);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

    fclose(fd);
    return Real_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI Fake_CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags,
  HCRYPTKEY* phKey) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptDeriveKey] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV hProv = %x\n", hProv);
    fprintf(fd, "\t ALG_ID Algid = %x\n", Algid);
    fprintf(fd, "\t HCRYPTHASH hBaseData = %x\n", hBaseData);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t HCRYPTKEY* phKey = %x, *phKey = %s\n", phKey, "Cannot deref the key directly");

    fclose(fd);
    return Real_CryptDeriveKey(hProv, Algid, hBaseData, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptGenKey] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV hProv = %x\n", hProv);
    fprintf(fd, "\t ALG_ID Algid = %x\n", Algid);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t HCRYPTKEY* phKey = %x, *phKey = %s\n", phKey, "Cannot deref the key directly");

    fclose(fd);
    return Real_CryptGenKey(hProv, Algid, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptGenRandom] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV hProv = %x\n", hProv);
    fprintf(fd, "\t DWORD dwLen = %x\n", dwLen);

    fprintf(fd, "\t BYTE* pbBuffer = %x, *pbBuffer = OUTPUT, cannot deref\n", pbBuffer);

    BOOL ret = Real_CryptGenRandom(hProv, dwLen, pbBuffer);

    fprintf(fd, "\t RandomData = ");
    for (int i = 0 ; i < dwLen ; i++) {
        fprintf(fd, "%02x",pbBuffer[i]);
    }
    fprintf(fd, "\n");

    fclose(fd);
    return ret;
}

BOOL WINAPI Fake_CryptImportKey(HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey,
  DWORD dwFlags, HCRYPTKEY* phKey) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptImportKey] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTPROV hProv = %x\n", hProv);
    fprintf(fd, "\t BYTE* pbData = %x, *pbData = %s\n", pbData, "BROKEN");
    fprintf(fd, "\t DWORD dwDataLen = %x\n", dwDataLen);
    fprintf(fd, "\t HCRYPTKEY hPubKey = %x\n", hPubKey);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t HCRYPTKEY* phKey = %x, *phKey = %s\n", phKey, "BROKEN");

    fclose(fd);
    return Real_CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags|CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags,
  BYTE* pbData, DWORD* pdwDataLen) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CryptExportKey] %s\n", mytime.c_str());
    fprintf(fd, "\t HCRYPTKEY hKey = %x\n", hKey);
    fprintf(fd, "\t HCRYPTKEY hExpKey = %x\n", hExpKey);
    fprintf(fd, "\t DWORD dwBlobType = %x\n", dwBlobType);
    fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
    fprintf(fd, "\t BYTE* pbData = %x, *pbData = %s\n", pbData, "BROKEN");
    fprintf(fd, "\t DWORD* pdwDataLen = %x, *pdwDataLen = %d\n", pdwDataLen, *pdwDataLen);
    fclose(fd);

    if (recursive == FALSE) {
        recursive = TRUE;
        FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
        if (pbData == NULL) {
            // CryptEncrypt being used to get allocation size for cipher data
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key length failed \n");
            }
            fprintf(fd, "\t ExfilKeyLen = %d\n", g_dwKeyBlobLen_Exfil);
        }
        else if (g_dwKeyBlobLen_Exfil != NULL) {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key data failed \n");
            }
            fprintf(fd, "\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                fprintf(fd, "%02x",g_pbKeyBlob_Exfil[i]);
            }
            fprintf(fd, "\n");
        }
        else {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key length failed \n");
            }

            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

            // Get the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed \n"), GetLastError());
                fprintf(fd, "[FAIL] Exfil key data failed \n");
            }

            // Print the export blob
            fprintf(fd, "\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                fprintf(fd, "%02x", g_pbKeyBlob_Exfil[i]);
            }
            fprintf(fd, "\n");

            //free(pbKeyBlob);
        }
        fclose(fd);
        recursive = FALSE;
    }

    return Real_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/* CryptoNG API functions */
NTSTATUS WINAPI Fake_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo,
  PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[BCryptEncrypt] %s\n", mytime.c_str());
    fclose(fd);

    return Real_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput,
        pcbResult, dwFlags);
}


///////////////////////////////////////////////////////////////////////////////////////////////////
/* File functions */
HFILE WINAPI Fake_OpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[OpenFile] %s\n", mytime.c_str());
    fprintf(fd, "\t LPCSTR lpFileName = %s\n", lpFileName);

    fclose(fd);

    return Real_OpenFile(lpFileName, lpReOpenBuff, uStyle);
}

NTSTATUS WINAPI Fake_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
    fprintf(fd, "[NtOpenFile] %s\n", mytime.c_str());
    fprintf(fd, "\t PUNICODE_STRING lpFileName = %wZ\n", FileName);

    fclose(fd);

  return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

HANDLE WINAPI Fake_CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();

    fprintf(fd, "[CreateFile] %s\n", mytime.c_str());
    fprintf(fd, "\t LPCSTR lpFileName = %s\n", lpFileName);

    fclose(fd);

    return Real_CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

NTSTATUS WINAPI Fake_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
  ULONG EaLength) {
    if (recursive2 == FALSE) {
        recursive2 = TRUE;
        FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
        std::string mytime = CurrentTime();
        fprintf(fd, "[NtCreateFile] %s\n", mytime.c_str());
        PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
        fprintf(fd, "\t PUNICODE_STRING FileName = %wZ\n", FileName);
        fclose(fd);

        if (Real_HookedSig == NULL) {
            unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
            if (sig_address != NULL) {
                Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
                DetourTransactionCommit();
            }
        }

        if (Real_HookedSig != NULL) {
            // ReadFile's job is done...
            //DetourTransactionBegin();
            //DetourUpdateThread(GetCurrentThread());
            //DetourDetach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
            //DetourTransactionCommit();
        }

        recursive2 = FALSE;
    }
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

/*
BOOL WINAPI Fake_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();
    fprintf(fd, "[ReadFile] %s\n", mytime.c_str());
    fclose(fd);

    if (Real_HookedSig == NULL) {
        unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
        //printf("[fake_readfile] Setting real_hookedsig\n");
        if (sig_address != NULL) {
            Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
            //printf("[fake_readfile] sig_address = [%08x]\n", sig_address);
            //printf("[fake_readfile] Real_HookedSig = [%08x]\n", Real_HookedSig);
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
            //printf("[fake_readfile2] Real_HookedSig = [%08x]\n", Real_HookedSig);
            DetourTransactionCommit();
        }
    }

    if (Real_HookedSig != NULL) {
        // ReadFile's job is done...
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        DetourTransactionCommit();
    }

    return Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
*/
/*
NTSTATUS WINAPI Fake_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    std::string mytime = CurrentTime();
    fprintf(fd, "[NtReadFile] %s\n", mytime.c_str());
    fclose(fd);

    if (Real_HookedSig == NULL) {
        unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
        //printf("[fake_readfile] Setting real_hookedsig\n");
        if (sig_address != NULL) {
            Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
            //printf("[fake_readfile] sig_address = [%08x]\n", sig_address);
            //printf("[fake_readfile] Real_HookedSig = [%08x]\n", Real_HookedSig);
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
            //printf("[fake_readfile2] Real_HookedSig = [%08x]\n", Real_HookedSig);
            DetourTransactionCommit();
        }
    }

    if (Real_HookedSig != NULL) {
        // ReadFile's job is done...
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourTransactionCommit();
    }

    return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}
*/
VOID __fastcall Fake_HookedSig(void * This, void * throwaway, const BYTE* key, size_t length, DWORD* whatever) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");
    fprintf(fd, "\t CryptoPPKey = ");
    for (int i = 0 ; i < length ; i++) {
        fprintf(fd, "%02x",key[i]);
    }
    fprintf(fd, "\n");
    fclose(fd);
    return Real_HookedSig(This, key, length, whatever);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
    FILE *fd = fopen("C:\\CryptoHookLog.dll", "a");

    switch(Reason) {
    case DLL_PROCESS_ATTACH:
        // DetourRestoreAfterWith(); // eugenek: not sure if this is necessary
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());


        DetourAttach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourAttach(&(PVOID&)Real_CryptDecrypt, Fake_CryptDecrypt);

        DetourAttach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourAttach(&(PVOID&)Real_CryptSetKeyParam, Fake_CryptSetKeyParam);
        // TODO(eugenek): Disabled because the function needs logic to check the key wasn't already
        // exported, else it keeps crashing. Somebody should add this logic.
        // DetourAttach(&(PVOID&)Real_CryptDestroyKey, Fake_CryptDestroyKey);

        DetourAttach(&(PVOID&)Real_CryptCreateHash, Fake_CryptCreateHash);
        DetourAttach(&(PVOID&)Real_CryptHashData, Fake_CryptHashData);

        DetourAttach(&(PVOID&)Real_CryptDeriveKey, Fake_CryptDeriveKey);
        DetourAttach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);

        DetourAttach(&(PVOID&)Real_CryptImportKey, Fake_CryptImportKey);
        DetourAttach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);

        DetourAttach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);

        //DetourAttach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        //DetourAttach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourAttach(&(PVOID&)Real_OpenFile, Fake_OpenFile);
        DetourAttach(&(PVOID&)Real_NtOpenFile, Fake_NtOpenFile);
        DetourAttach(&(PVOID&)Real_CreateFile, Fake_CreateFile);
        DetourAttach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);

        DetourAttach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);

        DetourTransactionCommit();
        fprintf(fd, "[SUCCESS] Hooked CryptoAPI\n");
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourDetach(&(PVOID&)Real_CryptDecrypt, Fake_CryptDecrypt);

        DetourDetach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourDetach(&(PVOID&)Real_CryptSetKeyParam, Fake_CryptSetKeyParam);
        // TODO(eugenek): Disabled because the function needs logic to check the key wasn't already
        // exported, else it keeps crashing. Somebody should add this logic.
        // DetourDetach(&(PVOID&)Real_CryptDestroyKey, Fake_CryptDestroyKey);

        DetourDetach(&(PVOID&)Real_CryptCreateHash, Fake_CryptCreateHash);
        DetourDetach(&(PVOID&)Real_CryptHashData, Fake_CryptHashData);

        DetourDetach(&(PVOID&)Real_CryptDeriveKey, Fake_CryptDeriveKey);
        DetourDetach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);

        DetourDetach(&(PVOID&)Real_CryptImportKey, Fake_CryptImportKey);
        DetourDetach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);

        DetourDetach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);

        //DetourDetach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        //DetourDetach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourDetach(&(PVOID&)Real_OpenFile, Fake_OpenFile);
        DetourDetach(&(PVOID&)Real_NtOpenFile, Fake_NtOpenFile);
        DetourDetach(&(PVOID&)Real_CreateFile, Fake_CreateFile);
        DetourDetach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);

        DetourDetach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);

        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    fclose(fd);
    return TRUE;
}


/*
* Searches the virtual memory of the process for a byte signature.
* Input:
*   sig - the signature to search for
*   sigend - the end of the signature to search for
*   sigsize - the size of the signature to search for
* Output:
*   virtual memory address of the byte signature if found. NULL if not found */
unsigned char* search_memory(char* sig, char sigend, size_t sigsize) {
    unsigned char* sig_address = NULL;
    /* Get our PID and a handle to the process */
    DWORD pid = GetCurrentProcessId();
    HANDLE process = OpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, FALSE, pid);

    /* Intelligently iterate over only mapped executable pages and dump them */
    /* Search for the signature in the pages */
    MEMORY_BASIC_INFORMATION info;
    DWORD bytesRead = 0;
    char* pbuf = NULL;
    unsigned char* current = NULL;
    for (current = NULL; VirtualQueryEx(process, current, &info, sizeof(info)) == sizeof(info); current += info.RegionSize) {
        // Only iterate over mapped executable memory
        if (info.State == MEM_COMMIT && (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE || info.Type == MEM_IMAGE) &&
            (info.AllocationProtect == PAGE_EXECUTE || info.AllocationProtect == PAGE_EXECUTE_READ
                || info.AllocationProtect == PAGE_EXECUTE_READWRITE || info.AllocationProtect == PAGE_EXECUTE_WRITECOPY)) {

            pbuf = (char*)malloc(info.RegionSize);
            ReadProcessMemory(process, current, pbuf, info.RegionSize, &bytesRead);
            size_t match_offset = search_array(sig, sigend, sigsize, pbuf, bytesRead, 31); // 80% match
            if (match_offset != NULL) {
                sig_address = current+match_offset;
                break;

            }

        }
    }

    return sig_address;
}

/*
* Searches an array for a fuzzy subarray.
* Input:
*   needle - subarray to search for
*   needle_end - last part of the subarray to search for
*   needleSize - size of aubarray to search for
*   haystack - array to search in
*   haystackSize - size of array to search in
*   threshold - integer amount of bytes that much match to return a match
* Output:
*   offset to the first match (only aim for one!). If none, then NULL. */
size_t search_array(char *needle, char needle_end, size_t needleSize, char *haystack, size_t haystackSize, size_t threshold) {
    size_t match_offset = NULL;
    for (int i = 0; i + needleSize <= haystackSize; i++) {
        size_t match_count = 0;
        for (int j = 0; j < needleSize; j++) {
            char needle_compare = needle[j];
            /* This is a hack to not find the needle in this DLL's memory */
            if (j == needleSize - 1) {
                needle_compare = needle_end;
            }
            if (haystack[i+j] == needle_compare) {
                match_count++;
            }
        }

        if(match_count >= threshold) {
            match_offset = i;
            break;
        }
    }

    return match_offset;
}

const std::string CurrentTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char currentTime[100] = "";
    sprintf(currentTime,"%d:%d:%d %d",st.wHour, st.wMinute, st.wSecond , st.wMilliseconds);
    return std::string(currentTime);
}

void MyHandleError(LPTSTR psz, int nErrorNumber) {
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}

