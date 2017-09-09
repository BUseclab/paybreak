/***************************************************************************************************
* PayBreak
* Eugene Kolodenker | eugene@eugenekolo.com | 2017
*
* Hook and trampoline into the MS Crypto API - Replaces Real_Crypt* with Fake_Crypt*
* Record calls, and trampoline back to the real functions.
* Recorded calls are logged in `C:\CryptoHookLog.dll`
*
***************************************************************************************************/

#pragma once
#ifndef HOOKCRYPT_H_
#define HOOKCRYPT_H_

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <Winternl.h>
#include <stdio.h>
#include <winioctl.h>

/**
* Saved function pointers.
*/
// Regular CryptAPI functions
static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*) = CryptDecrypt;
static BOOL (WINAPI *Real_CryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD) = CryptEncrypt;
static BOOL (WINAPI *Real_CryptAcquireContext)(HCRYPTPROV*, LPCTSTR, LPCTSTR, DWORD, DWORD) = CryptAcquireContext;
static BOOL (WINAPI *Real_CryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*) = CryptCreateHash;
static BOOL (WINAPI *Real_CryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD) = CryptHashData;
static BOOL (WINAPI *Real_CryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*) = CryptDeriveKey;
static BOOL (WINAPI *Real_CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*) = CryptGenKey;
static BOOL (WINAPI *Real_CryptImportKey)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*) = CryptImportKey;
static BOOL (WINAPI *Real_CryptExportKey)(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*) = CryptExportKey;
static BOOL (WINAPI *Real_CryptGenRandom)(HCRYPTPROV, DWORD, BYTE*) = CryptGenRandom;
static BOOL (WINAPI *Real_CryptSetKeyParam)(HCRYPTKEY, DWORD, const BYTE*, DWORD) = CryptSetKeyParam;
static BOOL (WINAPI *Real_CryptDestroyKey)(HCRYPTKEY hKey) = CryptDestroyKey;

// Statically compiled hooked functions
//static BOOL (WINAPI *Real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
//static NTSTATUS (WINAPI *Real_NtReadFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG) = NtReadFile;

static HFILE (WINAPI *Real_OpenFile)(LPCSTR, LPOFSTRUCT, UINT) = OpenFile;
static NTSTATUS (WINAPI *Real_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG) = NtOpenFile;
static HANDLE (WINAPI *Real_CreateFile)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFile;
static NTSTATUS (WINAPI *Real_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = NtCreateFile;
static VOID (__thiscall* Real_HookedSig )(void *, const BYTE*, size_t, DWORD*) = NULL;

// New CryptoAPI NG functions
static NTSTATUS (WINAPI *Real_BCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG) = BCryptEncrypt;

/**
* Fake functions for the trampolines.
*/
// Regular CryptAPI functions
BOOL WINAPI Fake_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags);
BOOL WINAPI Fake_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen);
BOOL WINAPI Fake_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen, DWORD dwBufLen);
BOOL WINAPI Fake_CryptAcquireContext(HCRYPTPROV* phProv, LPCTSTR pszContainer, LPCTSTR pszProvider,
  DWORD dwProvType, DWORD dwFlags);
BOOL WINAPI Fake_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags,
  HCRYPTHASH* phHash);
BOOL WINAPI Fake_CryptHashData(HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL WINAPI Fake_CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags,
  HCRYPTKEY* phKey);
BOOL WINAPI Fake_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI Fake_CryptImportKey(HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey,
  DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI Fake_CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags,
  BYTE* pbData, DWORD* pdwDataLen);
BOOL WINAPI Fake_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);
BOOL WINAPI Fake_CryptDestroyKey(HCRYPTKEY hKey);

// Statically compiled hooked functions
//BOOL WINAPI Fake_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
//NTSTATUS WINAPI Fake_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
//  PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

HFILE WINAPI Fake_OpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle);
NTSTATUS WINAPI Fake_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
HANDLE WINAPI Fake_CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
NTSTATUS WINAPI Fake_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
  ULONG EaLength);

VOID __fastcall Fake_HookedSig(void * This, void * throwaway, const BYTE* key, size_t length, DWORD* whatever);

// New CryptoAPI NG functions
NTSTATUS WINAPI Fake_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);

/**
* Helper functions
*/
unsigned char* search_memory(char* sig, char sigend, size_t sigsize);
size_t search_array(char *needle, char needle_end, size_t needleSize, char *haystack, size_t haystackSize, size_t threshold);
const std::string CurrentTime();
void MyHandleError(LPTSTR psz, int nErrorNumber);

#endif //HOOKCRYPT_H_
