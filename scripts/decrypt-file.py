#!/usr/bin/env python
import struct, sys, os
import argparse
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import magic

def decode_plaintextkey_blob(hexstr):
    """Decode a plaintext key blob and return the key_params with the actual key_val.
    Works for all key sizes.

    Notes on decoding Windows binary data
    The PUBLICKEYSTRUC structure, also known as the BLOBHEADER structure:
    typedef struct _PUBLICKEYSTRUC {
     BYTE   bType;
     BYTE   bVersion;
     WORD   reserved;
     ALG_ID aiKeyAlg;
    } BLOBHEADER, PUBLICKEYSTRUC;

    typedef struct _PLAINTEXTKEYBLOB {
     BLOBHEADER hdr; // 8 bytes
     DWORD      dwKeySize; // 4 bytes
      BYTE       rgbkey_val[];
    } PLAINTEXTKEYBLOB, *PPLAINTEXTKEYBLOB;

    DWORD - A 32-bit unsigned integer.
    WORD - A 16-bit unsigned integer.
    BYTE - A 8-bit unsigned integer.
    ALG_ID - DWORD

    AES-256 PLAINTEXTKEYBLOB Looks like:
    bType: 0x08, bVersion: 0x02, reserved: 0x0000, aiKeyAlg:0x00006610
    dwKeySize: 0x00000020, rgbkey_val: <256 bits>

    "If keys are generated for symmetric block ciphers, the key, by default, /
    is set up in cipher block chaining (CBC) mode with an initialization vector of zero." - MSDN

    Args:
        hexstr: A packed PLAINTEXTKEYBLOB.

    Returns:
        A tuple containing the key blob's key parameters, and the key's value.
    """

    PLAINTEXTKEYBLOB = namedtuple('PLAINTEXTKEYBLOB', 'bType bVersion reserved aiKeyAlgo dwKeySize')
    key_params = PLAINTEXTKEYBLOB._make(struct.unpack_from('<BBHII', hexstr.decode('hex')))
    key_val = hexstr[24::].decode('hex') # Get rgbkey_val[]

    return (key_params, key_val)

def decrypt_file(filename, key_val, mode=AES.MODE_CBC, iv='\x00'*16, trim=None):
    """Attempt decryption of a file.

    Args:
        filename: The name of the file you want to decrypt
        key_val: The key you want to use to decrypt with
        mode: The cipher block mode you want to decrypt with
        iv: The IV you want to use to decrypt with
        trim: The amount to trim to the file by before decrypting

    Returns:
        The decrypted data.

    Raises:
        Something if decryption failed.
    """
    with open(filename, 'rb') as f:
        encrypted_data = f.read()

    if trim:
        encrypted_data = encrypted_data[trim:]

    # Special cases
    if args.locky:
        # (https://www.lexsi.com/securityhub/abusing-bugs-in-the-locky-ransomware-to-create-a-vaccine/?lang=en)
        # Locky is a special case, it does some weird keystream homebrew crypto scheme
        # however, it's still using CryptoAPI, and can be reversed w/ this algo:
        # 1) Generate the locky keystream seed
        keystream = ""
        for i in range(0x80):
            keystream += "\x00"*15 + chr(i)

        # 2) Encrypt it w/ key_val AES
        keystream = AES.new(key_val, mode=AES.MODE_ECB).encrypt(keystream)

        # 3) XOR decrypt the data stored at the beginning of the .locky file
        # 0x230 is the file name size, 0x100 is the 0x100 is the RSA'd session key, 0x14 is the locky header
        enc_size = len(encrypted_data) - 0x230 - 0x100 - 0x14
        enc_content  = encrypted_data[:enc_size]
        decrypted_data = ""
        for i in range(enc_size):
            decrypted_data += chr(ord(enc_content[i]) ^ ord(keystream[0x230+i]))

        decrypted_data = decrypted_data[:-ord(decrypted_data[-1])] # Unpad the data

    elif args.tox:
        # Tox is a special case. It uses DES3, instead of AES, besides that it's boring.
        cipher = DES3.new(key_val, mode=DES3.MODE_CBC, IV='\x00'*8)
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_data = decrypted_data[:-ord(decrypted_data[-1])] # Unpad the data

    else:
        # Regular case
        try:
            cipher = AES.new(key_val, mode=mode, IV=iv)
            decrypted_data = cipher.decrypt(encrypted_data)
            decrypted_data = decrypted_data[:-ord(decrypted_data[-1])] # Unpad the data
        except ValueError:
            decrypted_data = ""

    return decrypted_data

def encrypt_file(filename, key_val, mode=AES.MODE_CBC, iv='\x00'*16):
    with open(filename, 'rb') as f:
        clear_data = f.read()

    cipher = AES.new(key_val, mode=mode, IV=iv)
    encrypted_data = cipher.encrypt(clear_data)

    return encrypted_data


def file_is_decrypted(filedata):
    """Check if a file is a common file type, aka successfully decrypted.

    Args:
        filedata: The data of the file to check.

    Returns:
        True if file is a common file type, False otherwise.
    """

    type_ = magic.from_buffer(filedata)
    common_types = ('ASCII', 'JPEG', 'DOC', 'GIF', 'MSVC', 'C source', 'PNG', 'Unicode text','PDF')
    if any(filetype in type_ for filetype in common_types):
        return True
    else:
        return False

def main(key_blob):
    """Decrypt ransomed file.

    Args:
        key_blob: A packed SIMPLEKEYBLOB containing an encryption key.

    Returns:
        True if successfully decrypted a file, False otherwise.
    """

    if not args.tox:
        key_params, key_val = decode_plaintextkey_blob(key_blob)
    else:
        key_params, key_val = 'tox', key_blob.decode('hex')


    for trim in range(0, min(args.trim, os.path.getsize(args.file))):
        decrypted_data = decrypt_file(args.file, key_val, args.mode, args.iv, trim=trim)

        if file_is_decrypted(decrypted_data):
            print("File {} decrypted @ trim = {}, key = {}, iv = {}, mode = {}, loc = {}"
                .format(args.file, trim, key_val.encode('hex'), args.iv.encode('hex'), args.mode,
                    args.out.name))

            args.out.write(decrypted_data)
            return True

    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True,
        help="Required. Specify the encrypted file to decrypt.")
    parser.add_argument('-k', '--key_blobs', required=True, default='keys.txt',
        help="Specify where the list of potential keys is, default=keys.txt")
    parser.add_argument('-o', '--out', default=sys.stdout,
        help="Specify where you want the decrypted file to go, default=stdout")
    parser.add_argument('-m', '--mode', default='cbc', choices=['cbc', 'ofb', 'ecb'],
        help="Specify what mode was used for encryption, default=cbc")
    parser.add_argument('-v','--iv', default='\x00'*16,
        help="Specify what IV was used for encryption, default=0x00*16")
    parser.add_argument('-c', '--encrypt',
        help="Encrypt the file instead with a specified key_blob.")
    parser.add_argument('-x', '--exhaustive', action='store_true', default=False,
        help="Continue attempting decryption, even after successfully finding a common file type.")
    parser.add_argument('--locky', action='store_true', default=False,
        help="Decrypt a locky ransom file.")
    parser.add_argument('--trim', action='store_true', default=1024,
        help="Amount to attempt trimming up to, default=1024")
    parser.add_argument('--tox', action='store_true', default=False,
        help="Decrypt a tox ransom file.")

    args = parser.parse_args()

    if args.mode == 'cbc':
        args.mode = AES.MODE_CBC
    elif args.mode == 'ofb':
        args.mode = AES.MODE_OFB
    elif args.mode == 'ecb':
        args.mode = AES.MODE_ECB
    else:
        print("Improper block cipher mode specified")
        sys.exit(2)

    orig_file_name = None
    if args.out != sys.stdout:
        orig_file_name = args.out
        out = open(args.out, 'wb')
        args.out = out

    if args.encrypt:
        key_blob = args.encrypt
        key_params, key_val = decode_plaintextkey_blob(key_blob)
        encrypted_data = encrypt_file(args.file, key_val, args.mode, args.iv)
        sys.exit(1)

    key_blobs = set([line.rstrip('\r\n') for line in open(args.key_blobs)])
    count = 1
    for key_blob in key_blobs:
        if main(key_blob):
            if args.exhaustive:
                # Keep going...
                count += 1
                if orig_file_name is not None:
                    # Obtain the next file name, to not overwrite all the results
                    next_filename = orig_file_name + str(count)
                    args.out.close()
                    args.out = open(next_filename, 'wb')
            else:
                # We're done!
                sys.exit(0)
