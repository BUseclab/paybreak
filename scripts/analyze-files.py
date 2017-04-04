#!/usr/bin/env python
"""Analyze files for their filetype and md5sum
"""
import hashlib
import os
import magic

FILES_DIR = 'files-to-spread'
MD5_OUT_FILE = 'file_info.txt'

outfile = open(MD5_OUT_FILE, 'w')

def get_file_type(filedata):
    type_ = magic.from_buffer(filedata)
    return type_

for root, dir, files in os.walk(FILES_DIR):
    for name in files:
        file = os.path.join(root, name)
        with open(file, 'r') as f:
            filedata = f.read()
            md5str = hashlib.md5(filedata).hexdigest()
            filetype = get_file_type(filedata)

            line = name + "\t" + filetype + "\t" + md5str + "\n"
            outfile.write(line)
            print(line)
            
outfile.close()
