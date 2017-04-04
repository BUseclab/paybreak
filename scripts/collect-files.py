#!/usr/bin/env python
"""Collect all the encrypted files.
"""
import os
import shutil
import magic
m = magic.Magic(magic_file="magic")

START = "C:/"
FILES_DIR = "collected-files"
DRY = True
collected_files = []

def get_file_type(file_name):
    return m.from_file(file_name)

for root, dirs, files in os.walk(START):
    for file in files:
        if FILES_DIR in root:
            continue

        full_file_path = os.path.join(root, os.path.basename(file))

        try:
            if get_file_type(full_file_path) != 'data':
                continue
        except IOError:
            print("Permission denied :(")
            continue
        except:
            print("Something went wrong... let's ignore it!")
            continue

        print(full_file_path)
        if not DRY:
            try:
                shutil.copy(full_file_path, FILES_DIR)
            except IOError:
                 print("Permission Denied :(")

            collected_files.append(file)


