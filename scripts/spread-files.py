#!/usr/bin/env python
"""Spread out honey files throughout the OS FS
"""
import os
import random
import shutil

START = "C:/"
FILES_DIR = "files-to-spread"
DRY = False

spread_files = []

for root, dir, files in os.walk(FILES_DIR):
    for name in files:
        file = os.path.join(root, name)
        spread_files.append(file)


for root, dirs, files in os.walk(START):
    for dirname in dirs:
        if 'FILES_DIR' in root or dirname == FILES_DIR:
            continue

        rand_amnt = random.randint(0, 3)
        for i in range(rand_amnt):
            file = random.choice(spread_files)

            if DRY:
                print(file, os.path.join(root, os.path.basename(file)))
            else:
                print(file, os.path.join(root, os.path.basename(file)))
                try:
                    shutil.copy(file, os.path.join(root, os.path.basename(file)))
                except IOError:
                    print("Permission Denied :(")

            spread_files.remove(file)


