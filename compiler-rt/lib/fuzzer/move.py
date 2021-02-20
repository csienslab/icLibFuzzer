#!/usr/bin/python3

import sys
import os
import argparse

args = argparse.ArgumentParser()
args.add_argument("--mode", "-m", required=True, choices=["origin", "small"],
        help="which mode of libfuzzer do you want?:\n\torigin: origin libfuzzer\n\tsmall : execv to create small forkserver")

FLAG = args.parse_args()
mode = FLAG.mode

names = ['FuzzerTracePC.h',
         'FuzzerTracePC.cpp',
         'FuzzerDriver.cpp',
         'FuzzerDictionary.h',
         'FuzzerLoop.cpp',
         'FuzzerValueBitMap.h',
         'FuzzerInternal.h',
         'FuzzerOptions.h',
         'FuzzerMain.cpp',
         'FuzzerFlags.def']



CURRENT_DIR = '.'

if mode == 'origin':
    for name in names:
        origin_name = os.path.join(CURRENT_DIR, 'origin_' + name)
        name = os.path.join(CURRENT_DIR, name)
        os.system('cp {} {}'.format(originname, name))
elif mode == 'small':
    for name in names:
        small_name = os.path.join(CURRENT_DIR, 'small_' + name)
        name = os.path.join(CURRENT_DIR, name)
        os.system('cp {} {}'.format(small_name, name))
else:
    print ('wtf')



