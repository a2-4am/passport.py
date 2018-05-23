#!/usr/bin/env python3

from passport import *
import sys

def opener(filename):
    base, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext == '.woz':
        return wozimage.WozReader(filename)
    if ext == '.edd':
        return wozimage.EDDReader(filename)
    raise RuntimeError("unrecognized file type")

Crack(opener(sys.argv[1]), DefaultLogger)
