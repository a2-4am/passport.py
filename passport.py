#!/usr/bin/env python3

from passport import *
import sys

def usage():
    print("usage: passport image.woz [Crack]\n"
          "       passport image.woz [Verify]\n"
          "       passport image.edd [Convert]\n"
          "       default is Crack if .woz specified, Convert if .edd is specified"
         )
    sys.exit()

args = len(sys.argv)

if args < 2:
    usage()

base, ext = os.path.splitext(sys.argv[1])
ext = ext.lower()

if ext == ".woz":
    if args == 2 or sys.argv[2].lower() == "crack":
        Crack(wozimage.WozReader(sys.argv[1]), DefaultLogger)
    elif sys.argv[2].lower() == "verify":
        Verify(wozimage.WozReader(sys.argv[1]), DefaultLogger)
    else:
        usage()
elif ext == ".edd":
    EDDToWoz(wozimage.EDDReader(sys.argv[1]), DefaultLogger)
else:
    raise RuntimeError("unrecognized file type")
