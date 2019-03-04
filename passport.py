#!/usr/bin/env python3

# (c) 2018-9 by 4am
# MIT-licensed

from passport import eddimage, wozardry, a2rimage
from passport.loggers import DefaultLogger, DebugLogger
from passport import Crack, Verify, Convert
from passport.strings import __date__, STRINGS
import argparse
import os.path

__version__ = "0.2" # https://semver.org/
__progname__ = "passport"

class BaseCommand:
    def __init__(self, name):
        self.name = name
        self.logger = None
        self.reader = None
        self.processor = None

    def setup(self, subparser, description=None, epilog=None, help="disk image (.a2r, .woz, .edd)", formatter_class=argparse.HelpFormatter):
        self.parser = subparser.add_parser(self.name, description=description, epilog=epilog, formatter_class=formatter_class)
        self.parser.add_argument("file", help=help)
        self.parser.set_defaults(action=self)

    def __call__(self, args):
        if not self.processor: return
        if not self.reader:
            base, ext = os.path.splitext(args.file)
            ext = ext.lower()
            if ext == ".woz":
                self.reader = wozardry.WozDiskImage
            elif ext == ".edd":
                self.reader = eddimage.EDDReader
            elif ext == ".a2r":
                self.reader = a2rimage.A2RImage
            else:
                print("unrecognized file type")
        if not self.logger:
            self.logger = args.debug and DebugLogger or DefaultLogger
        with open(args.file, "rb") as f:
            self.processor(args.file, self.reader(f), self.logger)

class CommandVerify(BaseCommand):
    def __init__(self):
        BaseCommand.__init__(self, "verify")
        self.processor = Verify

    def setup(self, subparser):
        BaseCommand.setup(self, subparser,
                          description="Verify track structure and sector data in a disk image")

class CommandConvert(BaseCommand):
    def __init__(self):
        BaseCommand.__init__(self, "convert")
        self.processor = Convert

    def setup(self, subparser):
        BaseCommand.setup(self, subparser,
                          description="Convert a disk image to .woz format")

class CommandCrack(BaseCommand):
    def __init__(self):
        BaseCommand.__init__(self, "crack")
        self.processor = Crack

    def setup(self, subparser):
        BaseCommand.setup(self, subparser,
                          description="Convert a disk image to .dsk format")

if __name__ == "__main__":
    cmds = [CommandVerify(), CommandConvert(), CommandCrack()]
    parser = argparse.ArgumentParser(prog=__progname__,
                                     description="""A multi-purpose tool for working with copy-protected Apple II disk images.

See '""" + __progname__ + """ <command> -h' for help on individual commands.""",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version=STRINGS["header"])
    parser.add_argument("-d", "--debug", action="store_true", help="print debugging information while processing")
    sp = parser.add_subparsers(dest="command", help="command")
    for command in cmds:
        command.setup(sp)
    args = parser.parse_args()
    args.action(args)
