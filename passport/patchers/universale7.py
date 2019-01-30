from passport.patchers import Patch, Patcher
from passport.util import *

class UniversalE7Patcher(Patcher):
    """replace remnants of E7 bitstream with a compatible BYTEstream that fools most E7 protection checks

(invented by qkumba, see PoC||GTFO 0x11 and 4am crack no. 655 Rocky's Boots 4.0 for explanation)
"""
    e7sector = b'\x00'*0xA0 + b'\xAC\x00'*0x30

    def should_run(self, track_num):
        return True

    def run(self, logical_sectors, track_num):
        patches = []
        for sector_num in logical_sectors:
            if find.at(0x00, logical_sectors[sector_num], self.e7sector):
                patches.append(Patch(track_num, sector_num, 0xA3, b'\x64\xB4\x44\x80\x2C\xDC\x18\xB4\x44\x80\x44\xB4', "e7"))
        return patches
