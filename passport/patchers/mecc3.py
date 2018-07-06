from passport.patchers import Patch, Patcher
from passport.util import *

class MECC3Patcher(Patcher):
    """MECC fastloader variant 3

tested on
- A-153 Word Munchers 1.1
"""
    def should_run(self, track_num):
        return self.g.mecc_variant == 3 and track_num == 0

    def run(self, logical_sectors, track_num):
        patches = []
        for a, x, v in ((0x0A, 0xE8, b'\xD5'),
                        (0x0A, 0xF2, b'\xAA'),
                        (0x0A, 0xFD, b'\x96'),
                        (0x0B, 0x6F, b'\xD5'),
                        (0x0B, 0x79, b'\xAA'),
                        (0x0B, 0x83, b'\xAD')):
            if logical_sectors[a][x] != v[0]:
                patches.append(Patch(0, a, x, v))
        return patches
