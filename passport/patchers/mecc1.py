from passport.patchers import Patch, Patcher
from passport.util import *

class MECC1Patcher(Patcher):
    """MECC fastloader variant 1

tested on
- A-153 Word Munchers 1.4
"""
    def should_run(self, track_num):
        return self.g.mecc_variant == 1 and track_num == 0

    def run(self, logical_sectors, track_num):
        patches = []
        for a, x, v in ((0x0B, 0x08, b'\xD5'),
                        (0x0B, 0x12, b'\xAA'),
                        (0x0B, 0x1D, b'\x96'),
                        (0x0B, 0x8F, b'\xD5'),
                        (0x0B, 0x99, b'\xAA'),
                        (0x0B, 0xA3, b'\xAD')):
            if logical_sectors[a][x] != v[0]:
                patches.append(Patch(0, a, x, v))
        return patches
