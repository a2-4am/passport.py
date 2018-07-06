from passport.patchers import Patch, Patcher
from passport.util import *

class MECC4Patcher(Patcher):
    """MECC fastloader variant 4

tested on
"""
    def should_run(self, track_num):
        return self.g.mecc_variant == 4 and track_num == 0

    def run(self, logical_sectors, track_num):
        patches = []
        for a, x, v in ((8, 0x83, b'\xD5'),
                        (8, 0x8D, b'\xAA'),
                        (8, 0x98, b'\x96'),
                        (8, 0x15, b'\xD5'),
                        (8, 0x1F, b'\xAA'),
                        (8, 0x2A, b'\xAD')):
            if logical_sectors[a][x] != v[0]:
                patches.append(Patch(0, a, x, v))
        return patches
