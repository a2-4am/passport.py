from passport.patchers import Patch, Patcher
from passport.util import *

class MECC2Patcher(Patcher):
    """MECC fastloader variant 2

tested on
- A-175 Phonics Prime Time - Initial Consonants 1.0
- A-176 Phonics Prime Time - Final Consonants 1.0
- A-179 Phonics Prime Time - Blends and Digraphs 1.0
"""
    def should_run(self, track_num):
        return self.g.mecc_variant == 2 and track_num == 0

    def run(self, logical_sectors, track_num):
        patches = []
        for a, x, v in ((7, 0x83, b'\xD5'),
                        (7, 0x8D, b'\xAA'),
                        (7, 0x98, b'\x96'),
                        (7, 0x15, b'\xD5'),
                        (7, 0x1F, b'\xAA'),
                        (7, 0x2A, b'\xAD')):
            if logical_sectors[a][x] != v[0]:
                patches.append(Patch(0, a, x, v))
        return patches
