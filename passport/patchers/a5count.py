from passport.patchers import Patch, Patcher
from passport.util import *

class A5CountPatcher(Patcher):
    """nibble count between $A5 and address prologue

tested on
- Game Frame One
- Game Frame Two
"""
    def should_run(self, track_num):
        return self.g.is_pascal

    def run(self, logical_sectors, track_num):
        offset = find.wild(concat_track(logical_sectors),
                           b'\x07'
                           b'\xE6\x02'
                           b'\xD0\x03'
                           b'\x4C\xA5\x00'
                           b'\xC9\xA5')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, 8 + (offset % 256), b'\xD0\x7B', "a5count")]
