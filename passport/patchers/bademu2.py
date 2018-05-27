from passport.patchers import Patch, Patcher
from passport.util import *

class BadEmu2Patcher(Patcher):
    """RWTS checks for timing bit by checking if data latch is still $D5 after waiting "too long" but this confuses legacy emulators (AppleWin, older versions of MAME) so we patch it for compatibility

tested on
- Dino Dig
- Make A Face
"""
    def should_run(self, track_num):
        return self.g.is_rwts and (track_num == 0)

    def run(self, logical_sectors, track_num):
        if not find.at(0x4F, logical_sectors[3],
                       b'\xBD\x8C\xC0'
                       b'\x10\xFB'
                       b'\x4A'
                       b'\xC9\x6A'
                       b'\xD0\xEF'
                       b'\xBD\x8C\xC0'
                       b'\xC9\xD5'
                       b'\xF0\x12'): return []
        return [Patch(0, 3, 0x59, b'\xF0\x05')]
        return patches
