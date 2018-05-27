from passport.patchers import Patch, Patcher
from passport.util import *

class BorderPatcher(Patcher):
    """RWTS changes prologue and epilogue sequences with an RWTS swapper at $BE5A

tested on
- Arena
- Early Bird
"""
    def should_run(self, track_num):
        return self.g.is_boot0 and self.g.is_boot1 and track_num == 0

    def run(self, logical_sectors, track_num):
        if not find.at(0x5A, logical_sectors[8],
                       b'\xC9\x23'
                       b'\xB0\xEB'
                       b'\x0A'
                       b'\x20\x6C\xBF'
                       b'\xEA'
                       b'\xEA'): return []
        return [Patch(0, 8, 0x5A, b'\x48\xA0\x01\xB1\x3C\x6A\x68\x90\x08\x0A', "border")]
