from passport.patchers import Patch, Patcher
from passport.util import *

class SunburstPatcher(Patcher):
    """RWTS with track-based address and data prologue modifications

tested on
- Challenge Math
- Safari Search
- Ten Clues
- The Factory
- Trading Post
- Word Quest
"""
    def should_run(self, track_num):
        return self.g.is_rwts and (track_num == 0)

    def run(self, logical_sectors, track_num):
        if not find.at(0x40, logical_sectors[3], b'\xD0'): return []
        if not find.at(0x9C, logical_sectors[3], b'\xF0'): return []
        if not find.at(0x69, logical_sectors[4], bytes.fromhex(
                "48"
                "A5 2A"
                "4A"
                "A8"
                "B9 29 BA"
                "8D 6A B9"
                "8D 84 BC"
                "B9 34 BA"
                "8D FC B8"
                "8D 5D B8"
                "C0 11"
                "D0 03"
                "A9 02"
                "AC"
                "A9 0E"
                "8D C0 BF"
                "68"
                "69 00"
                "48"
                "AD 78 04"
                "90 2B")): return []
        if not find.at(0x69, logical_sectors[6], bytes.fromhex(
                "4C B8 B6"
                "EA"
                "EA"
                "EA")): return []
        if not find.at(0x8C, logical_sectors[8], bytes.fromhex(
                "69 BA")): return []
        return [Patch(0, 3, 0x40, bytes.fromhex("F0")),
                Patch(0, 3, 0x9C, bytes.fromhex("D0")),
                Patch(0, 6, 0x69, bytes.fromhex("20 C3 BC 20 C3 BC")),
                Patch(0, 8, 0x8C, bytes.fromhex("A0 B9"))]
