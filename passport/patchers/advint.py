from passport.patchers import Patch, Patcher
from passport.util import *

class AdventureInternationalPatcher(Patcher):
    """encrypted protection check on Adventure International disks

tested on
- SAGA1 - Adventureland v2.1-416
- SAGA2 - Pirate Adventure v2.1-408
- SAGA5 - The Count v2.1-115
- SAGA6 - Strange Odyssey v2.1-119
"""
    def should_run(self, track_num):
        return True # TODO self.g.is_adventure_international

    def run(self, logical_sectors, track_num):
        buffy = concat_track(logical_sectors)
        offset = find.wild(buffy,
                           b'\x85' + find.WILDCARD + find.WILDCARD + \
                           b'\x74\x45\x09'
                           b'\xD9\x32'
                           b'\x0C\x30')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, offset % 256, b'\xD1\x59\xA7', "advint")]
