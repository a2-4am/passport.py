from passport.patchers import Patch, Patcher
from passport.util import *

class MicrofunPatcher(Patcher):
    def should_run(self, track_num):
        return self.g.is_rwts and (track_num == 0)

    def run(self, logical_sectors, track_num):
        offset = find.wild(concat_track(logical_sectors),
                           b'\xA0\x00\x84\x26\x84\x27\xBD\x8C\xC0')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, offset % 256, b'\x18\x60', "microfun")]
