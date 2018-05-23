from passport.patchers import Patch, Patcher
from passport.util import *

class A6BC95Patcher(Patcher):
    """nibble count after $A6 $BC $95 prologue

tested on
- The Secrets of Science Island
"""
    def should_run(self, track_num):
        return self.g.is_pascal

    def run(self, logical_sectors, track_num):
        buffy = concat_track(logical_sectors)
        if -1 == find.wild(buffy,
                           b'\xBD\x8C\xC0'
                           b'\x10\xFB'
                           b'\xC9\xA6'
                           b'\xD0\xED'):
            return False
        if -1 == find.wild(buffy,
                           b'\xBD\x8C\xC0'
                           b'\x10\xFB'
                           b'\xC9\xBC'):
            return False
        if -1 == find.wild(buffy,
                           b'\xBD\x8C\xC0'
                           b'\x10\xFB'
                           b'\xC9\x95'):
            return False
        offset = find.wild(buffy,
                           b'\xAE\xF8\x01'
                           b'\xA9\x0A'
                           b'\x8D\xFE\x01')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, offset % 256, b'\x60', "a6bc95")]
