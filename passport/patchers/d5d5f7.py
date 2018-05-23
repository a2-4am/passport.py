from passport.patchers import Patch, Patcher
from passport.util import *

class D5D5F7Patcher(Patcher):
    """nibble count with weird bitstream involving $D5 and $F7 as delimiters

tested on
- Ace Detective
- Cat 'n Mouse
- Cotton Tales
- Dyno-Quest
- Easy Street
- Fraction-oids
- Math Magic
- RoboMath
- NoteCard Maker
"""
    def should_run(self, track_num):
        # TODO
        return True

    def run(self, logical_sectors, track_num):
        offset = find.wild(concat_track(logical_sectors),
                           b'\xBD\x8C\xC0'
                           b'\x10\xFB'
                           b'\x48'
                           b'\x68'
                           b'\xC9\xD5'
                           b'\xD0\xF5'
                           b'\xA0\x00' + \
                           b'\x8C' + find.WILDCARD + find.WILDCARD + \
                           b'\xBD\x8C\xC0'
                           b'\x10\xFB'
                           b'\xC9\xD5'
                           b'\xF0\x0F'
                           b'\xC9\xF7'
                           b'\xD0\x01'
                           b'\xC8'
                           b'\x18'
                           b'\x6D')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, offset % 256, b'\x60', "d5d5f7")]
