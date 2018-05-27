from passport.patchers import Patch, Patcher
from passport.util import *

class BBF9Patcher(Patcher):
    """patch nibble check seen in Sunburst disks 1988 and later

see write-up of 4am crack no. 1165 Muppet Slate

tested on
- Muppet Slate (1988)
- Memory Building Blocks (1989)
- Odd One Out (1989)
- Regrouping (1989)
- Simon Says (1989)
- Teddy and Iggy (1990)
- 1-2-3 Sequence Me (1991)
"""
    def should_run(self, track_num):
        return self.g.is_prodos

    def run(self, logical_sectors, track_num):
        buffy = concat_track(logical_sectors)
        if -1 == find.wild(buffy,
                           b'\x8E\xC0'
                           b'\x18'
                           b'\xA5' + find.WILDCARD + \
                           b'\x69\x8C'
                           b'\x8D'): return []
        offset = find.wild(buffy,
                           b'\xBD\x89\xC0')
        if offset == -1: return []
        return [Patch(track_num, offset // 256, offset % 256, b'\x18\x60', "bbf9")]
