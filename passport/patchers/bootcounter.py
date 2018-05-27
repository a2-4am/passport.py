from passport.patchers import Patch, Patcher
from passport.util import *

class BootCounterPatcher(Patcher):
    """MECC "limited backup" disks contain code to self-destruct after a certain number of boots"""
    def should_run(self, track_num):
        return track_num == 1

    def run(self, logical_sectors, track_num):
        if not find.wild_at(0x00, logical_sectors[0],
                       b'\xAD\xF3\x03'
                       b'\x8D\xF4\x03'
                       b'\x20\x2F\xFB'
                       b'\x20\x93\xFE'
                       b'\x20\x89\xFE'
                       b'\x20\x58\xFC'
                       b'\xA9\x0A'
                       b'\x85\x25'
                       b'\x2C' + find.WILDCARD + find.WILDCARD + \
                       b'\xCE\x17\x18'
                       b'\xD0\x05'
                       b'\xA9\x80'
                       b'\x8D\x18\x18'): return []
        return [Patch(1, 0, 0x00, b'\x4C\x03\x1B', "bootcounter")]
        return patches
