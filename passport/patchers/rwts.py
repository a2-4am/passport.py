from passport.patchers import Patch, Patcher
from passport.util import *

class RWTSPatcher(Patcher):
    def should_run(self, track_num):
        return self.g.is_rwts and (track_num == 0)

    def run(self, logical_sectors, track_num):
        patches = []
        lda_bpl = b'\xBD\x8C\xC0\x10\xFB'
        lda_bpl_cmp = lda_bpl + b'\xC9' + find.WILDCARD
        lda_bpl_eor = lda_bpl + b'\x49' + find.WILDCARD
        lda_jsr = b'\xA9' + find.WILDCARD + b'\x20'
        lda_jsr_d5 = lda_jsr + b'\xD5'
        lda_jsr_b8 = lda_jsr + b'\xB8'
        for a, b, c, d, e in (
                # address prologue byte 1 (read)
                (0x55, 3, b'\xD5', 0x4F, lda_bpl_cmp + b'\xD0\xF0\xEA'),
                # address prologue byte 2 (read)
                (0x5F, 3, b'\xAA', 0x59, lda_bpl_cmp + b'\xD0\xF2\xA0\x03'),
                # address prologue byte 3 (read)
                (0x6A, 3, b'\x96', 0x64, lda_bpl_cmp + b'\xD0\xE7'),
                # address epilogue byte 1 (read)
                (0x91, 3, b'\xDE', 0x8B, lda_bpl_cmp + b'\xD0\xAE'),
                # address epilogue byte 2 (read)
                (0x9B, 3, b'\xAA', 0x95, lda_bpl_cmp + b'\xD0\xA4\x18'),
                # data prologue byte 1 (read)
                (0xE7, 2, b'\xD5', 0xE1, lda_bpl_eor + b'\xD0\xF4\xEA'),
                # data prologue byte 2 (read)
                (0xF1, 2, b'\xAA', 0xEB, lda_bpl_cmp + b'\xD0\xF2\xA0\x56'),
                # data prologue byte 3 (read)
                (0xFC, 2, b'\xAD', 0xF6, lda_bpl_cmp + b'\xD0\xE7'),
                # data epilogue byte 1 (read)
                (0x35, 3, b'\xDE', 0x2F, lda_bpl_cmp + b'\xD0\x0A\xEA'),
                # data epilogue byte 2 (read)
                (0x3F, 3, b'\xAA', 0x39, lda_bpl_cmp + b'\xF0\x5C\x38'),
                # address prologue byte 1 (write)
                (0x7A, 6, b'\xD5', 0x79, lda_jsr_d5),
                # address prologue byte 2 (write)
                (0x7F, 6, b'\xAA', 0x7E, lda_jsr_d5),
                # address prologue byte 3 (write)
                (0x84, 6, b'\x96', 0x83, lda_jsr_d5),
                # address epilogue byte 1 (write)
                (0xAE, 6, b'\xDE', 0xAD, lda_jsr_d5),
                # address epilogue byte 2 (write)
                (0xB3, 6, b'\xAA', 0xB2, lda_jsr_d5),
                # address epilogue byte 3 (write)
                (0xB8, 6, b'\xEB', 0xB7, lda_jsr_d5),
                # data prologue byte 1 (write)
                (0x53, 2, b'\xD5', 0x52, lda_jsr_b8),
                # data prologue byte 2 (write)
                (0x58, 2, b'\xAA', 0x57, lda_jsr_b8),
                # data prologue byte 3 (write)
                (0x5D, 2, b'\xAD', 0x5C, lda_jsr_b8),
                # data epilogue byte 1 (write)
                (0x9E, 2, b'\xDE', 0x9D, lda_jsr_b8),
                # data epilogue byte 2 (write)
                (0xA3, 2, b'\xAA', 0xA2, lda_jsr_b8),
                # data epilogue byte 3 (write)
                (0xA8, 2, b'\xEB', 0xA7, lda_jsr_b8),
                # data epilogue byte 4 (write)
                # needed by some Sunburst disks
                (0xAD, 2, b'\xFF', 0xAC, lda_jsr_b8),
        ):
            if not find.at(a, logical_sectors[b], c) and \
               find.wild_at(d, logical_sectors[b], e):
                patches.append(Patch(0, b, a, c))
        return patches
