from passport.rwts.dos33 import DOS33RWTS

class BECARWTS(DOS33RWTS):
    def is_protected_sector(self, logical_track_num, physical_sector_num):
        if logical_track_num > 0: return True
        return physical_sector_num not in (0x00, 0x0D, 0x0B, 0x09, 0x07, 0x05, 0x03, 0x01, 0x0E, 0x0C)

    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.data_prologue = self.data_prologue[:2]

    def verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        if self.is_protected_sector(logical_track_num, physical_sector_num):
            return DOS33RWTS.verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
        return True

    def find_data_prologue(self, track, logical_track_num, physical_sector_num):
        if not DOS33RWTS.find_data_prologue(self, track, logical_track_num, physical_sector_num):
            return False
        next(track.nibble())
        if self.is_protected_sector(logical_track_num, physical_sector_num):
            next(track.bit())
            next(track.nibble())
            next(track.bit())
            next(track.bit())
        return True

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        if self.is_protected_sector(logical_track_num, physical_sector_num):
            next(track.nibble())
        if logical_track_num == 0:
            next(track.nibble())
            next(track.nibble())
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
