from passport.rwts.dos33 import DOS33RWTS

class InfocomRWTS(DOS33RWTS):
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.data_prologue = self.data_prologue[:2]

    def find_data_prologue(self, track, logical_track_num, physical_sector_num):
        if not DOS33RWTS.find_data_prologue(self, track, logical_track_num, physical_sector_num):
            return False
        return next(track.nibble()) >= 0xAD
