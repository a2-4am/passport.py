from passport.rwts.dos33 import DOS33RWTS

class SunburstRWTS(DOS33RWTS):
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.address_epilogue = (logical_sectors[3][0x91],)
        self.data_epilogue = (logical_sectors[3][0x35],)
        self.address_prologue_third_nibble_by_track = logical_sectors[4][0x29:]
        self.data_prologue_third_nibble_by_track = logical_sectors[4][0x34:]

    def seek(self, logical_track_num):
        self.address_prologue = (self.address_prologue[0],
                                 self.address_prologue[1],
                                 self.address_prologue_third_nibble_by_track[logical_track_num])
        self.data_prologue = (self.data_prologue[0],
                              self.data_prologue[1],
                              self.data_prologue_third_nibble_by_track[logical_track_num])
        DOS33RWTS.seek(self, logical_track_num)
        if logical_track_num >= 0x11:
            return logical_track_num + 0.5
        else:
            return float(logical_track_num)
