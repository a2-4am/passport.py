from passport.rwts.dos33 import DOS33RWTS

class D5TimingBitRWTS(DOS33RWTS):
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.data_prologue = (logical_sectors[2][0xE7],
                              0xAA,
                              logical_sectors[2][0xFC])
        self.data_epilogue = (logical_sectors[3][0x35],
                              0xAA)

    def find_address_prologue(self, track):
        starting_revolutions = track.revolutions
        while (track.revolutions < starting_revolutions + 2):
            if next(track.nibble()) == 0xD5:
                bit = next(track.bit())
                if bit == 0: return True
                track.rewind(1)
        return False

    def verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        return True
