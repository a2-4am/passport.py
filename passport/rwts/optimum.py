from passport.rwts.dos33 import DOS33RWTS

class OptimumResourceRWTS(DOS33RWTS):
    def data_field_at_point(self, track, logical_track_num, physical_sector_num):
        if (logical_track_num, physical_sector_num) == (0x01, 0x0F):
            # TODO actually decode these
            disk_nibbles = []
            for i in range(343):
                disk_nibbles.append(next(track.nibble()))
            return bytearray(256) # all zeroes for now
        return DOS33RWTS.data_field_at_point(self, track, logical_track_num, physical_sector_num)

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        if (logical_track_num, physical_sector_num) == (0x01, 0x0F):
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
