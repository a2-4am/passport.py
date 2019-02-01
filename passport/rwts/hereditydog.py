from passport.rwts.dos33 import DOS33RWTS

class HeredityDogRWTS(DOS33RWTS):
    def data_field_at_point(self, track, logical_track_num, physical_sector_num):
        if (logical_track_num, physical_sector_num) == (0x00, 0x0A):
            # This sector is fake, full of too many consecutive 0s,
            # designed to read differently every time. We go through
            # and clean the stray bits, and be careful not to go past
            # the end so we don't include the next address prologue.
            start_index = track.bit_index
            while (track.bit_index < start_index + (343*8)):
                if self.nibble_translate_table.get(next(track.nibble()), 0xFF) == 0xFF:
                    track.bits[track.bit_index-8:track.bit_index] = 0
                    self.g.found_and_cleaned_weakbits = True
            return bytearray(256)
        return DOS33RWTS.data_field_at_point(self, track, logical_track_num, physical_sector_num)

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        if (logical_track_num, physical_sector_num) == (0x00, 0x0A):
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
