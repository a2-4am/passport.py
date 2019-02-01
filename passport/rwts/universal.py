from passport.rwts import RWTS

class UniversalRWTS(RWTS):
    acceptable_address_prologues = ((0xD4,0xAA,0x96), (0xD5,0xAA,0x96))

    def __init__(self, g):
        RWTS.__init__(self, g, address_epilogue=[], data_epilogue=[])

    def find_address_prologue(self, track):
        starting_revolutions = track.revolutions
        seen = [0,0,0]
        while (track.revolutions < starting_revolutions + 2):
            del seen[0]
            seen.append(next(track.nibble()))
            if tuple(seen) in self.acceptable_address_prologues: return True
        return False

    def verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
#        return True
        if not self.address_epilogue:
            self.address_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
        next(track.nibble())
        next(track.nibble())
        return result

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        if not self.data_epilogue:
            self.data_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num)
        next(track.nibble())
        next(track.nibble())
        return result

class UniversalRWTSIgnoreEpilogues(UniversalRWTS):
    def verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        return True

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        return True

class Track00RWTS(UniversalRWTSIgnoreEpilogues):
    def data_field_at_point(self, track, logical_track_num, physical_sector_num):
        start_index = track.bit_index
        start_revolutions = track.revolutions
        decoded = UniversalRWTS.data_field_at_point(self, track, logical_track_num, physical_sector_num)
        if not decoded:
            # If the sector didn't decode properly, rewind to the
            # beginning of the data field before returning to the
            # caller. This is for disks with a fake T00,S0A that
            # is full of consecutive 0s, where if we consume the bitstream
            # as nibbles, we'll end up consuming the next address field
            # and it will seem like that sector doesn't exist. And that
            # is generally logical sector 2, which is important not to
            # miss at this stage because its absence triggers a different
            # code path and everything falls apart.
            track.bit_index = start_index
            track.revolutions = start_revolutions
        return decoded
