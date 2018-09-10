#!/usr/bin/env python3

from passport import wozimage
from passport.patchers import *
from passport.strings import *
from passport.util import *
import bitarray
import collections
import os.path
import sys
import time

class BaseLogger: # base class
    def __init__(self, g):
        self.g = g

    def PrintByID(self, id, params = {}):
        """prints a predefined string, parameterized with some passed parameters and some globals"""
        pass

    def debug(self, s):
        pass

    def to_hex_string(self, n):
        if type(n) == int:
            return hex(n)[2:].rjust(2, "0").upper()
        if type(n) in (bytes, bytearray):
            return "".join([self.to_hex_string(x) for x in n])

SilentLogger = BaseLogger

class DefaultLogger(BaseLogger):
    # logger that writes to sys.stdout
    def PrintByID(self, id, params = {}):
        p = params.copy()
        if "track" not in p:
            p["track"] = self.g.track
        if "sector" not in params:
            p["sector"] = self.g.sector
        for k in ("track", "sector", "offset", "old_value", "new_value"):
            p[k] = self.to_hex_string(p.get(k, 0))
        sys.stdout.write(STRINGS[id].format(**p))

class DebugLogger(DefaultLogger):
    # logger that writes to sys.stdout, and writes debug information to sys.stderr
    def debug(self, s):
        sys.stderr.write(s)
        sys.stderr.write("\n")

class PassportGlobals:
    def __init__(self):
        # things about the disk
        self.is_boot0 = False
        self.is_boot1 = False
        self.is_master = False
        self.is_rwts = False
        self.is_dos32 = False
        self.is_prodos = False
        self.is_dinkeydos = False
        self.is_pascal = False
        self.is_protdos = False
        self.is_daviddos = False
        self.is_ea = False
        self.possible_gamco = False
        self.is_optimum = False
        self.is_mecc_fastloader = False
        self.mecc_variant = 0
        self.possible_d5d5f7 = False
        self.is_8b3 = False
        self.is_milliken1 = False
        self.is_adventure_international = False
        self.is_laureate = False
        self.is_datasoft = False
        self.is_sierra = False
        self.is_sierra13 = False
        self.is_f7f6 = False
        self.is_trillium = False
        self.polarware_tamper_check = False
        self.force_disk_vol = False
        self.captured_disk_volume_number = False
        self.disk_volume_number = None
        self.found_and_cleaned_weakbits = False
        self.protection_enforces_write_protected = False
        # things about the conversion process
        self.tried_univ = False
        self.track = 0
        self.sector = 0
        self.last_track = 0

class AddressField:
    def __init__(self, volume, track_num, sector_num, checksum):
        self.volume = volume
        self.track_num = track_num
        self.sector_num = sector_num
        self.checksum = checksum
        self.valid = (volume ^ track_num ^ sector_num ^ checksum) == 0

class Sector:
    def __init__(self, address_field, decoded, start_bit_index=None, end_bit_index=None):
        self.address_field = address_field
        self.decoded = decoded
        self.start_bit_index = start_bit_index
        self.end_bit_index = end_bit_index

    def __getitem__(self, i):
        return self.decoded[i]

class RWTS:
    kDefaultSectorOrder16 =     (0x00, 0x07, 0x0E, 0x06, 0x0D, 0x05, 0x0C, 0x04, 0x0B, 0x03, 0x0A, 0x02, 0x09, 0x01, 0x08, 0x0F)
    kDefaultAddressPrologue16 = (0xD5, 0xAA, 0x96)
    kDefaultAddressEpilogue16 = (0xDE, 0xAA)
    kDefaultDataPrologue16 =    (0xD5, 0xAA, 0xAD)
    kDefaultDataEpilogue16 =    (0xDE, 0xAA)
    kDefaultNibbleTranslationTable16 = {
        0x96: 0x00, 0x97: 0x01, 0x9a: 0x02, 0x9b: 0x03, 0x9d: 0x04, 0x9e: 0x05, 0x9f: 0x06, 0xa6: 0x07,
        0xa7: 0x08, 0xab: 0x09, 0xac: 0x0a, 0xad: 0x0b, 0xae: 0x0c, 0xaf: 0x0d, 0xb2: 0x0e, 0xb3: 0x0f,
        0xb4: 0x10, 0xb5: 0x11, 0xb6: 0x12, 0xb7: 0x13, 0xb9: 0x14, 0xba: 0x15, 0xbb: 0x16, 0xbc: 0x17,
        0xbd: 0x18, 0xbe: 0x19, 0xbf: 0x1a, 0xcb: 0x1b, 0xcd: 0x1c, 0xce: 0x1d, 0xcf: 0x1e, 0xd3: 0x1f,
        0xd6: 0x20, 0xd7: 0x21, 0xd9: 0x22, 0xda: 0x23, 0xdb: 0x24, 0xdc: 0x25, 0xdd: 0x26, 0xde: 0x27,
        0xdf: 0x28, 0xe5: 0x29, 0xe6: 0x2a, 0xe7: 0x2b, 0xe9: 0x2c, 0xea: 0x2d, 0xeb: 0x2e, 0xec: 0x2f,
        0xed: 0x30, 0xee: 0x31, 0xef: 0x32, 0xf2: 0x33, 0xf3: 0x34, 0xf4: 0x35, 0xf5: 0x36, 0xf6: 0x37,
        0xf7: 0x38, 0xf9: 0x39, 0xfa: 0x3a, 0xfb: 0x3b, 0xfc: 0x3c, 0xfd: 0x3d, 0xfe: 0x3e, 0xff: 0x3f,
    }

    def __init__(self,
                 g,
                 sectors_per_track = 16,
                 address_prologue = kDefaultAddressPrologue16,
                 address_epilogue = kDefaultAddressEpilogue16,
                 data_prologue = kDefaultDataPrologue16,
                 data_epilogue = kDefaultDataEpilogue16,
                 sector_order = kDefaultSectorOrder16,
                 nibble_translate_table = kDefaultNibbleTranslationTable16):
        self.sectors_per_track = sectors_per_track
        self.address_prologue = address_prologue
        self.address_epilogue = address_epilogue
        self.data_prologue = data_prologue
        self.data_epilogue = data_epilogue
        self.sector_order = sector_order
        self.nibble_translate_table = nibble_translate_table
        self.g = g
        self.track_num = 0

    def seek(self, track_num):
        self.track_num = track_num

    def reorder_to_logical_sectors(self, sectors):
        logical = {}
        for k, v in sectors.items():
            logical[self.sector_order[k]] = v
        return logical

    def find_address_prologue(self, track):
        return track.find(self.address_prologue)

    def address_field_at_point(self, track):
        volume = decode44(next(track.nibble()), next(track.nibble()))
        track_num = decode44(next(track.nibble()), next(track.nibble()))
        sector_num = decode44(next(track.nibble()), next(track.nibble()))
        checksum = decode44(next(track.nibble()), next(track.nibble()))
        return AddressField(volume, track_num, sector_num, checksum)

    def verify_nibbles_at_point(self, track, nibbles):
        found = []
        for i in nibbles:
            found.append(next(track.nibble()))
        return tuple(found) == tuple(nibbles)

    def verify_address_epilogue_at_point(self, track, track_num, physical_sector_num):
        return self.verify_nibbles_at_point(track, self.address_epilogue)

    def find_data_prologue(self, track, track_num, physical_sector_num):
        return track.find(self.data_prologue)

    def data_field_at_point(self, track, track_num, physical_sector_num):
        disk_nibbles = []
        for i in range(343):
            disk_nibbles.append(next(track.nibble()))
        checksum = 0
        secondary = []
        decoded = []
        for i in range(86):
            n = disk_nibbles[i]
            if n not in self.nibble_translate_table: return None
            b = self.nibble_translate_table[n]
            if b >= 0x80: return None
            checksum ^= b
            secondary.insert(0, checksum)
        for i in range(86, 342):
            n = disk_nibbles[i]
            if n not in self.nibble_translate_table: return None
            b = self.nibble_translate_table[n]
            if b >= 0x80: return None
            checksum ^= b
            decoded.append(checksum << 2)
        n = disk_nibbles[i]
        if n not in self.nibble_translate_table: return None
        b = self.nibble_translate_table[n]
        if b >= 0x80: return None
        checksum ^= b
        for i in range(86):
            low2 = secondary[85 - i]
            decoded[i] += (((low2 & 0b000001) << 1) + ((low2 & 0b000010) >> 1))
            decoded[i + 86] += (((low2 & 0b000100) >> 1) + ((low2 & 0b001000) >> 3))
            if i < 84:
                decoded[i + 172] += (((low2 & 0b010000) >> 3) + ((low2 & 0b100000) >> 5))
        return bytearray(decoded)

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        return self.verify_nibbles_at_point(track, self.data_epilogue)

    def decode_track(self, track, track_num, burn=0):
        sectors = collections.OrderedDict()
        if not track: return sectors
        starting_revolutions = track.revolutions
        verified_sectors = []
        while (len(verified_sectors) < self.sectors_per_track) and \
              (track.revolutions < starting_revolutions + 2):
            # store start index within track (used for .edd -> .woz conversion)
            start_bit_index = track.bit_index
            if not self.find_address_prologue(track):
                # if we can't even find a single address prologue, just give up
                self.g.logger.debug("can't find a single address prologue so LGTM or whatever")
                break
            # for edd->woz conversion, only save some of the bits preceding
            # the address prologue
            if track.bit_index - start_bit_index > 256:
                start_bit_index = track.bit_index - 256
            # decode address field
            address_field = self.address_field_at_point(track)
            self.g.logger.debug("found sector %s" % hex(address_field.sector_num)[2:].upper())
            if address_field.sector_num in verified_sectors:
                # the sector we just found is a sector we've already decoded
                # properly, so skip it
                self.g.logger.debug("duplicate sector %d, continuing" % address_field.sector_num)
                continue
            if address_field.sector_num > self.sectors_per_track:
                # found a weird sector whose ID is out of range
                # TODO: will eventually need to tweak this logic to handle Ultima V and others
                self.g.logger.debug("sector ID out of range %d" % address_field.sector_num)
                continue
            # put a placeholder for this sector in this position in the ordered dict
            # so even if this copy doesn't pan out but a later copy does, sectors
            # will still be in the original order
            sectors[address_field.sector_num] = None
            if not self.verify_address_epilogue_at_point(track, track_num, address_field.sector_num):
                # verifying the address field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                self.g.logger.debug("verify_address_epilogue_at_point failed, continuing")
                continue
            if not self.find_data_prologue(track, track_num, address_field.sector_num):
                # if we can't find a data field prologue, just give up
                self.g.logger.debug("find_data_prologue failed, giving up")
                break
            # read and decode the data field, and verify the data checksum
            decoded = self.data_field_at_point(track, track_num, address_field.sector_num)
            if not decoded:
                # decoding data field failed, but this is not necessarily fatal
                # because there might be another copy of this sector later
                self.g.logger.debug("data_field_at_point failed, continuing")
                continue
            if not self.verify_data_epilogue_at_point(track, track_num, address_field.sector_num):
                # verifying the data field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                self.g.logger.debug("verify_data_epilogue_at_point failed")
                continue
            # store end index within track (used for .edd -> .woz conversion)
            end_bit_index = track.bit_index
            # if the caller told us to burn a certain number of sectors before
            # saving the good ones, do it now (used for .edd -> .woz conversion)
            if burn:
                burn -= 1
                continue
            # all good, and we want to save this sector, so do it
            sectors[address_field.sector_num] = Sector(address_field, decoded, start_bit_index, end_bit_index)
            verified_sectors.append(address_field.sector_num)
            self.g.logger.debug("saved sector %s" % hex(address_field.sector_num))
        # remove placeholders of sectors that we found but couldn't decode properly
        # (made slightly more difficult by the fact that we're trying to remove
        # elements from an OrderedDict while iterating through the OrderedDict,
        # which Python really doesn't want to do)
        while None in sectors.values():
            for k in sectors:
                if not sectors[k]:
                    del sectors[k]
                    break
        return sectors

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

    def verify_address_epilogue_at_point(self, track, track_num, physical_sector_num):
#        return True
        if not self.address_epilogue:
            self.address_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_address_epilogue_at_point(self, track, track_num, physical_sector_num)
        next(track.nibble())
        next(track.nibble())
        return result

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        if not self.data_epilogue:
            self.data_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_data_epilogue_at_point(self, track, track_num, physical_sector_num)
        next(track.nibble())
        next(track.nibble())
        return result

class UniversalRWTSIgnoreEpilogues(UniversalRWTS):
    def verify_address_epilogue_at_point(self, track, track_num, physical_sector_num):
        return True

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        return True

class Track00RWTS(UniversalRWTSIgnoreEpilogues):
    def data_field_at_point(self, track, track_num, physical_sector_num):
        start_index = track.bit_index
        start_revolutions = track.revolutions
        decoded = UniversalRWTS.data_field_at_point(self, track, track_num, physical_sector_num)
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

class DOS33RWTS(RWTS):
    def __init__(self, logical_sectors, g):
        self.g = g
        self.reset(logical_sectors)
        RWTS.__init__(self,
                      g,
                      sectors_per_track=16,
                      address_prologue=self.address_prologue,
                      address_epilogue=self.address_epilogue,
                      data_prologue=self.data_prologue,
                      data_epilogue=self.data_epilogue,
                      nibble_translate_table=self.nibble_translate_table)

    def reset(self, logical_sectors):
        self.address_prologue = (logical_sectors[3][0x55],
                                 logical_sectors[3][0x5F],
                                 logical_sectors[3][0x6A])
        self.address_epilogue = (logical_sectors[3][0x91],
                                 logical_sectors[3][0x9B])
        self.data_prologue = (logical_sectors[2][0xE7],
                              logical_sectors[2][0xF1],
                              logical_sectors[2][0xFC])
        self.data_epilogue = (logical_sectors[3][0x35],
                              logical_sectors[3][0x3F])
        self.nibble_translate_table = {}
        for nibble in range(0x96, 0x100):
            self.nibble_translate_table[nibble] = logical_sectors[4][nibble]

class BorderRWTS(DOS33RWTS):
    # TODO doesn't work yet, not sure why
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.address_prologue = (logical_sectors[9][0x16],
                                 logical_sectors[9][0x1B],
                                 logical_sectors[9][0x20])
        self.address_epilogue = (logical_sectors[9][0x25],
                                 logical_sectors[9][0x2A])
        self.data_prologue = (logical_sectors[8][0xFD],
                              logical_sectors[9][0x02],
                              logical_sectors[9][0x02])
        self.data_epilogue = (logical_sectors[9][0x0C],
                              logical_sectors[9][0x11])

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

    def verify_address_epilogue_at_point(self, track, track_num, physical_sector_num):
        return True

class InfocomRWTS(DOS33RWTS):
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.data_prologue = self.data_prologue[:2]

    def find_data_prologue(self, track, track_num, physical_sector_num):
        if not DOS33RWTS.find_data_prologue(self, track, track_num, physical_sector_num):
            return False
        return next(track.nibble()) >= 0xAD

class OptimumResourceRWTS(DOS33RWTS):
    def data_field_at_point(self, track, track_num, physical_sector_num):
        if (track_num, physical_sector_num) == (0x01, 0x0F):
            # TODO actually decode these
            disk_nibbles = []
            for i in range(343):
                disk_nibbles.append(next(track.nibble()))
            return bytearray(256) # all zeroes for now
        return DOS33RWTS.data_field_at_point(self, track, track_num, physical_sector_num)

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        if (track_num, physical_sector_num) == (0x01, 0x0F):
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, track_num, physical_sector_num)

class HeredityDogRWTS(DOS33RWTS):
    def data_field_at_point(self, track, track_num, physical_sector_num):
        if (track_num, physical_sector_num) == (0x00, 0x0A):
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
        return DOS33RWTS.data_field_at_point(self, track, track_num, physical_sector_num)

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        if (track_num, physical_sector_num) == (0x00, 0x0A):
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, track_num, physical_sector_num)

class BECARWTS(DOS33RWTS):
    def is_protected_sector(self, track_num, physical_sector_num):
        if track_num > 0: return True
        return physical_sector_num not in (0x00, 0x0D, 0x0B, 0x09, 0x07, 0x05, 0x03, 0x01, 0x0E, 0x0C)

    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.data_prologue = self.data_prologue[:2]

    def verify_address_epilogue_at_point(self, track, track_num, physical_sector_num):
        if self.is_protected_sector(track_num, physical_sector_num):
            return DOS33RWTS.verify_address_epilogue_at_point(self, track, track_num, physical_sector_num)
        return True

    def find_data_prologue(self, track, track_num, physical_sector_num):
        if not DOS33RWTS.find_data_prologue(self, track, track_num, physical_sector_num):
            return False
        next(track.nibble())
        if self.is_protected_sector(track_num, physical_sector_num):
            next(track.bit())
            next(track.nibble())
            next(track.bit())
            next(track.bit())
        return True

    def verify_data_epilogue_at_point(self, track, track_num, physical_sector_num):
        if self.is_protected_sector(track_num, physical_sector_num):
            next(track.nibble())
        if track_num == 0:
            next(track.nibble())
            next(track.nibble())
            return True
        return DOS33RWTS.verify_data_epilogue_at_point(self, track, track_num, physical_sector_num)

class LaureateRWTS(DOS33RWTS):
    # nibble table is in T00,S06
    # address prologue is T00,S05 A$55,A$5F,A$6A
    # address epilogue is T00,S05 A$91,A$9B
    # data prologue is T00,S04 A$E7,A$F1,A$FC
    # data epilogue is T00,S05 A$35,A$3F
    def reset(self, logical_sectors):
        self.address_prologue = (logical_sectors[5][0x55],
                                 logical_sectors[5][0x5F],
                                 logical_sectors[5][0x6A])
        self.address_epilogue = (logical_sectors[5][0x91],
                                 logical_sectors[5][0x9B])
        self.data_prologue = (logical_sectors[4][0xE7],
                              logical_sectors[4][0xF1],
                              logical_sectors[4][0xFC])
        self.data_epilogue = (logical_sectors[5][0x35],
                              logical_sectors[5][0x3F])
        self.nibble_translate_table = {}
        for nibble in range(0x96, 0x100):
            self.nibble_translate_table[nibble] = logical_sectors[6][nibble]

class MECCRWTS(DOS33RWTS):
    # MECC fastloaders
    def __init__(self, mecc_variant, logical_sectors, g):
        g.mecc_variant = mecc_variant
        DOS33RWTS.__init__(self, logical_sectors, g)

    def reset(self, logical_sectors):
        self.nibble_translate_table = self.kDefaultNibbleTranslationTable16
        self.address_epilogue = (0xDE, 0xAA)
        self.data_epilogue = (0xDE, 0xAA)
        if self.g.mecc_variant == 1:
            self.address_prologue = (logical_sectors[0x0B][0x08],
                                     logical_sectors[0x0B][0x12],
                                     logical_sectors[0x0B][0x1D])
            self.data_prologue = (logical_sectors[0x0B][0x8F],
                                  logical_sectors[0x0B][0x99],
                                  logical_sectors[0x0B][0xA3])
        elif self.g.mecc_variant == 2:
            self.address_prologue = (logical_sectors[7][0x83],
                                     logical_sectors[7][0x8D],
                                     logical_sectors[7][0x98])
            self.data_prologue = (logical_sectors[7][0x15],
                                  logical_sectors[7][0x1F],
                                  logical_sectors[7][0x2A])
        elif self.g.mecc_variant == 3:
            self.address_prologue = (logical_sectors[0x0A][0xE8],
                                     logical_sectors[0x0A][0xF2],
                                     logical_sectors[0x0A][0xFD])
            self.data_prologue = (logical_sectors[0x0B][0x6F],
                                  logical_sectors[0x0B][0x79],
                                  logical_sectors[0x0B][0x83])
        elif self.g.mecc_variant == 4:
            self.address_prologue = (logical_sectors[8][0x83],
                                     logical_sectors[8][0x8D],
                                     logical_sectors[8][0x98])
            self.data_prologue = (logical_sectors[8][0x15],
                                  logical_sectors[8][0x1F],
                                  logical_sectors[8][0x2A])

class BasePassportProcessor: # base class
    def __init__(self, disk_image, logger_class=DefaultLogger):
        self.g = PassportGlobals()
        self.g.disk_image = disk_image
        self.g.logger = logger_class(self.g)
        self.rwts = None
        self.output_tracks = {}
        self.patchers = []
        self.patches_found = []
        self.patch_count = 0 # number of patches found across all tracks
        self.patcher_classes = [
            #SunburstPatcher,
            #JMPBCF0Patcher,
            #JMPBEB1Patcher,
            #JMPBECAPatcher,
            #JMPB660Patcher,
            #JMPB720Patcher,
            bademu.BadEmuPatcher,
            bademu2.BadEmu2Patcher,
            rwts.RWTSPatcher,
            #RWTSLogPatcher,
            mecc1.MECC1Patcher,
            mecc2.MECC2Patcher,
            mecc3.MECC3Patcher,
            mecc4.MECC4Patcher,
            #ROL1EPatcher,
            #JSRBB03Patcher,
            #DavidBB03Patcher,
            #RWTSSwapPatcher,
            #RWTSSwap2Patcher,
            border.BorderPatcher,
            #JMPAE8EPatcher,
            #JMPBBFEPatcher,
            #DatasoftPatcher,
            #NibTablePatcher,
            #DiskVolPatcher,
            #C9FFPatcher,
            #MillikenPatcher,
            #MethodsPatcher,
            #JSR8B3Patcher,
            #LaureatePatcher,
            #PascalRWTSPatcher,
            #MicrogramsPatcher,
            #DOS32Patcher,
            #DOS32DLMPatcher,
            microfun.MicrofunPatcher,
            #T11DiskVolPatcher,
            #T02VolumeNamePatcher,
            universale7.UniversalE7Patcher,
            a6bc95.A6BC95Patcher,
            a5count.A5CountPatcher,
            d5d5f7.D5D5F7Patcher,
            #ProDOSRWTSPatcher,
            #ProDOS6APatcher,
            #ProDOSMECCPatcher,
            bbf9.BBF9Patcher,
            #MemoryConfigPatcher,
            #OriginPatcher,
            #RWTSSwapMECCPatcher,
            #ProtectedDOSPatcher,
            #FBFFPatcher,
            #FBFFEncryptedPatcher,
            #PolarwarePatcher,
            #SierraPatcher,
            #CorrupterPatcher,
            #EAPatcher,
            #GamcoPatcher,
            #OptimumPatcher,
            bootcounter.BootCounterPatcher,
            #JMPB412Patcher,
            #JMPB400Patcher,
            advint.AdventureInternationalPatcher,
            #JSR8635Patcher,
            #JMPB4BBPatcher,
            #DOS32MUSEPatcher,
            #SRAPatcher,
            #Sierra13Patcher,
            #SSPROTPatcher,
            #F7F6Patcher,
            #TrilliumPatcher,
            ]
        self.burn = 0
        if self.preprocess():
            if self.run():
                self.postprocess()

    def SkipTrack(self, track_num, track):
        # don't look for whole-track protections on track 0, that's silly
        if track_num == 0: return False
        # Electronic Arts protection track?
        if track_num == 6:
            if self.rwts.find_address_prologue(track):
                address_field = self.rwts.address_field_at_point(track)
                if address_field and address_field.track_num == 5: return True
        # Nibble count track?
        repeated_nibble_count = 0
        start_revolutions = track.revolutions
        last_nibble = 0x00
        while (repeated_nibble_count < 512 and track.revolutions < start_revolutions + 2):
            n = next(track.nibble())
            if n == last_nibble:
                repeated_nibble_count += 1
            else:
                repeated_nibble_count = 0
            last_nibble = n
        if repeated_nibble_count == 512:
            self.g.logger.PrintByID("sync")
            return True
        # TODO IsUnformatted and other tests
        return False

    def IDDiversi(self, t00s00):
        """returns True if T00S00 is Diversi-DOS bootloader, or False otherwise"""
        return find.at(0xF1, t00s00,
                       b'\xB3\xA3\xA0\xD2\xCF\xD2\xD2\xC5'
                       b'\x8D\x87\x8D')

    def IDProDOS(self, t00s00):
        """returns True if T00S00 is ProDOS bootloader, or False otherwise"""
        return find.at(0x00, t00s00,
                       b'\x01'
                       b'\x38'
                       b'\xB0\x03'
                       b'\x4C')

    def IDPascal(self, t00s00):
        """returns True if T00S00 is Pascal bootloader, or False otherwise"""
        if find.wild_at(0x00, t00s00,
                        b'\x01'
                        b'\xE0\x60'
                        b'\xF0\x03'
                        b'\x4C' + find.WILDCARD + b'\x08'):
            return True
        return find.at(0x00, t00s00,
                       b'\x01'
                       b'\xE0\x70'
                       b'\xB0\x04'
                       b'\xE0\x40'
                       b'\xB0')

    def IDDavidDOS(self, t00s00):
        """returns True if T00S00 is David-DOS II bootloader, or False otherwise"""
        if not find.at(0x01, t00s00,
                       b'\xA5\x27'
                       b'\xC9\x09'
                       b'\xD0\x17'):
            return False
        return find.wild_at(0x4A, t00s00,
                            b'\xA2' + find.WILDCARD + \
                            b'\xBD' + find.WILDCARD + b'\x08' + \
                            b'\x9D' + find.WILDCARD + b'\x04' + \
                            b'\xCA'
                            b'\x10\xF7')

    def IDDatasoft(self, t00s00):
        """returns True if T00S00 is encrypted Datasoft bootloader, or False otherwise"""
        return find.at(0x00, t00s00,
                       b'\x01\x4C\x7E\x08\x04\x8A\x0C\xB8'
                       b'\x00\x56\x10\x7A\x00\x00\x1A\x16'
                       b'\x12\x0E\x0A\x06\x53\x18\x9A\x02'
                       b'\x10\x1B\x02\x10\x4D\x56\x15\x0B'
                       b'\xBF\x14\x14\x54\x54\x54\x92\x81'
                       b'\x1B\x10\x10\x41\x06\x73\x0A\x10'
                       b'\x33\x4E\x00\x73\x12\x10\x33\x7C'
                       b'\x00\x11\x20\xE3\x49\x50\x73\x1A'
                       b'\x10\x41\x00\x23\x80\x5B\x0A\x10'
                       b'\x0B\x4E\x9D\x0A\x10\x9D\x0C\x10'
                       b'\x60\x1E\x53\x10\x90\x53\xBC\x90'
                       b'\x53\x00\x90\xD8\x52\x00\xD8\x7C'
                       b'\x00\x53\x80\x0B\x06\x41\x00\x09'
                       b'\x04\x45\x0C\x63\x04\x90\x94\xD0'
                       b'\xD4\x23\x04\x91\xA1\xEB\xCD\x06'
                       b'\x95\xA1\xE1\x98\x97\x86')

    def IDMicrograms(self, t00s00):
        """returns True if T00S00 is Micrograms bootloader, or False otherwise"""
        if not find.at(0x01, t00s00,
                       b'\xA5\x27'
                       b'\xC9\x09'
                       b'\xD0\x12'
                       b'\xA9\xC6'
                       b'\x85\x3F'):
            return False
        return find.at(0x42, t00s00, b'\x4C\x00')

    def IDQuickDOS(self, t00s00):
        """returns True if T00S00 is Quick-DOS bootloader, or False otherwise"""
        return find.at(0x01, t00s00,
                       b'\xA5\x27'
                       b'\xC9\x09'
                       b'\xD0\x27'
                       b'\x78'
                       b'\xAD\x83\xC0')

    def IDRDOS(self, t00s00):
        """returns True if T00S00 is Quick-DOS bootloader, or False otherwise"""
        return find.at(0x00, t00s00,
                       b'\x01'
                       b'\xA9\x60'
                       b'\x8D\x01\x08'
                       b'\xA2\x00'
                       b'\xA0\x1F'
                       b'\xB9\x00\x08'
                       b'\x49')

    def IDDOS33(self, t00s00):
        """returns True if T00S00 is DOS bootloader or some variation
        that can be safely boot traced, or False otherwise"""
        # Code at $0801 must be standard (with one exception)
        if not find.wild_at(0x00, t00s00,
                            b'\x01'
                            b'\xA5\x27'
                            b'\xC9\x09'
                            b'\xD0\x18'
                            b'\xA5\x2B'
                            b'\x4A'
                            b'\x4A'
                            b'\x4A'
                            b'\x4A'
                            b'\x09\xC0'
                            b'\x85\x3F'
                            b'\xA9\x5C'
                            b'\x85\x3E'
                            b'\x18'
                            b'\xAD\xFE\x08'
                            b'\x6D\xFF\x08' + \
                            find.WILDCARD + find.WILDCARD + find.WILDCARD + \
                            b'\xAE\xFF\x08'
                            b'\x30\x15'
                            b'\xBD\x4D\x08'
                            b'\x85\x3D'
                            b'\xCE\xFF\x08'
                            b'\xAD\xFE\x08'
                            b'\x85\x27'
                            b'\xCE\xFE\x08'
                            b'\xA6\x2B'
                            b'\x6C\x3E\x00'
                            b'\xEE\xFE\x08'
                            b'\xEE\xFE\x08'): return False
        # DOS 3.3 has JSR $FE89 / JSR $FE93 / JSR $FB2F
        # some Sierra have STA $C050 / STA $C057 / STA $C055 instead
        # with the unpleasant side-effect of showing text-mode garbage
        # if mixed-mode was enabled at the time
        if not find.at(0x3F, t00s00,
                       b'\x20\x89\xFE'
                       b'\x20\x93\xFE'
                       b'\x20\x2F\xFB'
                       b'\xA6\x2B'):
            if not find.at(0x3F, t00s00,
                           b'\x8D\x50\xC0'
                           b'\x8D\x57\xC0'
                           b'\x8D\x55\xC0'
                           b'\xA6\x2B'): return False
        # Sector order map must be standard (no exceptions)
        if not find.at(0x4D, t00s00,
                       b'\x00\x0D\x0B\x09\x07\x05\x03\x01'
                       b'\x0E\x0C\x0A\x08\x06\x04\x02\x0F'): return False
        # standard code at $081C -> success & done
        if find.at(0x1C, t00s00,
                   b'\x8D\xFE\x08'): return True

        # Minor variant (e.g. Terrapin Logo 3.0) jumps to $08F0 and back
        # but is still safe to trace. Check for this jump and match
        # the code at $08F0 exactly.
        # unknown code at $081C -> failure
        if not find.at(0x1C, t00s00,
                       b'\x4C\xF0\x08'): return False
        # unknown code at $08F0 -> failure, otherwise success & done
        return find.at(0xF0, t00s00,
                       b'\x8D\xFE\x08'
                       b'\xEE\xF3\x03'
                       b'\x4C\x1F\x08')

    def IDPronto(self, t00s00):
        """returns True if T00S00 is Pronto-DOS bootloader, or False otherwise"""
        return find.at(0x5E, t00s00,
                       b'\xB0\x50'
                       b'\xAD\xCB\xB5'
                       b'\x85\x42')

    def IDLaureate(self, t00s00):
        """returns True if T00S00 is Laureate bootloader, or False otherwise"""
        if not find.at(0x2E, t00s00,
                       b'\xAE\xFF\x08'
                       b'\x30\x1E'
                       b'\xE0\x02'
                       b'\xD0\x05'
                       b'\xA9\xBF'
                       b'\x8D\xFE\x08'): return False
        return find.at(0xF8, t00s00,
                       b'\x4C\x00\xB7'
                       b'\x00\x00\x00\xFF\x0B')

    def IDMECC(self, t00s00):
        """returns True if T00S00 is MECC bootloader, or False otherwise"""
        return find.at(0x00, t00s00,
                       b'\x01'
                       b'\x4C\x1A\x08'
                       b'\x17\x0F\x00'
                       b'\x00\x0D\x0B\x09\x07\x05\x03\x01'
                       b'\x0E\x0C\x0A\x08\x06\x04\x02\x0F')

    def IDMECCVariant(self, logical_sectors):
        """returns int (1-4) of MECC bootloader variant, or 0 if no known variant is detected"""
        # variant 1 (labeled "M8" on original disks)
        if find.wild_at(0x02, logical_sectors[0x0B],
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9' + find.WILDCARD + \
                        b'\xD0\xEF'
                        b'\xEA'
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9' + find.WILDCARD + \
                        b'\xD0\xE5'
                        b'\xA0\x03'
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9'):
            if find.wild_at(0x89, logical_sectors[0x0B],
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9' + find.WILDCARD + \
                            b'\xD0\xF4'
                            b'\xEA'
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9' + find.WILDCARD + \
                            b'\xD0\xF2'
                            b'\xEA'
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9'):
                return 1
        # variant 2 (labeled "M7" on original disks)
        m7a = b'\xBD\x8C\xC0' \
              b'\x10\xFB' \
              b'\xC9' + find.WILDCARD + \
            b'\xD0\xF0' \
            b'\xEA' \
            b'\xBD\x8C\xC0' \
            b'\x10\xFB' \
            b'\xC9' + find.WILDCARD + \
            b'\xD0\xF2' \
            b'\xA0\x03' \
            b'\xBD\x8C\xC0' \
            b'\x10\xFB' \
            b'\xC9'
        m7b = b'\xBD\x8C\xC0' \
              b'\x10\xFB' \
              b'\x49'
        m7c = b'\xEA' \
              b'\xBD\x8C\xC0' \
              b'\x10\xFB' \
              b'\xC9' + find.WILDCARD + \
              b'\xD0\xF2' \
              b'\xA0\x56' \
              b'\xBD\x8C\xC0' \
              b'\x10\xFB' \
              b'\xC9'
        if find.wild_at(0x7D, logical_sectors[7], m7a):
            if find.at(0x0F, logical_sectors[7], m7b):
                if find.wild_at(0x18, logical_sectors[7], m7c):
                    return 2
        # variant 3 ("M7" variant found in Word Muncher 1.1 and others)
        if find.wild_at(0xE2, logical_sectors[0x0A],
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9' + find.WILDCARD + \
                        b'\xD0\xEF'
                        b'\xEA'
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9' + find.WILDCARD + \
                        b'\xD0\xF2'
                        b'\xA0\x03'
                        b'\xBD\x8C\xC0'
                        b'\x10\xFB'
                        b'\xC9'):
            if find.wild_at(0x69, logical_sectors[0x0B],
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9' + find.WILDCARD + \
                            b'\xD0\xF4'
                            b'\xEA'
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9' + find.WILDCARD + \
                            b'\xD0\xF2'
                            b'\xEA'
                            b'\xBD\x8C\xC0'
                            b'\x10\xFB'
                            b'\xC9'):
                return 3
        # variant 4 (same as variant 2 but everything is on sector 8 instead of 7)
        if find.wild_at(0x7D, logical_sectors[8], m7a):
            if find.at(0x0F, logical_sectors[8], m7b):
                if find.wild_at(0x18, logical_sectors[8], m7c):
                    return 2
        return 0 # unknown variant

    def IDBootloader(self, t00):
        """returns RWTS object that can (hopefully) read the rest of the disk"""
        temporary_rwts_for_t00 = Track00RWTS(self.g)
        physical_sectors = temporary_rwts_for_t00.decode_track(t00, 0)
        if 0 not in physical_sectors:
            self.g.logger.PrintByID("fatal0000")
            return None
        t00s00 = physical_sectors[0].decoded
        logical_sectors = temporary_rwts_for_t00.reorder_to_logical_sectors(physical_sectors)

        if self.IDDOS33(t00s00):
            self.g.is_boot0 = True
            if self.IDDiversi(t00s00):
                self.g.logger.PrintByID("diversidos")
            elif self.IDPronto(t00s00):
                self.g.logger.PrintByID("prontodos")
            else:
                self.g.logger.PrintByID("dos33boot0")
            if border.BorderPatcher(self.g).run(logical_sectors, 0):
                return BorderRWTS(logical_sectors, self.g)
            return self.TraceDOS33(logical_sectors)
        # TODO JSR08B3
        if self.IDMECC(t00s00):
            self.g.is_mecc_fastloader = True
            self.g.logger.PrintByID("mecc")
            mecc_variant = self.IDMECCVariant(logical_sectors)
            self.g.logger.debug("mecc_variant = %d" % mecc_variant)
            if mecc_variant:
                return MECCRWTS(mecc_variant, logical_sectors, self.g)
        # TODO MECC fastloader
        # TODO DOS 3.3P
        if self.IDLaureate(t00s00):
            self.g.logger.PrintByID("laureate")
            return LaureateRWTS(logical_sectors, self.g)
        # TODO Electronic Arts
        # TODO DOS 3.2
        # TODO IDEncoded44
        # TODO IDEncoded53
        self.g.is_prodos = self.IDProDOS(t00s00)
        if self.g.is_prodos:
            # TODO IDVolumeName
            # TODO IDDinkeyDOS
            pass
        self.g.is_pascal = self.IDPascal(t00s00)
        self.g.is_daviddos = self.IDDavidDOS(t00s00)
        self.g.is_datasoft = self.IDDatasoft(t00s00)
        self.g.is_micrograms = self.IDMicrograms(t00s00)
        self.g.is_quickdos = self.IDQuickDOS(t00s00)
        self.g.is_rdos = self.IDRDOS(t00s00)
        return self.StartWithUniv()

    def TraceDOS33(self, logical_sectors):
        """returns RWTS object"""

        use_builtin = False
        # check that all the sectors of the RWTS were actually readable
        for i in range(1, 10):
            if i not in logical_sectors:
                use_builtin = True
                break
        # TODO handle Protected.DOS here
        if not use_builtin:
            # check for "STY $48;STA $49" at RWTS entry point ($BD00)
            use_builtin = not find.at(0x00, logical_sectors[7], b'\x84\x48\x85\x49')
        if not use_builtin:
            # check for "SEC;RTS" at $B942
            use_builtin = not find.at(0x42, logical_sectors[3], b'\x38\x60')
        if not use_builtin:
            # check for "LDA $C08C,X" at $B94F
            use_builtin = not find.at(0x4F, logical_sectors[3], b'\xBD\x8C\xC0')
        if not use_builtin:
            # check for "JSR $xx00" at $BDB9
            use_builtin = not find.at(0xB9, logical_sectors[7], b'\x20\x00')
        if not use_builtin:
            # check for RWTS variant that has extra code before
            # JSR $B800 e.g. Verb Viper (DLM), Advanced Analogies (Hartley)
            use_builtin = find.at(0xC5, logical_sectors[7], b'\x20\x00')
        if not use_builtin:
            # check for RWTS variant that uses non-standard address for slot
            # LDX $1FE8 e.g. Pinball Construction Set (1983)
            use_builtin = find.at(0x43, logical_sectors[8], b'\xAE\xE8\x1F')
        if not use_builtin:
            # check for D5+timingbit RWTS
            if find.at(0x59, logical_sectors[3], b'\xBD\x8C\xC0\xC9\xD5'):
                self.g.logger.PrintByID("diskrwts")
                return D5TimingBitRWTS(logical_sectors, self.g)

        # TODO handle Milliken here
        # TODO handle Adventure International here

        if not use_builtin and (logical_sectors[0][0xFE] == 0x22):
            return InfocomRWTS(logical_sectors, self.g)

        if not use_builtin and (find.at(0xF4, logical_sectors[2],
                                        b'\x4C\xCA') or
                                find.at(0xFE, logical_sectors[2],
                                        b'\x4C\xCA')):
            self.g.logger.PrintByID("jmpbeca")
            return BECARWTS(logical_sectors, self.g)

        if not use_builtin and (find.wild_at(0x5D, logical_sectors[0],
                                             b'\x68'
                                             b'\x85' + find.WILDCARD + \
                                             b'\x68' + \
                                             b'\x85' + find.WILDCARD + \
                                             b'\xA0\x01' + \
                                             b'\xB1' + find.WILDCARD + \
                                             b'\x85\x54')):
            self.g.logger.PrintByID("optimum")
            return OptimumResourceRWTS(logical_sectors, self.g)

        if not use_builtin and (find.wild_at(0x16, logical_sectors[5],
                                             b'\xF0\x05'
                                             b'\xA2\xB2'
                                             b'\x4C\xF0\xBB'
                                             b'\xBD\x8C\xC0'
                                             b'\xA9' + find.WILDCARD + \
                                             b'\x8D\x00\x02'
                                             b'\xBD\x8C\xC0'
                                             b'\x10\xFB'
                                             b'\xC9\xEB'
                                             b'\xD0\xF7'
                                             b'\xBD\x8C\xC0'
                                             b'\x10\xFB'
                                             b'\xC9\xD5'
                                             b'\xD0\xEE'
                                             b'\xBD\x8C\xC0'
                                             b'\x10\xFB'
                                             b'\xC9\xAA'
                                             b'\xD0\xE5'
                                             b'\xA9\x4C'
                                             b'\xA0\x00'
                                             b'\x99\x00\x95'
                                             b'\x88'
                                             b'\xD0\xFA'
                                             b'\xCE\x46\xBB'
                                             b'\xAD\x46\xBB'
                                             b'\xC9\x07'
                                             b'\xD0\xEC'
                                             b'\xA9\x18'
                                             b'\x8D\x42\xB9'
                                             b'\xA9\x0A'
                                             b'\x8D\xED\xB7'
                                             b'\xD0\x05')):
            self.g.logger.PrintByID("bb00")
            if find.at(0x04, logical_sectors[5],
                       b'\xBD\x8D\xC0'
                       b'\xBD\x8E\xC0'
                       b'\x30\x05'
                       b'\xA2\xB1'
                       b'\x4C\xF0\xBB'):
                self.g.protection_enforces_write_protected = True
            return HeredityDogRWTS(logical_sectors, self.g)

        if use_builtin:
            return self.StartWithUniv()

        self.g.logger.PrintByID("diskrwts")
        return DOS33RWTS(logical_sectors, self.g)

    def StartWithUniv(self):
        """return Universal RWTS object, log that we're using it, and set global flags appropriately"""
        self.g.logger.PrintByID("builtin")
        self.g.tried_univ = True
        self.g.is_protdos = False
        return UniversalRWTS(self.g)

    def preprocess(self):
        return True

    def run(self):
        self.g.logger.PrintByID("header")
        self.g.logger.PrintByID("reading", {"filename":self.g.disk_image.filename})

        # get all raw track data from the source disk
        self.tracks = {}
        for track_num in range(0x23):
            self.tracks[float(track_num)] = self.g.disk_image.seek(float(track_num))

        # analyze track $00 to create an RWTS
        self.rwts = self.IDBootloader(self.tracks[0])
        if not self.rwts: return False

        # initialize all patchers
        for P in self.patcher_classes:
            self.patchers.append(P(self.g))

        # main loop - loop through disk from track $22 down to track $00
        for track_num in range(0x22, -1, -1):
            self.g.track = track_num
            self.rwts.seek(track_num)
            self.g.logger.debug("Seeking to track %s" % hex(self.g.track))
            try_again = True
            while try_again:
                try_again = False
                physical_sectors = self.rwts.decode_track(self.tracks[track_num], track_num, self.burn)
                if len(physical_sectors) == self.rwts.sectors_per_track:
                    continue
                else:
                    self.g.logger.debug("found %d sectors" % len(physical_sectors))
                if (0x0F not in physical_sectors) and self.SkipTrack(track_num, self.tracks[track_num]):
                    physical_sectors = None
                    continue
                # TODO wrong in case where we switch mid-track.
                # Need to save the sectors that worked with the original RWTS
                # then append the ones that worked with the universal RWTS
                if not self.g.tried_univ:
                    self.g.logger.PrintByID("switch", {"sector":0x0F}) # TODO find exact sector
                    self.rwts = UniversalRWTS(self.g)
                    self.g.tried_univ = True
                    try_again = True
                    continue
                if track_num == 0 and type(self.rwts) != UniversalRWTSIgnoreEpilogues:
                    self.rwts = UniversalRWTSIgnoreEpilogues(self.g)
                    try_again = True
                    continue
                self.g.logger.PrintByID("fail")
                return False
            self.save_track(track_num, physical_sectors)
        return True

    def save_track(self, track_num, physical_sectors):
        pass

    def apply_patches(self, logical_sectors, patches):
        pass

class Verify(BasePassportProcessor):
    def AnalyzeT00(self, logical_sectors):
        self.g.is_boot1 = find.at(0x00, logical_sectors[1],
            b'\x8E\xE9\xB7\x8E\xF7\xB7\xA9\x01'
            b'\x8D\xF8\xB7\x8D\xEA\xB7\xAD\xE0'
            b'\xB7\x8D\xE1\xB7\xA9\x02\x8D\xEC'
            b'\xB7\xA9\x04\x8D\xED\xB7\xAC\xE7'
            b'\xB7\x88\x8C\xF1\xB7\xA9\x01\x8D'
            b'\xF4\xB7\x8A\x4A\x4A\x4A\x4A\xAA'
            b'\xA9\x00\x9D\xF8\x04\x9D\x78\x04')
        self.g.is_master = find.at(0x00, logical_sectors[1],
            b'\x8E\xE9\x37\x8E\xF7\x37\xA9\x01'
            b'\x8D\xF8\x37\x8D\xEA\x37\xAD\xE0'
            b'\x37\x8D\xE1\x37\xA9\x02\x8D\xEC'
            b'\x37\xA9\x04\x8D\xED\x37\xAC\xE7'
            b'\x37\x88\x8C\xF1\x37\xA9\x01\x8D'
            b'\xF4\x37\x8A\x4A\x4A\x4A\x4A\xAA'
            b'\xA9\x00\x9D\xF8\x04\x9D\x78\x04')
        self.g.is_rwts = find.wild_at(0x00, logical_sectors[7],
            b'\x84\x48\x85\x49\xA0\x02\x8C' + find.WILDCARD + \
            find.WILDCARD + b'\xA0\x04\x8C' + find.WILDCARD + find.WILDCARD + b'\xA0\x01' + \
            b'\xB1\x48\xAA\xA0\x0F\xD1\x48\xF0'
            b'\x1B\x8A\x48\xB1\x48\xAA\x68\x48'
            b'\x91\x48\xBD\x8E\xC0\xA0\x08\xBD'
            b'\x8C\xC0\xDD\x8C\xC0\xD0\xF6\x88'
            b'\xD0\xF8\x68\xAA\xBD\x8E\xC0\xBD'
            b'\x8C\xC0\xA0\x08\xBD\x8C\xC0\x48')
    
    def save_track(self, track_num, physical_sectors):
        if not physical_sectors: return {}
        logical_sectors = self.rwts.reorder_to_logical_sectors(physical_sectors)
        should_run_patchers = (len(physical_sectors) == 16) # TODO
        if should_run_patchers:
            if track_num == 0:
                # set additional globals for patchers to use
                self.AnalyzeT00(logical_sectors)
            for patcher in self.patchers:
                if patcher.should_run(track_num):
                    patches = patcher.run(logical_sectors, track_num)
                    if patches:
                        self.apply_patches(logical_sectors, patches)
                        self.patches_found.extend(patches)
        return logical_sectors

    def apply_patches(self, logical_sectors, patches):
        for patch in patches:
            if patch.id:
                self.g.logger.PrintByID(patch.id, patch.params)

    def postprocess(self):
        self.g.logger.PrintByID("passver")

class Crack(Verify):
    def save_track(self, track_num, physical_sectors):
        self.output_tracks[float(track_num)] = Verify.save_track(self, track_num, physical_sectors)

    def apply_patches(self, logical_sectors, patches):
        for patch in patches:
            if patch.id:
                self.g.logger.PrintByID(patch.id, patch.params)
            if len(patch.new_value) > 0:
                b = logical_sectors[patch.sector_num].decoded
                patch.params["old_value"] = b[patch.byte_offset:patch.byte_offset+len(patch.new_value)]
                patch.params["new_value"] = patch.new_value
                self.g.logger.PrintByID("modify", patch.params)
                for i in range(len(patch.new_value)):
                    b[patch.byte_offset + i] = patch.new_value[i]
                logical_sectors[patch.sector_num].decoded = b

    def postprocess(self):
        source_base, source_ext = os.path.splitext(self.g.disk_image.filename)
        output_filename = source_base + '.dsk'
        self.g.logger.PrintByID("writing", {"filename":output_filename})
        with open(output_filename, "wb") as f:
            for track_num in range(0x23):
                if track_num in self.output_tracks:
                    f.write(concat_track(self.output_tracks[track_num]))
                else:
                    f.write(bytes(256*16))
        if self.patches_found:
            self.g.logger.PrintByID("passcrack")
        else:
            self.g.logger.PrintByID("passcrack0")

class EDDToWoz(BasePassportProcessor):
    def preprocess(self):
        self.burn = 2
        return True

    def save_track(self, track_num, physical_sectors):
        track_num = float(track_num)
        track = self.tracks[track_num]
        if physical_sectors:
            b = bitarray.bitarray(endian="big")
            for s in physical_sectors.values():
                b.extend(track.bits[s.start_bit_index:s.end_bit_index])
        else:
            # TODO this only works about half the time
            b = track.bits[:51021]
        self.output_tracks[track_num] = wozimage.Track(b, len(b))

    def postprocess(self):
        source_base, source_ext = os.path.splitext(self.g.disk_image.filename)
        output_filename = source_base + '.woz'
        self.g.logger.PrintByID("writing", {"filename":output_filename})
        woz_image = wozimage.WozWriter(STRINGS["header"].strip())
        woz_image.info["cleaned"] = self.g.found_and_cleaned_weakbits
        woz_image.info["write_protected"] = self.g.protection_enforces_write_protected
        woz_image.meta["image_date"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        for q in range(1 + (0x23 * 4)):
            track_num = q / 4
            if track_num in self.output_tracks:
                woz_image.add_track(track_num, self.output_tracks[track_num])
        with open(output_filename, 'wb') as f:
            woz_image.write(f)
        try:
            wozimage.WozReader(output_filename)
        except Exception as e:
            os.remove(output_filename)
            raise Exception from e
