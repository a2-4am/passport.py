from collections import OrderedDict
from passport.util import *

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
        self.logical_track_num = 0

    def seek(self, logical_track_num):
        self.logical_track_num = logical_track_num
        return float(logical_track_num)

    def reorder_to_logical_sectors(self, physical_sectors):
        logical = {}
        for k, v in physical_sectors.items():
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

    def verify_address_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        return self.verify_nibbles_at_point(track, self.address_epilogue)

    def find_data_prologue(self, track, logical_track_num, physical_sector_num):
        return track.find(self.data_prologue)

    def data_field_at_point(self, track, logical_track_num, physical_sector_num):
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

    def verify_data_epilogue_at_point(self, track, logical_track_num, physical_sector_num):
        return self.verify_nibbles_at_point(track, self.data_epilogue)

    def decode_track(self, track, logical_track_num, burn=0):
        sectors = OrderedDict()
        if not track: return sectors
        if not track.bits: return sectors
        starting_revolutions = track.revolutions
        verified_sectors = []
        while (len(verified_sectors) < self.sectors_per_track) and \
              (track.revolutions < starting_revolutions + 2):
            # store start index within track (used for .woz conversion)
            start_bit_index = track.bit_index
            if not self.find_address_prologue(track):
                # if we can't even find a single address prologue, just give up
                self.g.logger.debug("can't find a single address prologue so LGTM or whatever")
                break
            # for .woz conversion, only save some of the bits preceding
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
            if not self.verify_address_epilogue_at_point(track, logical_track_num, address_field.sector_num):
                # verifying the address field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                self.g.logger.debug("verify_address_epilogue_at_point failed, continuing")
                continue
            if not self.find_data_prologue(track, logical_track_num, address_field.sector_num):
                # if we can't find a data field prologue, just give up
                self.g.logger.debug("find_data_prologue failed, giving up")
                break
            # read and decode the data field, and verify the data checksum
            decoded = self.data_field_at_point(track, logical_track_num, address_field.sector_num)
            if not decoded:
                # decoding data field failed, but this is not necessarily fatal
                # because there might be another copy of this sector later
                self.g.logger.debug("data_field_at_point failed, continuing")
                continue
            if not self.verify_data_epilogue_at_point(track, logical_track_num, address_field.sector_num):
                # verifying the data field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                self.g.logger.debug("verify_data_epilogue_at_point failed")
                continue
            # store end index within track (used for .woz conversion)
            end_bit_index = track.bit_index
            # if the caller told us to burn a certain number of sectors before
            # saving the good ones, do it now (used for .woz conversion)
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

from .universal import *
from .dos33 import *
from .sunburst import *
from .border import *
from .d5timing import *
from .infocom import *
from .optimum import *
from .hereditydog import *
from .beca import *
from .laureate import *
from .mecc import *
