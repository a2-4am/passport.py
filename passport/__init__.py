#!/usr/bin/env python3

from passport import wozimage
from passport.patchers import *
from passport.strings import *
from passport.util import *
import bitarray
import collections
import os.path
import sys

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
        self.is_mecc1 = False
        self.is_mecc2 = False
        self.is_mecc3 = False
        self.is_mecc4 = False
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
                 sectors_per_track = 16,
                 address_prologue = kDefaultAddressPrologue16,
                 address_epilogue = kDefaultAddressEpilogue16,
                 data_prologue = kDefaultDataPrologue16,
                 data_epilogue = kDefaultDataEpilogue16,
                 sector_order = kDefaultSectorOrder16,
                 nibble_translate_table = kDefaultNibbleTranslationTable16,
                 logger = None):
        self.sectors_per_track = sectors_per_track
        self.address_prologue = address_prologue
        self.address_epilogue = address_epilogue
        self.data_prologue = data_prologue
        self.data_epilogue = data_epilogue
        self.sector_order = sector_order
        self.nibble_translate_table = nibble_translate_table
        self.logger = logger or SilentLogger

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
        
    def verify_address_epilogue_at_point(self, track):
        return self.verify_nibbles_at_point(track, self.address_epilogue)

    def find_data_prologue(self, track):
        return track.find(self.data_prologue)

    def data_field_at_point(self, track):
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

    def verify_data_epilogue_at_point(self, track):
        return self.verify_nibbles_at_point(track, self.data_epilogue)

    def decode_track(self, track, burn=0):
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
                break
            # decode address field
            address_field = self.address_field_at_point(track)
            if address_field.sector_num in verified_sectors:
                # the sector we just found is a sector we've already decoded
                # properly, so skip past it
                self.logger.debug("duplicate sector %d" % address_field.sector_num)
                if self.find_data_prologue(track):
                    if self.data_field_at_point(track):
                        self.verify_data_epilogue_at_point(track)
                continue
            if address_field.sector_num > self.sectors_per_track:
                # found a weird sector whose ID is out of range
                # TODO: will eventually need to tweak this logic to handle Ultima V and others
                self.logger.debug("sector ID out of range %d" % address_field.sector_num)
                continue
            # put a placeholder for this sector in this position in the ordered dict
            # so even if this copy doesn't pan out but a later copy does, sectors
            # will still be in the original order
            sectors[address_field.sector_num] = None
            if not self.verify_address_epilogue_at_point(track):
                # verifying the address field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                continue
            if not self.find_data_prologue(track):
                # if we can't find a data field prologue, just give up
                break
            # read and decode the data field, and verify the data checksum
            decoded = self.data_field_at_point(track)
            if not decoded:
                self.logger.debug("data_field_at_point failed")
#                if DEBUG and address_field.sector_num == 0x0A:
#                    DEBUG_CACHE.append(track.bits[start_bit_index:track.bit_index])
#                    if len(DEBUG_CACHE) == 2:
#                        import code
#                        cache = DEBUG_CACHE
#                        code.interact(local=locals())
                # decoding data field failed, but this is not necessarily fatal
                # because there might be another copy of this sector later
                continue
            if not self.verify_data_epilogue_at_point(track):
                # verifying the data field epilogue failed, but this is
                # not necessarily fatal because there might be another copy
                # of this sector later
                self.logger.debug("verify_data_epilogue_at_point failed")
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

    def __init__(self, logger):
        RWTS.__init__(self, address_epilogue=[], data_epilogue=[], logger=logger)

    def find_address_prologue(self, track):
        starting_revolutions = track.revolutions
        seen = [0,0,0]
        while (track.revolutions < starting_revolutions + 2):
            del seen[0]
            seen.append(next(track.nibble()))
            if tuple(seen) in self.acceptable_address_prologues: return True
        return False

    def verify_address_epilogue_at_point(self, track):
        return True
        if not self.address_epilogue:
            self.address_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_address_epilogue_at_point(self, track)
        next(track.nibble())
        next(track.nibble())
        return result

    def verify_data_epilogue_at_point(self, track):
        if not self.data_epilogue:
            self.data_epilogue = [next(track.nibble())]
            result = True
        else:
            result = RWTS.verify_data_epilogue_at_point(self, track)
        next(track.nibble())
        next(track.nibble())
        return result

class UniversalRWTSIgnoreEpilogues(UniversalRWTS):
    def verify_address_epilogue_at_point(self, track):
        return True
    
    def verify_data_epilogue_at_point(self, track):
        return True

class DOS33RWTS(RWTS):
    def __init__(self, logical_sectors, logger):
        address_prologue = (logical_sectors[3][0x55],
                            logical_sectors[3][0x5F],
                            logical_sectors[3][0x6A])
        address_epilogue = (logical_sectors[3][0x91],
                            logical_sectors[3][0x9B])
        data_prologue = (logical_sectors[2][0xE7],
                         logical_sectors[2][0xF1],
                         logical_sectors[2][0xFC])
        data_epilogue = (logical_sectors[3][0x35],
                         logical_sectors[3][0x3F])
        nibble_translate_table = {}
        for nibble in range(0x96, 0x100):
            nibble_translate_table[nibble] = logical_sectors[4][nibble]
        RWTS.__init__(self,
                      sectors_per_track=16,
                      address_prologue=address_prologue,
                      address_epilogue=address_epilogue,
                      data_prologue=data_prologue,
                      data_epilogue=data_epilogue,
                      nibble_translate_table=nibble_translate_table,
                      logger=logger)

class BasePassportProcessor: # base class
    def __init__(self, disk_image, logger_class=DefaultLogger):
        self.g = PassportGlobals()
        self.g.disk_image = disk_image
        self.logger = logger_class(self.g)
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
            #BadEmuPatcher,
            #BadEmu2Patcher,
            rwts.RWTSPatcher,
            #RWTSLogPatcher,
            #MECC1Patcher,
            #MECC2Patcher,
            #MECC3Patcher,
            #MECC4Patcher,
            #ROL1EPatcher,
            #JSRBB03Patcher,
            #DavidBB03Patcher,
            #RWTSSwapPatcher,
            #RWTSSwap2Patcher,
            #BorderPatcher,
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
            #A6BC95Patcher,
            #A5CountPatcher,
            d5d5f7.D5D5F7Patcher,
            #ProDOSRWTSPatcher,
            #ProDOS6APatcher,
            #ProDOSMECCPatcher,
            #BBF9Patcher,
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
            #BootCounterPatcher,
            #JMPB412Patcher,
            #JMPB400Patcher,
            #AdvIntPatcher,
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

    def SkipTrack(self, rwts, track_num, track):
        # don't look for whole-track protections on track 0, that's silly
        if track_num == 0: return False
        # Electronic Arts protection track?
        if track_num == 6:
            if rwts.find_address_prologue(track):
                address_field = rwts.address_field_at_point(track)
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
            self.logger.PrintByID("sync")
            return True
        # TODO IsUnformatted and other tests
        return False
    
    def IDDiversi(self, t00s00):
        """returns True if T00S00 is Diversi-DOS bootloader, or False otherwise"""
        return find.at(0xF1, t00s00,
                      b'\xB3\xA3\xA0\xD2\xCF\xD2\xD2\xC5'
                      b'\x8D\x87\x8D')

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

    def IDBootloader(self, t00):
        """returns RWTS object that can (hopefully) read the rest of the disk"""
        rwts = UniversalRWTSIgnoreEpilogues(self.logger)
        physical_sectors = rwts.decode_track(t00)
        if 0 not in physical_sectors:
            self.logger.PrintByID("fatal0000")
            return None
        t00s00 = physical_sectors[0]
    
        if self.IDDOS33(t00s00):
            self.g.is_boot0 = True
            if self.IDDiversi(t00s00):
                self.logger.PrintByID("diversidos")
            elif self.IDPronto(t00s00):
                self.logger.PrintByID("prontodos")
            else:
                self.logger.PrintByID("dos33boot0")
            # TODO handle JSR08B3 here
            rwts = self.TraceDOS33(rwts.reorder_to_logical_sectors(physical_sectors), rwts)
        else:
            self.logger.PrintByID("builtin")
            self.g.tried_univ = True
            rwts = UniversalRWTS(self.logger)
        return rwts

    def TraceDOS33(self, logical_sectors, rwts):
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

        # TODO handle Milliken here
        # TODO handle Adventure International here
        # TODO handle Infocom here
    
        if use_builtin:
            self.logger.PrintByID("builtin")
            return rwts

        self.logger.PrintByID("diskrwts")
        self.g.is_rwts = True
        return DOS33RWTS(logical_sectors, self.logger)

    def preprocess(self):
        return True
    
    def run(self):
        self.logger.PrintByID("header")
        self.logger.PrintByID("reading", {"filename":self.g.disk_image.filename})

        # get all raw track data from the source disk
        self.tracks = {}
        for track_num in range(0x23):
            self.tracks[float(track_num)] = self.g.disk_image.seek(float(track_num))

        # analyze track $00 to create an RWTS
        rwts = self.IDBootloader(self.tracks[0])
        if not rwts: return False

        # initialize all patchers
        for P in self.patcher_classes:
            self.patchers.append(P(self.g))

        # main loop - loop through disk from track $22 down to track $00
        for track_num in range(0x22, -1, -1):
            if track_num == 0 and self.g.tried_univ:
                rwts = UniversalRWTSIgnoreEpilogues(self.logger)
            should_run_patchers = False
            self.g.track = track_num
            physical_sectors = rwts.decode_track(self.tracks[track_num], self.burn)
            if 0x0F not in physical_sectors:
                if self.SkipTrack(rwts, track_num, self.tracks[track_num]):
                    self.save_track(rwts, track_num, None)
                    continue
            if len(physical_sectors) < rwts.sectors_per_track:
                # TODO wrong in case where we switch mid-track.
                # Need to save the sectors that worked with the original RWTS
                # then append the ones that worked with the universal RWTS
                if self.g.tried_univ:
                    self.logger.PrintByID("fail")
                    return False
                self.logger.PrintByID("switch", {"sector":0x0F}) # TODO find exact sector
                rwts = UniversalRWTS(self.logger)
                self.g.tried_univ = True
                physical_sectors = rwts.decode_track(self.tracks[track_num], self.burn)
            if len(physical_sectors) < rwts.sectors_per_track:
                self.logger.PrintByID("fail") # TODO find exact sector
                return False
            self.save_track(rwts, track_num, physical_sectors)
        return True

    def save_track(self, rwts, track_num, physical_sectors):
        pass

    def apply_patches(self, logical_sectors, patches):
        pass

class Verify(BasePassportProcessor):
    def save_track(self, rwts, track_num, physical_sectors):
        if not physical_sectors: return {}
        logical_sectors = rwts.reorder_to_logical_sectors(physical_sectors)
        should_run_patchers = (len(physical_sectors) == 16) # TODO
        if should_run_patchers:
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
                self.logger.PrintByID(patch.id, patch.params)

    def postprocess(self):
        self.logger.PrintByID("passver")

class Crack(Verify):
    def save_track(self, rwts, track_num, physical_sectors):
        self.output_tracks[float(track_num)] = Verify.save_track(self, rwts, track_num, physical_sectors)
        
    def apply_patches(self, logical_sectors, patches):
        for patch in patches:
            if patch.id:
                self.logger.PrintByID(patch.id, patch.params)
            if len(patch.new_value) > 0:
                b = logical_sectors[patch.sector_num].decoded
                patch.params["old_value"] = b[patch.byte_offset:patch.byte_offset+len(patch.new_value)]
                patch.params["new_value"] = patch.new_value
                self.logger.PrintByID("modify", patch.params)
                for i in range(len(patch.new_value)):
                    b[patch.byte_offset + i] = patch.new_value[i]
                logical_sectors[patch.sector_num].decoded = b
    
    def postprocess(self):
        source_base, source_ext = os.path.splitext(self.g.disk_image.filename)
        output_filename = source_base + '.dsk'
        self.logger.PrintByID("writing", {"filename":output_filename})
        with open(output_filename, "wb") as f:
            for track_num in range(0x23):
                if track_num in self.output_tracks:
                    f.write(concat_track(self.output_tracks[track_num]))
                else:
                    f.write(bytes(256*16))
        if self.patches_found:
            self.logger.PrintByID("passcrack")
        else:
            self.logger.PrintByID("passcrack0")

class EDDToWoz(BasePassportProcessor):
    def preprocess(self):
        self.burn = 2
        return True

    def save_track(self, rwts, track_num, physical_sectors):
        track_num = float(track_num)
        track = self.tracks[track_num]
        if physical_sectors:
            b = bitarray.bitarray(endian="big")
            for s in physical_sectors.values():
                b.extend(track.bits[s.start_bit_index:s.end_bit_index])
        else:
            b = track.bits[:51021]
        self.output_tracks[track_num] = wozimage.Track(b, len(b))
    
    def postprocess(self):
        source_base, source_ext = os.path.splitext(self.g.disk_image.filename)
        output_filename = source_base + '.woz'
        self.logger.PrintByID("writing", {"filename":output_filename})
        woz_image = wozimage.WozWriter(STRINGS["header"].strip())
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
