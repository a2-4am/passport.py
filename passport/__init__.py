from passport.loggers import *
from passport.rwts import *
from passport.patchers import *
from passport.strings import *
from passport.constants import *
from passport.util import *
from passport import wozardry
import bitarray
import io
import json
import os.path
import time

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
        self.track = 0 # display purposes only
        self.sector = 0 # display purposes only
        self.last_track = 0
        self.filename = None

class BasePassportProcessor: # base class
    def __init__(self, filename, disk_image, logger_class=DefaultLogger):
        self.g = PassportGlobals()
        self.g.filename = filename
        self.g.disk_image = disk_image
        self.g.logger = logger_class(self.g)
        self.rwts = None
        self.output_tracks = {}
        self.patchers = []
        self.patches_found = []
        self.patch_count = 0 # number of patches found across all tracks
        self.patcher_classes = [
            SunburstPatcher,
            #JMPBCF0Patcher,
            #JMPBEB1Patcher,
            #JMPBECAPatcher,
            #JMPB660Patcher,
            #JMPB720Patcher,
            BadEmuPatcher,
            BadEmu2Patcher,
            RWTSPatcher,
            #RWTSLogPatcher,
            MECC1Patcher,
            MECC2Patcher,
            MECC3Patcher,
            MECC4Patcher,
            #ROL1EPatcher,
            #JSRBB03Patcher,
            #DavidBB03Patcher,
            #RWTSSwapPatcher,
            #RWTSSwap2Patcher,
            BorderPatcher,
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
            MicrofunPatcher,
            #T11DiskVolPatcher,
            #T02VolumeNamePatcher,
            UniversalE7Patcher,
            A6BC95Patcher,
            A5CountPatcher,
            D5D5F7Patcher,
            #ProDOSRWTSPatcher,
            #ProDOS6APatcher,
            #ProDOSMECCPatcher,
            BBF9Patcher,
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
            BootCounterPatcher,
            #JMPB412Patcher,
            #JMPB400Patcher,
            AdventureInternationalPatcher,
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

    def SkipTrack(self, logical_track_num, track):
        # don't look for whole-track protections on track 0, that's silly
        if logical_track_num == 0: return False
        # Missing track?
        if not track.bits:
            self.g.logger.PrintByID("unformat")
            return True
        # Electronic Arts protection track?
        if logical_track_num == 6:
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
        # TODO IsUnformatted nibble test and other tests
        # (still need these for disks like Crime Wave and Thunder Bombs)
        return False

    def IDDiversi(self, t00s00):
        """returns True if T00S00 is Diversi-DOS bootloader, or False otherwise"""
        return find.at(0xF1, t00s00, kIDDiversiDOSBootloader)

    def IDProDOS(self, t00s00):
        """returns True if T00S00 is ProDOS bootloader, or False otherwise"""
        return find.at(0x00, t00s00, kIDProDOSBootloader)

    def IDPascal(self, t00s00):
        """returns True if T00S00 is Pascal bootloader, or False otherwise"""
        return find.wild_at(0x00, t00s00, kIDPascalBootloader1) or \
            find.at(0x00, t00s00, kIDPascalBootloader2)

    def IDDavidDOS(self, t00s00):
        """returns True if T00S00 is David-DOS II bootloader, or False otherwise"""
        return find.at(0x01, t00s00, kIDDavidDOS1) and \
            find.wild_at(0x4A, t00s00, kIDDavidDOS2)

    def IDDatasoft(self, t00s00):
        """returns True if T00S00 is encrypted Datasoft bootloader, or False otherwise"""
        return find.at(0x00, t00s00, kIDDatasoft)

    def IDMicrograms(self, t00s00):
        """returns True if T00S00 is Micrograms bootloader, or False otherwise"""
        return find.at(0x01, t00s00, kIDMicrograms1) and \
            find.at(0x42, t00s00, kIDMicrograms2)

    def IDQuickDOS(self, t00s00):
        """returns True if T00S00 is Quick-DOS bootloader, or False otherwise"""
        return find.at(0x01, t00s00, kIDQuickDOS)

    def IDRDOS(self, t00s00):
        """returns True if T00S00 is Quick-DOS bootloader, or False otherwise"""
        return find.at(0x00, t00s00, kIDRDOS)

    def IDDOS33(self, t00s00):
        """returns True if T00S00 is DOS bootloader or some variation
        that can be safely boot traced, or False otherwise"""
        # Code at $0801 must be standard (with one exception)
        if not find.wild_at(0x00, t00s00, kIDDOS33a):
            return False
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

    def IDSunburst(self, logical_sectors):
        """returns True if |logical_sectors| contains track 0 of a Sunburst disk, False otherwise"""
        if 4 not in logical_sectors:
            return False
        return find.wild_at(0x69, logical_sectors[0x04],
                            bytes.fromhex("48"
                                          "A5 2A"
                                          "4A"
                                          "A8"
                                          "B9 29 BA"
                                          "8D 6A B9"
                                          "8D 84 BC"
                                          "B9 34 BA"
                                          "8D FC B8"
                                          "8D 5D B8"
                                          "C0 11"
                                          "D0 03"
                                          "A9 02"
                                          "AC"
                                          "A9 0E"
                                          "8D C0 BF"
                                          "68"
                                          "69 00"
                                          "48"
                                          "AD 78 04"
                                          "90 2B"))

    def IDBootloader(self, t00, suppress_errors=False):
        """returns RWTS object that can (hopefully) read the rest of the disk"""
        temporary_rwts_for_t00 = Track00RWTS(self.g)
        physical_sectors = temporary_rwts_for_t00.decode_track(t00, 0)
        if 0 not in physical_sectors:
            if not suppress_errors:
                self.g.logger.PrintByID("fail")
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
            if self.IDSunburst(logical_sectors):
                self.g.logger.PrintByID("sunburst")
                return SunburstRWTS(logical_sectors, self.g)
            return self.TraceDOS33(logical_sectors)
        # TODO JSR08B3
        if self.IDMECC(t00s00):
            self.g.is_mecc_fastloader = True
            self.g.logger.PrintByID("mecc")
            mecc_variant = self.IDMECCVariant(logical_sectors)
            self.g.logger.debug("mecc_variant = %d" % mecc_variant)
            if mecc_variant:
                return MECCRWTS(mecc_variant, logical_sectors, self.g)
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
        self.g.logger.PrintByID("reading", {"filename":self.g.filename})
        supports_reseek = ("reseek" in dir(self.g.disk_image))

        # get raw track $00 data from the source disk
        self.tracks = {}
        self.tracks[0] = self.g.disk_image.seek(0)
        # analyze track $00 to create an RWTS
        self.rwts = self.IDBootloader(self.tracks[0], supports_reseek)
        if not self.rwts and supports_reseek:
            self.tracks[0] = self.g.disk_image.reseek(0)
            self.rwts = self.IDBootloader(self.tracks[0])
        if not self.rwts: return False

        # initialize all patchers
        for P in self.patcher_classes:
            self.patchers.append(P(self.g))

        # main loop - loop through disk from track $22 down to track $00
        for logical_track_num in range(0x22, -1, -1):
            self.g.track = logical_track_num # for display purposes only
            self.g.logger.debug("Seeking to track %s" % hex(self.g.track))

            # distinguish between logical and physical track numbers to deal with
            # disks like Sunburst that store logical track 0x11+ on physical track 0x11.5+
            physical_track_num = self.rwts.seek(logical_track_num)

            # self.tracks must be indexed by physical track number so we can write out
            # .woz files correctly
            self.tracks[physical_track_num] = self.g.disk_image.seek(physical_track_num)

            tried_reseek = False
            physical_sectors = OrderedDict()
            while True:
                physical_sectors.update(self.rwts.decode_track(self.tracks[physical_track_num], logical_track_num, self.burn))
                if self.rwts.enough(logical_track_num, physical_sectors):
                    break

                if supports_reseek and not tried_reseek:
                    self.tracks[physical_track_num] = self.g.disk_image.reseek(physical_track_num)
                    self.g.logger.debug("Reseeking to track %s" % hex(self.g.track))
                    tried_reseek = True
                    continue

                self.g.logger.debug("found %d sectors" % len(physical_sectors))
                if (0x0F not in physical_sectors) and self.SkipTrack(logical_track_num, self.tracks[physical_track_num]):
                    physical_sectors = None
                    break

                if self.g.tried_univ:
                    if logical_track_num == 0x22 and (0x0F not in physical_sectors):
                        self.g.logger.PrintByID("fail", {"sector":0x0F})
                        self.g.logger.PrintByID("fatal220f")
                        return False
                else:
                    transition_sector = 0x0F
                    if physical_sectors:
                        temp_logical_sectors = self.rwts.reorder_to_logical_sectors(physical_sectors)
                        transition_sector = min(temp_logical_sectors.keys())
                    self.g.logger.PrintByID("switch", {"sector":transition_sector})
                    self.rwts = UniversalRWTS(self.g)
                    self.g.tried_univ = True
                    continue

                if logical_track_num == 0 and type(self.rwts) != UniversalRWTSIgnoreEpilogues:
                    self.rwts = UniversalRWTSIgnoreEpilogues(self.g)
                    continue

                self.g.logger.PrintByID("fail")
                return False
            self.save_track(physical_track_num, logical_track_num, physical_sectors)
        return True

    def save_track(self, physical_track_num, logical_track_num, physical_sectors):
        pass

    def apply_patches(self, logical_sectors, patches):
        pass

class Verify(BasePassportProcessor):
    def AnalyzeT00(self, logical_sectors):
        self.g.is_boot1 = find.at(0x00, logical_sectors[1], kIDBoot1)
        self.g.is_master = find.at(0x00, logical_sectors[1], kIDMaster)
        self.g.is_rwts = find.wild_at(0x00, logical_sectors[7], kIDRWTS)

    def save_track(self, physical_track_num, logical_track_num, physical_sectors):
        if not physical_sectors: return {}
        logical_sectors = self.rwts.reorder_to_logical_sectors(physical_sectors)
        if self.rwts.enough(logical_track_num, physical_sectors):
            # patchers operate on logical tracks
            if logical_track_num == 0:
                # set additional globals for patchers to use
                self.AnalyzeT00(logical_sectors)
            for patcher in self.patchers:
                if patcher.should_run(logical_track_num):
                    patches = patcher.run(logical_sectors, logical_track_num)
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
    def save_track(self, physical_track_num, logical_track_num, physical_sectors):
        # output_tracks is indexed on logical track number here because the
        # point of cracking is normalizing to logical tracks and sectors
        self.output_tracks[logical_track_num] = Verify.save_track(self, physical_track_num, logical_track_num, physical_sectors)

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
        source_base, source_ext = os.path.splitext(self.g.filename)
        output_filename = source_base + '.dsk'
        self.g.logger.PrintByID("writing", {"filename":output_filename})
        with open(output_filename, "wb") as f:
            for logical_track_num in range(0x23):
                if logical_track_num in self.output_tracks:
                    f.write(concat_track(self.output_tracks[logical_track_num]))
                else:
                    f.write(bytes(256*16))
        if self.patches_found:
            self.g.logger.PrintByID("passcrack")
        else:
            self.g.logger.PrintByID("passcrack0")

class Convert(BasePassportProcessor):
    def preprocess(self):
        self.burn = 2
        return True

    def save_track(self, physical_track_num, logical_track_num, physical_sectors):
        track = self.tracks[physical_track_num]
        if physical_sectors:
            b = bitarray.bitarray(endian="big")
            for s in physical_sectors.values():
                b.extend(track.bits[s.start_bit_index:s.end_bit_index])
        else:
            # TODO call wozify here instead
            b = track.bits[:51021]
        # output_tracks is indexed on physical track number here because the
        # point of .woz is to capture the physical layout of the original disk
        self.output_tracks[physical_track_num] = wozardry.Track(b, len(b))

    def postprocess(self):
        source_base, source_ext = os.path.splitext(self.g.filename)
        output_filename = source_base + '.woz'
        self.g.logger.PrintByID("writing", {"filename":output_filename})
        woz_image = wozardry.WozDiskImage()
        json_string = self.g.disk_image.to_json()
        woz_image.from_json(json_string)
        j = json.loads(json_string)
        root = [x for x in j.keys()].pop()
        woz_image.info["creator"] = STRINGS["header"].strip()[:32]
        woz_image.info["synchronized"] = j[root]["info"]["synchronized"]
        woz_image.info["cleaned"] = True #self.g.found_and_cleaned_weakbits
        woz_image.info["write_protected"] = self.g.protection_enforces_write_protected or j[root]["info"]["write_protected"]
        woz_image.meta["image_date"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        for q in range(1 + (0x23 * 4)):
            physical_track_num = q / 4
            if physical_track_num in self.output_tracks:
                woz_image.add_track(physical_track_num, self.output_tracks[physical_track_num])
        try:
            wozardry.WozDiskImage(io.BytesIO(bytes(woz_image)))
        except Exception as e:
            raise Exception from e
        with open(output_filename, 'wb') as f:
            f.write(bytes(woz_image))
