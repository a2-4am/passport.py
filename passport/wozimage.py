#!/usr/bin/env python3

# (c) 2018 by 4am
# MIT-licensed
# portions from MIT-licensed defedd.py (c) 2014 by Paul Hagstrom

import binascii
import bitarray # https://pypi.org/project/bitarray/
import collections
import itertools
import sys

# domain-specific constants defined in .woz specification
kWOZ1 = b'WOZ1'
kINFO = b'INFO'
kTMAP = b'TMAP'
kTRKS = b'TRKS'
kMETA = b'META'
kBitstreamLengthInBytes = 6646
kLanguages = ('English','Spanish','French','German','Chinese','Japanese','Italian','Dutch','Portugese','Danish','Finnish','Norwegian','Swedish','Russian','Polish','Turkish','Arabic','Thai','Czech','Hungarian','Catalan','Croatian','Greek','Hebrew','Romanian','Slovak','Ukranian','Indonesian','Malay','Vietnamese','Other')
kRequiresRAM = ('16K','24K','32K','48K','64K','128K','256K','512K','768K','1M','1.25M','1.5M+','Unknown')
kRequiresMachine = ('2','2+','2e','2c','2e+','2gs','2c+','3','3+')

# strings and things, for print routines and error messages
sEOF = "Unexpected EOF"
sBadChunkSize = "Bad chunk size"
dNoYes = {False:'no',True:'yes'}
tQuarters = ('.00','.25','.50','.75')

# errors that may be raised
class WozError(Exception): pass # base class
class WozCRCError(WozError): pass
class WozFormatError(WozError): pass
class WozEOFError(WozFormatError): pass
class WozHeaderError(WozFormatError): pass
class WozHeaderError_NoWOZ1(WozHeaderError): pass
class WozHeaderError_NoFF(WozHeaderError): pass
class WozHeaderError_NoLF(WozHeaderError): pass
class WozINFOFormatError(WozFormatError): pass
class WozINFOFormatError_BadVersion(WozINFOFormatError): pass
class WozINFOFormatError_BadDiskType(WozINFOFormatError): pass
class WozINFOFormatError_BadWriteProtected(WozINFOFormatError): pass
class WozINFOFormatError_BadSynchronized(WozINFOFormatError): pass
class WozINFOFormatError_BadCleaned(WozINFOFormatError): pass
class WozTMAPFormatError(WozFormatError): pass
class WozTMAPFormatError_BadTRKS(WozTMAPFormatError): pass
class WozTRKSFormatError(WozFormatError): pass
class WozMETAFormatError(WozFormatError): pass
class WozMETAFormatError_DuplicateKey(WozFormatError): pass
class WozMETAFormatError_BadLanguage(WozFormatError): pass
class WozMETAFormatError_BadRAM(WozFormatError): pass
class WozMETAFormatError_BadMachine(WozFormatError): pass

def from_uint32(b):
    return int.from_bytes(b, byteorder="little")
from_uint16=from_uint32

def to_uint32(b):
    return b.to_bytes(4, byteorder="little")

def to_uint16(b):
    return b.to_bytes(2, byteorder="little")

def raise_if(cond, e, s=""):
    if cond: raise e(s)

class Track:
    def __init__(self, bits, bit_count):
        self.bits = bits
        while len(self.bits) > bit_count:
            self.bits.pop()
        self.bit_count = bit_count
        self.bit_index = 0
        self.revolutions = 0
        
    def bit(self):
        b = self.bits[self.bit_index] and 1 or 0
        self.bit_index += 1
        if self.bit_index >= self.bit_count:
            self.bit_index = 0
            self.revolutions += 1
        yield b

    def nibble(self):
        b = 0
        while b == 0:
            b = next(self.bit())
        n = 0x80
        for bit_index in range(6, -1, -1):
            b = next(self.bit())
            n += b << bit_index
        yield n

    def find(self, sequence):
        starting_revolutions = self.revolutions
        seen = [0] * len(sequence)
        while (self.revolutions < starting_revolutions + 2):
            del seen[0]
            seen.append(next(self.nibble()))
            if tuple(seen) == tuple(sequence): return True
        return False

class WozTrack(Track):
    def __init__(self, bits, bit_count, splice_point = 0xFFFF, splice_nibble = 0, splice_bit_count = 0):
        Track.__init__(self, bits, bit_count)
        self.splice_point = splice_point
        self.splice_nibble = splice_nibble
        self.splice_bit_count = splice_bit_count

class DiskImage: # base class
    def __init__(self, filename=None, stream=None):
        raise_if(not filename and not stream, WozError, "no input")
        self.filename = filename
        self.tracks = []

    def seek(self, track_num):
        """returns Track object for the given track, or None if the track is not part of this disk image. track_num can be 0..40 in 0.25 increments (0, 0.25, 0.5, 0.75, 1, &c.)"""
        return None

class EDDReader(DiskImage):
    def __init__(self, filename=None, stream=None):
        DiskImage.__init__(self, filename, stream)
        with stream or open(filename, 'rb') as f:
            for i in range(137):
                raw_bytes = f.read(16384)
                raise_if(len(raw_bytes) != 16384, WozError, "Bad EDD file (did you image by quarter tracks?)")
                bits = bitarray.bitarray(endian="big")
                bits.frombytes(raw_bytes)
                self.tracks.append(Track(bits, 131072))

    def seek(self, track_num):
        if type(track_num) != float:
            track_num = float(track_num)
        if track_num < 0.0 or \
           track_num > 35.0 or \
           track_num.as_integer_ratio()[1] not in (1,2,4):
            raise WozError("Invalid track %s" % track_num)
        trk_id = int(track_num * 4)
        return self.tracks[trk_id]

class WozWriter:
    def __init__(self, creator):
        self.tracks = []
        self.tmap = [0xFF]*160
        self.creator = creator
        #self.meta = collections.OrderedDict()

    def add_track(self, track_num, track):
        tmap_id = int(track_num * 4)
        trk_id = len(self.tracks)
        self.tracks.append(track)
        self.tmap[tmap_id] = trk_id
        if tmap_id:
            self.tmap[tmap_id - 1] = trk_id
        if tmap_id < 159:
            self.tmap[tmap_id + 1] = trk_id

    def build_info(self):
        chunk = bytearray()
        chunk.extend(kINFO) # chunk ID
        chunk.extend(to_uint32(60)) # chunk size
        chunk.extend(b'\x01') # version = 1
        chunk.extend(b'\x01') # disk type = 1 (5.25-inch)
        chunk.extend(b'\x00') # write-protected = 0
        chunk.extend(b'\x00') # synchronized = 0
        chunk.extend(b'\x00') # cleaned = 0
        chunk.extend(self.creator.encode("UTF-8").ljust(32, b" ")) # creator
        chunk.extend(b'\x00' * 23) # reserved
        return chunk
    
    def build_tmap(self):
        chunk = bytearray()
        chunk.extend(kTMAP) # chunk ID
        chunk.extend(to_uint32(160)) # chunk size
        chunk.extend(bytes(self.tmap))
        return chunk
    
    def build_trks(self):
        chunk = bytearray()
        chunk.extend(kTRKS) # chunk ID
        chunk_size = len(self.tracks)*6656
        chunk.extend(to_uint32(chunk_size)) # chunk size
        for track in self.tracks:
            raw_bytes = track.bits.tobytes()
            chunk.extend(raw_bytes) # bitstream as raw bytes
            chunk.extend(b'\x00' * (6646 - len(raw_bytes))) # padding to 6646 bytes
            chunk.extend(to_uint16(len(raw_bytes))) # bytes used
            chunk.extend(to_uint16(track.bit_count)) # bit count
            chunk.extend(b'\xFF\xFF') # splice point (none)
            chunk.extend(b'\xFF') # splice nibble (none)
            chunk.extend(b'\xFF') # splice bit count (none)
            chunk.extend(b'\x00\x00') # reserved
        return chunk

    def build_meta(self):
        return b''
        
    def build_head(self, crc):
        chunk = bytearray()
        chunk.extend(kWOZ1) # magic bytes
        chunk.extend(b'\xFF\x0A\x0D\x0A') # more magic bytes
        chunk.extend(to_uint32(crc)) # CRC32 of rest of file (calculated in caller)
        return chunk

    def write(self, stream):
        info = self.build_info()
        tmap = self.build_tmap()
        trks = self.build_trks()
        meta = self.build_meta()
        crc = binascii.crc32(info + tmap + trks + meta)
        head = self.build_head(crc)
        stream.write(head)
        stream.write(info)
        stream.write(tmap)
        stream.write(trks)
        stream.write(meta)
        
class WozReader(DiskImage):
    def __init__(self, filename=None, stream=None):
        DiskImage.__init__(self, filename, stream)
        self.tmap = None
        self.info = None
        self.meta = None

        with stream or open(filename, 'rb') as f:
            header_raw = f.read(8)
            raise_if(len(header_raw) != 8, WozEOFError, sEOF)
            self.__process_header(header_raw)
            crc_raw = f.read(4)
            raise_if(len(crc_raw) != 4, WozEOFError, sEOF)
            crc = from_uint32(crc_raw)
            all_data = []
            while True:
                chunk_id = f.read(4)
                if not chunk_id: break
                raise_if(len(chunk_id) != 4, WozEOFError, sEOF)
                all_data.append(chunk_id)
                chunk_size_raw = f.read(4)
                raise_if(len(chunk_size_raw) != 4, WozEOFError, sEOF)
                all_data.append(chunk_size_raw)
                chunk_size = from_uint32(chunk_size_raw)
                data = f.read(chunk_size)
                raise_if(len(data) != chunk_size, WozEOFError, sEOF)
                all_data.append(data)
                if chunk_id == kINFO:
                    raise_if(chunk_size != 60, WozINFOFormatError, sBadChunkSize)
                    self.__process_info(data)
                elif chunk_id == kTMAP:
                    raise_if(chunk_size != 160, WozTMAPFormatError, sBadChunkSize)
                    self.__process_tmap(data)
                elif chunk_id == kTRKS:
                    self.__process_trks(data)
                elif chunk_id == kMETA:
                    self.__process_meta(data)
            if crc:
                raise_if(crc != binascii.crc32(b''.join(all_data)) & 0xffffffff, WozCRCError, "Bad CRC")

    def __process_header(self, data):
        raise_if(data[:4] != kWOZ1, WozHeaderError_NoWOZ1, "Magic string 'WOZ1' not present at offset 0")
        raise_if(data[4] != 0xFF, WozHeaderError_NoFF, "Magic byte 0xFF not present at offset 4")
        raise_if(data[5:8] != b'\x0A\x0D\x0A', WozHeaderError_NoLF, "Magic bytes 0x0A0D0A not present at offset 5")

    def __process_info(self, data):
        version = data[0]
        raise_if(version != 1, WozINFOFormatError_BadVersion, "Unknown version (expected 1, found %d)" % version)
        disk_type = data[1]
        raise_if(disk_type not in (1,2), WozINFOFormatError_BadDiskType, "Unknown disk type (expected 1 or 2, found %d)" % disk_type)
        write_protected = data[2]
        raise_if(write_protected not in (0,1), WozINFOFormatError_BadWriteProtected, "Unknown write protected flag (expected 0 or 1, found %d)" % write_protected)
        synchronized = data[3]
        raise_if(synchronized not in (0,1), WozINFOFormatError_BadSynchronized, "Unknown synchronized flag (expected 0, or 1, found %d)" % synchronized)
        cleaned = data[4]
        raise_if(cleaned not in (0,1), WozINFOFormatError_BadCleaned, "Unknown cleaned flag (expected 0 or 1, found %d)" % cleaned)
        try:
            creator = data[5:37].decode('UTF-8')
        except:
            raise WOZINFOFormatError("Creator is not valid UTF-8")
        self.info = {"version": version,
                     "disk_type": disk_type,
                     "write_protected": (write_protected == 1),
                     "synchronized": (synchronized == 1),
                     "cleaned": (cleaned == 1),
                     "creator": creator}

    def __process_tmap(self, data):
        self.tmap = list(data)

    def __process_trks(self, data):
        i = 0
        while i < len(data):
            raw_bytes = data[i:i+kBitstreamLengthInBytes]
            raise_if(len(raw_bytes) != kBitstreamLengthInBytes, WozEOFError, sEOF)
            i += kBitstreamLengthInBytes
            bytes_used_raw = data[i:i+2]
            raise_if(len(bytes_used_raw) != 2, WozEOFError, sEOF)
            bytes_used = from_uint16(bytes_used_raw)
            raise_if(bytes_used > kBitstreamLengthInBytes, WozTRKSFormatError, "TRKS chunk %d bytes_used is out of range" % len(self.tracks))
            i += 2
            bit_count_raw = data[i:i+2]
            raise_if(len(bit_count_raw) != 2, WozEOFError, sEOF)
            bit_count = from_uint16(bit_count_raw)
            i += 2
            splice_point_raw = data[i:i+2]
            raise_if(len(splice_point_raw) != 2, WozEOFError, sEOF)
            splice_point = from_uint16(splice_point_raw)
            if splice_point != 0xFFFF:
                raise_if(splice_point > bit_count, WozTRKSFormatError, "TRKS chunk %d splice_point is out of range" % len(self.tracks))
            i += 2
            splice_nibble = data[i]
            i += 1
            splice_bit_count = data[i]
            if splice_point != 0xFFFF:
                raise_if(splice_bit_count not in (8,9,10), WozTRKSFormatError, "TRKS chunk %d splice_bit_count is out of range" % len(self.tracks))
            i += 3
            bits = bitarray.bitarray(endian="big")
            bits.frombytes(raw_bytes)
            self.tracks.append(WozTrack(bits, bit_count, splice_point, splice_nibble, splice_bit_count))
        for trk, i in zip(self.tmap, itertools.count()):
            raise_if(trk != 0xFF and trk >= len(self.tracks), WozTMAPFormatError_BadTRKS, "Invalid TMAP entry: track %d%s points to non-existent TRKS chunk %d" % (i/4, tQuarters[i%4], trk))

    def __process_meta(self, data):
        try:
            metadata = data.decode('UTF-8')
        except:
            raise WozMETAFormatError("Metadata is not valid UTF-8")
        self.meta = collections.OrderedDict()
        for line in metadata.split('\n'):
            if not line: continue
            columns_raw = line.split('\t')
            raise_if(len(columns_raw) != 2, WozMETAFormatError, "Malformed metadata")
            key, value_raw = columns_raw
            raise_if(key in self.meta, WozMETAFormatError_DuplicateKey, "Duplicate metadata key %s" % key)
            values = value_raw.split("|")
            if key == "language":
                for value in values:
                    raise_if(value and (value not in kLanguages), WozMETAFormatError_BadLanguage, "Invalid metadata language")
            elif key == "requires_ram":
                for value in values:
                    raise_if(value and (value not in kRequiresRAM), WozMETAFormatError_BadRAM, "Invalid metadata requires_ram")
            elif key == "requires_machine":
                for value in values:
                    raise_if(value and (value not in kRequiresMachine), WozMETAFormatError_BadMachine, "Invalid metadata requires_machine")
            self.meta[key] = values

    def seek(self, track_num):
        """returns Track object for the given track, or None if the track is not part of this disk image. track_num can be 0..40 in 0.25 increments (0, 0.25, 0.5, 0.75, 1, &c.)"""
        if type(track_num) != float:
            track_num = float(track_num)
        if track_num < 0.0 or \
           track_num > 40.0 or \
           track_num.as_integer_ratio()[1] not in (1,2,4):
            raise WozError("Invalid track %s" % track_num)
        trk_id = self.tmap[int(track_num * 4)]
        if trk_id == 0xFF: return None
        return self.tracks[trk_id]

# ----- quick info dump routines -----
kWidth = 20 # width of first column for printing info and metadata

def print_info(wozimage):
    print()
    print("INFO")
    print("File format version:".ljust(kWidth), "%d" % wozimage.info["version"])
    print("Disk type:".ljust(kWidth),           ("5.25-inch", "3.5-inch")[wozimage.info["disk_type"]-1])
    print("Write protected:".ljust(kWidth),     dNoYes[wozimage.info["write_protected"]])
    print("Track synchronized:".ljust(kWidth),  dNoYes[wozimage.info["synchronized"]])
    print("Weakbits cleaned:".ljust(kWidth),    dNoYes[wozimage.info["cleaned"]])
    print("Creator:".ljust(kWidth),             wozimage.info["creator"])

def print_tmap(wozimage):
    print()
    print("TMAP")
    i = 0
    for tindex in wozimage.tmap:
        if tindex != 0xFF:
            print("Track %d%s -> TRKS %d" % (i/4, tQuarters[i%4], tindex))
        i += 1

def print_meta(wozimage):
    if not wozimage.meta: return
    print()
    print("META")
    for key, values in wozimage.meta.items():
        print((key + ":").ljust(kWidth), values[0])
        for value in values[1:]:
            print("".ljust(kWidth), value)

if __name__ == "__main__":
    for wozfile in sys.argv[1:]:
        w = WozReader(wozfile)
        print_tmap(w)
        print_meta(w)
        print_info(w)
