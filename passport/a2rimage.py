from passport.wozimage import DiskImage, Track, WozError, raise_if
from passport import a2rchery
import bitarray
import collections

class A2RImage:
    def __init__(self, filename=None, stream=None):
        self.filename = filename
        self.tracks = collections.OrderedDict()
        self.a2r_image = a2rchery.A2RReader(filename, stream)

    def to_bits(self, flux_record):
        """|flux_record| is a dictionary of 'capture_type', 'data_length', 'tick_count', and 'data'"""
        bits = bitarray.bitarray()
        estimated_track_length = 0
        if not flux_record or flux_record["capture_type"] != a2rchery.kCaptureTiming:
            return bits, estimated_track_length, 0
        ticks = 0
        flux_total = 0
        fluxxen = flux_record["data"]
        speeds = [(len([1 for i in fluxxen if i%t==0]), t) for t in range(0x1c,0x25)]
        speeds.sort()
        speed = speeds[-1][1]
        for flux_value in fluxxen[1:]:
            ticks += flux_value
            if not estimated_track_length and ticks > flux_record["tick_count"]:
                estimated_track_length = len(bits)
            flux_total += flux_value
            if flux_value == 0xFF:
                continue
            bits.extend([0] * ((flux_total - speed//2) // speed))
            bits.append(1)
            flux_total = 0
        return bits, estimated_track_length, speed

    def find_track_length(self, bits, estimated_track_length):
        twice_bits = bits + bits
        for matchlen in (8192, 4096, 2048, 1024):
            if estimated_track_length < 32768 or len(bits) < 32768: continue
            for offset in range(0, estimated_track_length, matchlen):
                for length_delta in (0, 1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7, 8, -8, 9, -9, 10, -10, 11, -11, 12, -12):
                    real_length = estimated_track_length + length_delta
                    if real_length > 53168: continue
                    if twice_bits[8+offset:offset+matchlen] == twice_bits[real_length+8+offset:real_length+matchlen+offset]:
                        return real_length
        return 0

    def normalize(self, flux_records):
        bits_and_lengths = [self.to_bits(flux_record) for flux_record in flux_records]
        all_bits = [bits[8:self.find_track_length(bits, estimated_track_length)+8] for bits, estimated_track_length, speed in bits_and_lengths]
        return all_bits

    def seek(self, track_num):
        if type(track_num) != float:
            track_num = float(track_num)
        if track_num < 0.0 or \
           track_num > 35.0 or \
           track_num.as_integer_ratio()[1] not in (1,2,4):
            raise WozError("Invalid track %s" % track_num)
        location = int(track_num * 4)
        if not self.tracks.get(location):
            all_bits = bitarray.bitarray()
            for flux_record in self.a2r_image.flux.get(location, [{}]):
                bits, track_length, speed = self.to_bits(flux_record)
                all_bits.extend(bits)
            self.tracks[location] = Track(all_bits, len(all_bits), speed=speed)
        return self.tracks[location]
