from passport.wozardry import Track, raise_if
from passport import a2rchery
import bitarray
import collections

class A2RSeekError(a2rchery.A2RError): pass

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

    def seek(self, track_num):
        if type(track_num) != float:
            track_num = float(track_num)
        if track_num < 0.0 or \
           track_num > 35.0 or \
           track_num.as_integer_ratio()[1] not in (1,2,4):
            raise A2RSeekError("Invalid track %s" % track_num)
        location = int(track_num * 4)
        if not self.tracks.get(location):
            all_bits = bitarray.bitarray()
            for flux_record in self.a2r_image.flux.get(location, [{}]):
                bits, track_length, speed = self.to_bits(flux_record)
                all_bits.extend(bits)
            self.tracks[location] = Track(all_bits, len(all_bits))
        return self.tracks[location]
