from passport.wozardry import Track, raise_if
import bitarray
import json

class EDDError(Exception): pass # base class
class EDDLengthError(EDDError): pass
class EDDSeekError(EDDError): pass

class EDDReader:
    def __init__(self, iostream):
        for i in range(137):
            raw_bytes = iostream.read(16384)
            raise_if(len(raw_bytes) != 16384, EDDLengthError, "Bad EDD file (did you image by quarter tracks?)")
            bits = bitarray.bitarray(endian="big")
            bits.frombytes(raw_bytes)
            self.tracks.append(Track(bits, 131072))

    def seek(self, track_num):
        if type(track_num) != float:
            track_num = float(track_num)
        if track_num < 0.0 or \
           track_num > 35.0 or \
           track_num.as_integer_ratio()[1] not in (1,2,4):
            raise EDDSeekError("Invalid track %s" % track_num)
        trk_id = int(track_num * 4)
        return self.tracks[trk_id]

    def to_json(self):
        j = {"edd":
             {"info":
              {"synchronized":False,
               "write_protected":False,
               "cleaned":False
              },
              "meta":{}
             }
        }
        return json.dumps(j, indent=2)
