__all__ = [
    "a5count",
    "a6bc95",
    "advint",
    "bademu",
    "d5d5f7",
    "microfun",
    "rwts",
    "universale7",
    ]

class Patch:
    # represents a single patch that could be applied to a disk image
    def __init__(self, track_num, sector_num, byte_offset, new_value, id=None, params={}):
        self.track_num = track_num
        self.sector_num = sector_num
        self.byte_offset = byte_offset
        self.new_value = new_value # (can be 0-length bytearray if this "patch" is really just an informational message with no changes)
        self.id = id # for logger.PrintByID (can be None)
        self.params = params.copy()
        self.params["track"] = track_num
        self.params["sector"] = sector_num
        self.params["offset"] = byte_offset

class Patcher: # base class
    def __init__(self, g):
        self.g = g

    def should_run(self, track_num):
        """returns True if this patcher applies to the given track in the current process (possibly affected by state in self.g), or False otherwise"""
        return False

    def run(self, logical_sectors, track_num):
        """returns list of Patch objects representing patches that could be applied to logical_sectors"""
        return []

