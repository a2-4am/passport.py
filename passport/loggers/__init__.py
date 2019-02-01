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

from .silent import SilentLogger
from .default import DefaultLogger
from .debug import DebugLogger
