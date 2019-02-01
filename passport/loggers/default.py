from passport.loggers import BaseLogger
from passport.strings import STRINGS
import sys

class DefaultLogger(BaseLogger):
    """print to stdout in a form and verbosity that more or less mimics Passport/6502"""
    def PrintByID(self, id, params = {}):
        p = params.copy()
        if "track" not in p:
            p["track"] = self.g.track
        if "sector" not in params:
            p["sector"] = self.g.sector
        for k in ("track", "sector", "offset", "old_value", "new_value"):
            p[k] = self.to_hex_string(p.get(k, 0))
        sys.stdout.write(STRINGS[id].format(**p))
