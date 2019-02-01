from passport.loggers.default import DefaultLogger
import sys

class DebugLogger(DefaultLogger):
    """print usual log to stdout, print extra debugging information to stderr"""
    def debug(self, s):
        sys.stderr.write(s)
        sys.stderr.write("\n")
