import re

WILDCARD = b'\x97'
WILDSTR  = "97"

def wild(source_bytes, search_bytes):
    """Search source_bytes (bytes object) for the first instance of search_bytes (bytes_object). search_bytes may contain WILDCARD, which matches any single byte (like "." in a regular expression). Returns index of first match, or -1 if no matches."""
    search_bytes = re.escape(search_bytes).replace(WILDCARD, b'.')
    match = re.search(search_bytes, source_bytes)
    if match:
        return match.start()
    return -1

def wild_at(offset, source_bytes, search_bytes):
    """returns True if the search_bytes was found in source_bytes at offset (search_bytes may include wildcards), otherwise False"""
    offset = wild(source_bytes[offset:], search_bytes)
    return offset == 0

def at(offset, source_bytes, search_bytes):
    """returns True if the exact bytes search_bytes was found in source_bytes at offset (no wildcards), otherwise False"""
    return source_bytes[offset:offset+len(search_bytes)] == search_bytes
