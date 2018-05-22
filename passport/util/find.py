WILDCARD = b'\x97'

def wild(source_bytes, search_bytes):
    """Search source_bytes (bytes object) for the first instance of search_bytes (bytes_object). search_bytes may contain a wildcard that matches any byte, like '.' in a regular expression. Returns index of first match or -1, like string find() method."""
    ranges = search_bytes.split(WILDCARD)
    first_index = last_index = source_bytes.find(ranges[0])
    if first_index == -1: return -1
    last_index += len(ranges[0])
    for search_range in ranges[1:]:
        last_index += 1
        if not search_range: continue
        if source_bytes[last_index:last_index + len(search_range)] != search_range: return -1
        last_index += len(search_range)
    return first_index

def wild_at(offset, source_bytes, search_bytes):
    """returns True if the search_bytes was found in source_bytes at offset (search_bytes may include wildcards), otherwise False"""
    return wild(source_bytes[offset:], search_bytes) == 0

def at(offset, source_bytes, search_bytes):
    """returns True if the exact bytes search_bytes was found in source_bytes at offset (no wildcards), otherwise False"""
    return source_bytes[offset:offset+len(search_bytes)] == search_bytes
