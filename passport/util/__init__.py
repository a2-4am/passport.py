__all__ = ["find", "decode44", "concat_track"]

def decode44(n1, n2):
    return ((n1 << 1) + 1) & n2

def concat_track(logical_sectors):
    """returns a single bytes object containing all data from logical_sectors dict, in order"""
    data = []
    for i in range(16):
        if i in logical_sectors:
            data.append(logical_sectors[i].decoded)
        else:
            data.append(bytearray(256))
    return b''.join(data)
