# Bitcoin Core varint encoding (NOT the same as CompactSize)
# see: https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h


def read_bitcoin_core_varint(reader) -> int:
    """Read a varint from rev*.dat. 7-bit encoding with continuation bit."""
    n = 0
    while True:
        b = reader.read_uint8()
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n


def decompress_amount(x: int) -> int:
    """Undo Bitcoin Core's amount compression. See compressor.cpp."""
    if x == 0:
        return 0

    x -= 1
    e = x % 10
    x //= 10

    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1

    while e > 0:
        n *= 10
        e -= 1

    return n
