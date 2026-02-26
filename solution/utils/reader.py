# Simple cursor-based binary reader for parsing Bitcoin wire format

import struct


class BufferReader:

    def __init__(self, data: bytes):
        self.data = data
        self.cursor = 0

    def read(self, n: int) -> bytes:
        if self.cursor + n > len(self.data):
            raise ValueError(f"Read past end: need {n} bytes at offset {self.cursor}, have {len(self.data)}")
        result = self.data[self.cursor:self.cursor + n]
        self.cursor += n
        return result

    def read_uint8(self) -> int:
        return struct.unpack('<B', self.read(1))[0]

    def read_uint16(self) -> int:
        return struct.unpack('<H', self.read(2))[0]

    def read_uint32(self) -> int:
        return struct.unpack('<I', self.read(4))[0]

    def read_uint64(self) -> int:
        return struct.unpack('<Q', self.read(8))[0]

    def read_int32(self) -> int:
        return struct.unpack('<i', self.read(4))[0]

    def read_compact_size(self) -> int:
        first = self.read_uint8()
        if first < 0xFD:
            return first
        elif first == 0xFD:
            return self.read_uint16()
        elif first == 0xFE:
            return self.read_uint32()
        else:
            return self.read_uint64()

    def read_bytes(self, n: int) -> bytes:
        return self.read(n)

    def read_hash(self) -> bytes:
        return self.read(32)

    def has_more(self) -> bool:
        return self.cursor < len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.cursor

    def peek(self, n: int = 1) -> bytes:
        if self.cursor + n > len(self.data):
            return self.data[self.cursor:]
        return self.data[self.cursor:self.cursor + n]
