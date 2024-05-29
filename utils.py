import struct


class ByteReader:
  def __init__(self, data: bytes) -> None:
    self.data = data

  def read_u8(self) -> int:
    v = struct.unpack(">B", self.data[:1])[0]
    self.data = self.data[1:]
    return v

  def read_u16(self) -> int:
    v = struct.unpack(">H", self.data[:2])[0]
    self.data = self.data[2:]
    return v

  def read_u24(self) -> int:
    v = struct.unpack(">I", b"\x00" + self.data[:3])[0]
    self.data = self.data[3:]
    return v

  def read_bytes(self, len: int) -> bytes:
    v = self.data[:len]
    self.data = self.data[len:]
    return v


class ByteWriter:
  def __init__(self) -> None:
    self.data = b""

  def write_u8(self, v: int) -> bytes:
    self.data += struct.pack(">B", v)
    return self.data

  def write_u16(self, v: int) -> bytes:
    self.data += struct.pack(">H", v)
    return self.data

  def write_u24(self, v: int) -> bytes:
    self.data += struct.pack(">I", v)[1:]
    return self.data

  def write_bytes(self, v: bytes) -> bytes:
    self.data += v
    return self.data

