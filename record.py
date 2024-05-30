from enum import Enum

from utils import ByteReader, ByteWriter


class RecordContentType(Enum):
  CHANGE_CIPHER_SPEC = 0x14
  ALERT = 0x15
  HANDSHAKE = 0x16
  APPLICATION_DATA = 0x17
  HEARTBEAT = 0x18


class RecordVersion(Enum):
  SSL_3 = 0x0300
  TLS_1 = 0x0301
  TLS_1_1 = 0x0302
  TLS_1_2 = 0x0303
  TLS_1_3 = 0x0304


class Record:
  def __init__(self,
               content_type: RecordContentType,
               version: RecordVersion,
               data: bytes):
    self.content_type = content_type
    self.version = version
    self.data = data

  @property
  def length(self) -> int:
    return len(self.data)

  @classmethod
  def from_bytes(cls, data: bytes):
    reader = ByteReader(data)

    content_type = RecordContentType(reader.read_u8())
    version = RecordVersion(reader.read_u16())
    length = reader.read_u16()
    data = reader.read_bytes(length)

    return cls(content_type, version, data)

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u8(self.content_type.value)
    writer.write_u16(self.version.value)
    writer.write_u16(self.length)
    assert self.length == len(self.data)
    data = writer.write_bytes(self.data)

    return data

  def __len__(self) -> int:
    return len(self.to_bytes())

  def __str__(self) -> str:
    s = []
    s.append("** Record **")
    s.append(f"Content Type : {self.content_type.name}")
    s.append(f"Version      : {self.version.name}")
    s.append(f"Length       : {self.length}")
    s.append(f"Data         : 0x{self.data[:32].hex()} ...")
    return "\n".join(s)

