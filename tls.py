# https://tls13.xargs.org/

import struct
from enum import Enum
from typing import List

from cipher_suites import CipherSuite
from utils import ByteReader, ByteWriter

class HandshakeType(Enum):
  HELLO_REQUEST = 0x00
  CLIENT_HELLO = 0x01
  SERVER_HELLO = 0x02
  HELLO_VERIFY_REQUEST = 0x03
  NEW_SESSION_TICKET = 0x04
  CERTIFICATE = 0x0B
  SERVER_KEY_EXCHANGE = 0x0C
  CERTIFICATE_REQUEST = 0x0D
  SERVER_DONE = 0x0E
  CERTIFICATE_VERIFY = 0x0F
  CLIENT_KEY_EXCHANGE = 0x10
  FINISHED = 0x14
  CERTIFICATE_STATUS = 0x16

class Handshake:
  def __init__(self,
               type: HandshakeType,
               length: int,
               version: int,
               random: bytes,
               session_id: bytes,
               cipher_suites: List[CipherSuite],
               compression_methods: List[int],
               extensions: bytes
               ):
    self.type = type
    self.length = length
    self.version = version
    self.random = random
    self.session_id = session_id
    self.cipher_suites = cipher_suites
    self.compression_methods = compression_methods
    self.extensions = extensions

  @classmethod
  def from_bytes(cls, data: bytes):
    reader = ByteReader(data)

    type = HandshakeType(reader.read_u8())
    length = reader.read_u24()
    version = reader.read_u16()
    random = reader.read_bytes(32)
    session_id_length = reader.read_u8()
    session_id = reader.read_bytes(session_id_length)
    cipher_suites_len = reader.read_u16()
    cipher_suites = reader.read_bytes(cipher_suites_len)

    cipher_suites = [
      CipherSuite(int.from_bytes(cipher_suites[i:i + 2], "big"))
        for i in range(0, cipher_suites_len, 2)
    ]

    compression_methods_len = reader.read_u8()
    compression_methods = list(reader.read_bytes(compression_methods_len))

    # TODO: Parse extenstions
    extensions_len = reader.read_u16()
    extensions = reader.read_bytes(extensions_len)

    return cls(type, length, version, random, session_id, cipher_suites,
               compression_methods, extensions)

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u8(self.type.value)
    writer.write_u24(self.length)
    writer.write_u16(self.version)

    assert len(self.random) == 32
    writer.write_bytes(self.random)

    session_id_len = len(self.session_id) * 1
    session_id = bytes(self.session_id)
    assert len(session_id) == session_id_len
    writer.write_u8(session_id_len)
    writer.write_bytes(session_id)

    cipher_suites_len = len(self.cipher_suites) * 2
    cipher_suites = bytes.join(b"", [
      cs.value.to_bytes(2, "big") for cs in self.cipher_suites
    ])
    assert len(cipher_suites) == cipher_suites_len
    writer.write_u16(cipher_suites_len)
    writer.write_bytes(cipher_suites)

    compression_methods_len = len(self.compression_methods) * 1
    compression_methods = bytes(self.compression_methods)
    assert len(compression_methods) == compression_methods_len
    writer.write_u8(compression_methods_len)
    writer.write_bytes(compression_methods)

    extensions_len = len(self.extensions)
    extensions = self.extensions
    assert len(extensions) == extensions_len
    writer.write_u16(extensions_len)
    data = writer.write_bytes(extensions)

    return data

  def __str__(self) -> str:
    s = []
    s.append("** Handshake **")
    s.append(f"Type       : {self.type.name}")
    s.append(f"Length     : {self.length}")
    s.append(f"Version    : 0x{self.version:04x}")
    s.append(f"Random     : {self.random}")
    s.append(f"Session ID : {self.session_id}")
    s.append(f"Cipher suites:")

    for cipher_suite in self.cipher_suites:
      s.append(f"  {cipher_suite.name}")

    s.append(f"Compression : {self.compression_methods}")
    #s.append(f"Extensions : {self.extensions}")
    return "\n".join(s)

