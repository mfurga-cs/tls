# https://tls13.xargs.org/

from enum import IntEnum
from typing import List

from cipher_suites import CipherSuite
from utils import ByteReader, ByteWriter

from x25519 import base_point_mult


class HandshakeType(IntEnum):
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


class HandshakeVersion(IntEnum):
  TLS_1 = 0x0301
  TLS_1_1 = 0x0302
  TLS_1_2 = 0x0303
  TLS_1_3 = 0x0304


class HandshakeExtensionType(IntEnum):
  SERVER_NAME = 0
  MAX_FRAGMENT_LENGTH = 1
  CLIENT_CERTIFICATE_URL = 2
  TRUSTED_CA_KEYS = 3
  TRUNCATED_HMAC = 4
  STATUS_REQUEST = 5
  USER_MAPPING = 6
  CLIENT_AUTHZ = 7
  SERVER_AUTHZ = 8
  CERT_TYPE = 9
  SUPPORTED_GROUPS = 10
  EC_POINT_FORMATS = 11
  SRP = 12
  SIGNATURE_ALGORITHMS = 13
  USE_SRTP = 14
  HEARTBEAT = 15
  APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
  STATUS_REQUEST_V2 = 17
  SIGNED_CERTIFICATE_TIMESTAMP = 18
  CLIENT_CERTIFICATE_TYPE = 19
  SERVER_CERTIFICATE_TYPE = 20
  PADDING = 21
  ENCRYPT_THEN_MAC = 22
  EXTENDED_MASTER_SECRET = 23
  TOKEN_BINDING = 24
  CACHED_INFO = 25
  TLS_LTS = 26
  COMPRESS_CERTIFICATE = 27
  RECORD_SIZE_LIMIT = 28
  PWD_PROTECT = 29
  PWD_CLEAR = 30
  PASSWORD_SALT = 31
  TICKET_PINNING = 32
  TLS_CERT_WITH_EXTERN_PSK = 33
  DELEGATED_CREDENTIAL = 34
  SESSION_TICKET = 35
  TLMSP = 36
  TLMSP_PROXYING = 37
  TLMSP_DELEGATE = 38
  SUPPORTED_EKT_CIPHERS = 39
  RESERVED = 40
  PRE_SHARED_KEY = 41
  EARLY_DATA = 42
  SUPPORTED_VERSIONS = 43
  COOKIE = 44
  PSK_KEY_EXCHANGE_MODES = 45
  CERTIFICATE_AUTHORITIES = 47
  OID_FILTERS = 48
  POST_HANDSHAKE_AUTH = 49
  SIGNATURE_ALGORITHMS_CERT = 50
  KEY_SHARE = 51
  TRANSPARENCY_INFO = 52
  CONNECTION_ID = 54
  EXTERNAL_ID_HASH = 55
  EXTERNAL_SESSION_ID = 56
  QUIC_TRANSPORT_PARAMETERS = 57
  TICKET_REQUEST = 58
  DNSSEC_CHAIN = 59
  SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS = 60
  RRC = 61
  UNASIGNED = 62
  ECH_OUTER_EXTENSIONS = 64768
  ENCRYPTED_CLIENT_HELLO = 65037
  RENEGOTIATION_INFO = 65281

  RESERVED_46 = 46
  RESERVED_2570 = 2570
  RESERVED_6682 = 6682
  RESERVED_10794 = 10794
  RESERVED_14906 = 14906
  RESERVED_19018 = 19018
  RESERVED_23130 = 23130
  RESERVED_27242 = 27242
  RESERVED_31354 = 31354
  RESERVED_35466 = 35466
  RESERVED_39578 = 39578
  RESERVED_43690 = 43690
  RESERVED_47802 = 47802
  RESERVED_51914 = 51914
  RESERVED_56026 = 56026
  RESERVED_60138 = 60138
  RESERVED_64250 = 64250
  RESERVED_65280 = 65280

  UNASIGNED_17513 = 17513


  # TODO: Move these values to enum fields.
  @classmethod
  def _missing_(cls, value):
    # if value in [46, 2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
    #              35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250, 65280]:
    #   return cls.RESERVED

    if 65282 <= value <= 65535:
      return cls.RESERVED

    return cls.UNASIGNED


class HandshakeExtension:
  def __init__(self,
               type: HandshakeExtensionType,
               data: bytes):
    self.type = type
    self.data = data

  @property
  def length(self) -> int:
    return len(self.data)

  @classmethod
  def from_bytes(cls, data: bytes):
    reader = ByteReader(data)

    type = HandshakeExtensionType(reader.read_u16())
    length = reader.read_u16()
    data = reader.read_bytes(length)

    return cls(type, data)

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u16(self.type.value)
    writer.write_u16(self.length)
    assert self.length == len(self.data)
    data = writer.write_bytes(self.data)

    return data

  def __len__(self) -> int:
    return len(self.to_bytes())

  def __str__(self) -> str:
    s = []
    s.append(f"Type : {self.type.name.ljust(40)} (0x{self.type:04x})")
    s.append(f"Length : {self.length}")
    s.append(f"Data : 0x{self.data[:8].hex()} ...")
    return "\t".join(s)


class KeyShareEntry:
  def __init__(self, group: int, key: bytes):
    self.group = group
    self.key = key
    #self.pub_key = base_point_mult(key)

  @property
  def length(self):
    return len(self.key)

  @classmethod
  def from_bytes(cls, data: bytes):
    reader = ByteReader(data)

    group = reader.read_u16()
    length = reader.read_u16()
    key = reader.read_bytes(length)

    return cls(group, key)

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u16(self.group)
    writer.write_u16(self.length)
    assert self.length == len(self.key)
    data = writer.write_bytes(self.key)

    return data

  def __len__(self) -> int:
    return len(self.to_bytes())

  def __str__(self) -> str:
    s = []
    s.append(f"Group : 0x{self.group:04x}")
    s.append(f"Length : {self.length}")
    s.append(f"Key : 0x{self.key[:8].hex()} ...")
    #s.append(f"Public key : 0x{self.pub_key[:8].encode().hex()} ...")
    return "\t".join(s)


class KeyShareExtension:
  def __init__(self, entries: KeyShareEntry):
    self.entries = entries

  @property
  def length(self) -> int:
    return sum(len(entry) for entry in self.entries)

  @classmethod
  def from_bytes(cls, data: bytes):
    reader = ByteReader(data)

    length = reader.read_u16()
    data = reader.read_bytes(length)

    entries = []
    while len(data) > 0:
      entry = KeyShareEntry.from_bytes(data)
      entries.append(entry)
      data = data[len(entry):]

    return cls(entries)

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u16(self.length)
    entries = bytes.join(b"", [
      entry.to_bytes() for entry in self.entries
    ])
    assert len(entries) == self.length
    data = writer.write_bytes(entries)

    return data

  def __len__(self) -> int:
    return len(self.to_bytes())

  def __str__(self) -> str:
    s = []
    s.append("** Key Share Extension **")
    s.append("Entries :")

    for entry in self.entries:
      s.append(f"  {str(entry)}")
    return "\n".join(s)


class Handshake:
  def __init__(self,
               type: HandshakeType,
               version: HandshakeVersion,
               random: bytes,
               session_id: bytes,
               cipher_suites: List[CipherSuite],
               compression_methods: List[int],
               extensions: List[HandshakeExtension]):
    self.type = type
    self.version = version
    assert len(random) == 32
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
    version = HandshakeVersion(reader.read_u16())
    random = reader.read_bytes(32)

    session_id_length = reader.read_u8()
    session_id = reader.read_bytes(session_id_length)

    if type == HandshakeType.CLIENT_HELLO:
      cipher_suites_len = reader.read_u16()
    else:
      assert type == HandshakeType.SERVER_HELLO
      cipher_suites_len = 2

    cipher_suites = reader.read_bytes(cipher_suites_len)
    cipher_suites = [
      CipherSuite(int.from_bytes(cipher_suites[i:i + 2], "big"))
        for i in range(0, cipher_suites_len, 2)
    ]

    if type == HandshakeType.CLIENT_HELLO:
      compression_methods_len = reader.read_u8()
    else:
      assert type == HandshakeType.SERVER_HELLO
      compression_methods_len = 1

    compression_methods = list(reader.read_bytes(compression_methods_len))

    extensions_len = reader.read_u16()
    extensions = reader.read_bytes(extensions_len)
    exts = []
    while len(extensions) > 0:
      extension = HandshakeExtension.from_bytes(extensions)
      exts.append(extension)
      extensions = extensions[len(extension):]

    return cls(type, version, random, session_id, cipher_suites,
               compression_methods, exts)

  @property
  def length(self) -> int:
    l = 2 + 32 + 1 + len(self.session_id)

    if self.type == HandshakeType.CLIENT_HELLO:
      l += 2  # cipher suites len

    l += len(self.cipher_suites) * 2

    if self.type == HandshakeType.CLIENT_HELLO:
      l += 1  # compression methods len

    l += len(self.compression_methods)
    l += 2  # extensions len
    l += sum(len(ext) for ext in self.extensions)

    return l

  def to_bytes(self) -> bytes:
    writer = ByteWriter()

    writer.write_u8(self.type.value)
    writer.write_u24(self.length)
    writer.write_u16(self.version.value)

    assert len(self.random) == 32
    writer.write_bytes(self.random)

    session_id_len = len(self.session_id) * 1
    session_id = bytes(self.session_id)
    assert len(session_id) == session_id_len
    writer.write_u8(session_id_len)
    writer.write_bytes(session_id)

    if self.type == HandshakeType.CLIENT_HELLO:
      cipher_suites_len = len(self.cipher_suites) * 2
      writer.write_u16(cipher_suites_len)
    else:
      assert self.type == HandshakeType.SERVER_HELLO
      cipher_suites_len = 2

    cipher_suites = bytes.join(b"", [
      cs.value.to_bytes(2, "big") for cs in self.cipher_suites
    ])
    assert len(cipher_suites) == cipher_suites_len
    writer.write_bytes(cipher_suites)

    if self.type == HandshakeType.CLIENT_HELLO:
      compression_methods_len = len(self.compression_methods) * 1
      writer.write_u8(compression_methods_len)
    else:
      assert self.type == HandshakeType.SERVER_HELLO
      compression_methods_len = 1

    compression_methods = bytes(self.compression_methods)
    assert len(compression_methods) == compression_methods_len
    writer.write_bytes(compression_methods)

    extensions_len = sum([len(ext) for ext in self.extensions])
    extensions = bytes.join(b"", [
      ext.to_bytes() for ext in self.extensions
    ])
    assert len(extensions) == extensions_len
    writer.write_u16(extensions_len)
    data = writer.write_bytes(extensions)

    return data

  def __len__(self) -> int:
    return len(self.to_bytes())

  def __str__(self) -> str:
    s = []
    s.append("** Handshake **")
    s.append(f"Type          : {self.type.name}")
    s.append(f"Length        : {self.length}")
    s.append(f"Version       : {self.version.name}")
    s.append(f"Random        : 0x{self.random.hex()}")
    s.append(f"Session ID    : 0x{self.session_id.hex()}")
    s.append(f"Cipher suites :")

    for cipher_suite in self.cipher_suites:
      s.append(f"  {cipher_suite.name}")

    s.append(f"Compression   : {self.compression_methods}")
    s.append(f"Extensions    :")

    for extension in self.extensions:
      s.append(f"  {str(extension)}")

    return "\n".join(s)

