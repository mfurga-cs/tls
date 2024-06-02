#!/usr/bin/env python3
# https://tls13.xargs.org/

import sys

from random import randbytes
from time import sleep
from hashlib import sha384
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric import x25519

from hkdf import hkdf_extract, hkdf_expand_label
from tls import (
  Handshake,
  HandshakeType,
  HandshakeVersion,
  HandshakeExtension,
  HandshakeExtensionType,
  KeyShareEntry,
  KeyShareExtension
)
from record import (
  Record,
  RecordContentType,
  RecordVersion
)
from cipher_suites import CipherSuite

def parse_tls_packet(data: bytes) -> None:
  client_record = Record.from_bytes(data)
  print(client_record)

  assert data[:len(client_record)] == client_record.to_bytes()

  if client_record.content_type != RecordContentType.HANDSHAKE:
    print("Nope")
    return

  client_hello = Handshake.from_bytes(client_record.data)

  assert client_hello.type == HandshakeType.CLIENT_HELLO
  assert data[5:] == client_hello.to_bytes()

  print(client_hello)

  if CipherSuite.TLS_AES_256_GCM_SHA384 not in client_hello.cipher_suites:
    print("TLS_AES_256_GCM_SHA384 is not supported by client")
    return

  # read the client's public key
  client_key_share = next(filter(
    lambda ext: ext.type == HandshakeExtensionType.KEY_SHARE,
    client_hello.extensions
  ), None)

  if client_key_share is None:
    print("Handshake does not contain the Key Share extension")
    return

  key_share_ext = KeyShareExtension.from_bytes(client_key_share.data)
  client_pub_key = next(filter(
    lambda entry: entry.group == 29, key_share_ext.entries), None)

  if client_pub_key is None:
    print("Handshake does not contain the x25519 Key Share Entry")
    return

  client_pub_key = client_pub_key.key

  print(f"Client's public key: 0x{client_pub_key[:8].hex()} ...")

  # TODO: To generate
  server_priv_key = bytes.fromhex(
    "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

  server_pub_key = bytes.fromhex(
    "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")

  server_random = bytes.fromhex(
    "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

  server_session_id = bytes.fromhex(
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

  # server key exchange generation
  key_share_server_pub = KeyShareEntry(group=29, key=server_pub_key)

  # server hello
  server_hello = Handshake(
    type=HandshakeType.SERVER_HELLO,
    version=HandshakeVersion.TLS_1_2,
    random=server_random,
    session_id=server_session_id,
    cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
    compression_methods=[0],
    extensions=[
      HandshakeExtension(
        type=HandshakeExtensionType.SUPPORTED_VERSIONS,
        data=HandshakeVersion.TLS_1_3.to_bytes(2, "big")
      ),
      HandshakeExtension(
        type=HandshakeExtensionType.KEY_SHARE,
        data=key_share_server_pub.to_bytes()
      )
    ]
  )

  server_hello_record = Record(
    RecordContentType.HANDSHAKE,
    RecordVersion.TLS_1_2,
    server_hello.to_bytes()
  )

  # hello hash
  hello_hash = bytes.fromhex(
    sha384(client_hello.to_bytes() + server_hello.to_bytes()).hexdigest())

  # shared secret
  priv = x25519.X25519PrivateKey.from_private_bytes(server_priv_key)
  pub = x25519.X25519PublicKey.from_public_bytes(client_pub_key)
  shared_secret = priv.exchange(pub)

  early_secret = hkdf_extract(b"\x00", b"\x00" * 48, hash=sha384)
  empty_hash = bytes.fromhex(sha384(b"").hexdigest())

  derived_secret = hkdf_expand_label(
    early_secret,
    label=b"derived",
    hash_value=empty_hash,
    length=48,
    hash=sha384
  )

  handshake_secret = hkdf_extract(
    salt=derived_secret,
    input_key_material=shared_secret,
    hash=sha384
  )

  server_secret = hkdf_expand_label(
    handshake_secret,
    label=b"s hs traffic",
    hash_value=hello_hash,
    length=48,
    hash=sha384
  )

  server_handshake_key = hkdf_expand_label(
    server_secret,
    label=b"key",
    hash_value=b"",
    length=32,
    hash=sha384
  )

  server_handshake_iv = hkdf_expand_label(
    server_secret,
    label=b"iv",
    hash_value=b"",
    length=12,
    hash=sha384
  )

  print(f"Handshake secret     : {handshake_secret.hex()}")
  print(f"Server secret        : {server_secret.hex()}")
  print(f"Server handshake key : {server_handshake_key.hex()}")
  print(f"Server handshake IV  : {server_handshake_iv.hex()}")

  server_change_cipher_spec = Record(
    RecordContentType.CHANGE_CIPHER_SPEC,
    RecordVersion.TLS_1_2,
    b"\x01"
  )

  cipher = AES.new(
    server_handshake_key,
    AES.MODE_GCM,
    server_handshake_iv
  )
  cipher.update(bytes.fromhex("1703030017"))  # record header
  encrypted_data, mac_tag = cipher.encrypt_and_digest(bytes.fromhex("08000002000016"))

  print()
  print(encrypted_data.hex())
  print(mac_tag.hex())

  server_application_data_1 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    encrypted_data + mac_tag
  )

  server_application_data_2 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    bytes.fromhex("baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a769175ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0ac30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea70743418794c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28deee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e")
  )


def main() -> None:
  if len(sys.argv) < 2:
    print(f"Usage: ./{sys.argv[0]} <filename to TLS raw data>")
    sys.exit(1)

  with open(sys.argv[1], "rb") as f:
    data = f.read()

  parse_tls_packet(data)

if __name__ == "__main__":
  main()

