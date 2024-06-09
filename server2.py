#!/usr/bin/env python3

import socket
import hmac
from random import randbytes
from time import sleep
from hashlib import sha384
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from utils import ByteReader, ByteWriter

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
from record import Record, RecordContentType, RecordVersion
from cipher_suites import CipherSuite

HOST = "127.0.0.1"
PORT = 1443

def parse(data: bytes, client):
  client_record = Record.from_bytes(data)
  print(client_record)

  assert data[:len(client_record)] == client_record.to_bytes()

  if client_record.content_type != RecordContentType.HANDSHAKE:
    print("Nope")
    return

  client_hello = Handshake.from_bytes(client_record.data)

  print(len(data[5:]))
  print(len(client_hello.to_bytes()))

  for i, (b1, b2) in enumerate(zip(data[5:], client_hello.to_bytes())):
    if b1 != b2:
      print(hex(i), b1, b2)

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

  server_session_id = client_hello.session_id

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

  extra_extensions = bytes.fromhex("080000020000")

  cipher = AES.new(
    server_handshake_key,
    AES.MODE_GCM,
    server_handshake_iv
  )
  cipher.update(bytes.fromhex("1703030017"))  # record header
  encrypted_data, mac_tag = cipher.encrypt_and_digest(extra_extensions + b"\x16")

  #print()
  #print(encrypted_data.hex())
  #print(mac_tag.hex())

  server_application_data_1 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    encrypted_data + mac_tag
  )

  #print(server_application_data_1.to_bytes().hex())

  # wrapped record: server certificate
  writer = ByteWriter()

  certificate = bytes.fromhex("3082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a0")

  writer.write_u8(HandshakeType.CERTIFICATE)  # handshake type
  writer.write_u24(1 + 3 + 3 + len(certificate) + 2)  # length of the data
  writer.write_u8(0x00)  # request context
  writer.write_u24(3 + len(certificate) + 2)  # length of the certificate
  writer.write_u24(len(certificate))  # length of the first (and only) certificate
  writer.write_bytes(certificate)  # certificate
  writer.write_u16(0x0000)  # certificate extensions
  # writer.write_u8(0x16)  # record type

  server_certificate = writer.data

  cipher = AES.new(
    server_handshake_key,
    AES.MODE_GCM,
    (int.from_bytes(server_handshake_iv, "big") ^ 1).to_bytes(12, "big")
  )
  cipher.update(bytes.fromhex("1703030343"))
  encrypted_data, mac_tag = cipher.encrypt_and_digest(server_certificate + b"\x16")

  #print()
  #print(encrypted_data.hex())
  #print(mac_tag.hex())

  server_application_data_2 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    encrypted_data + mac_tag
  )

  #print(server_application_data_2.to_bytes().hex())

  # wrapped record: certificate verify
  cert_private_key = RSA.import_key(open("certs/server.key", "rb").read())
  h = SHA256.new(hello_hash)
  signature = pss.new(cert_private_key).sign(h)

  assert len(signature) == 256

  writer = ByteWriter()

  writer.write_u8(HandshakeType.CERTIFICATE_VERIFY)  # handshake type
  writer.write_u24(2 + 2 + len(signature))  # length of the data
  writer.write_u16(0x0804)  # RSA-PSS-RSAE-SHA256
  writer.write_u16(len(signature))
  writer.write_bytes(signature)
  #writer.write_u8(0x16)  # record type

  certificate_verify = writer.data

  cipher = AES.new(
    server_handshake_key,
    AES.MODE_GCM,
    (int.from_bytes(server_handshake_iv, "big") ^ 2).to_bytes(12, "big")
  )
  cipher.update(b"\x17\x03\x03" + (len(certificate_verify) + 1 + 16).to_bytes(2, "big"))
  encrypted_data, mac_tag = cipher.encrypt_and_digest(certificate_verify + b"\x16")

  #print()
  #print(encrypted_data.hex())
  #print(mac_tag.hex())

  server_application_data_3 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    encrypted_data + mac_tag
  )

  #print(server_application_data_3.to_bytes().hex())

  # server handshake finished

  finished_key = hkdf_expand_label(
    server_secret,
    label=b"finished",
    hash_value=b"",
    length=48,
    hash=sha384
  )

  finished_hash = bytes.fromhex(sha384(
    client_record.to_bytes()[5:] + \
    server_hello_record.to_bytes()[5:] + \
    extra_extensions + \
    server_certificate + \
    certificate_verify
  ).hexdigest())

  verify_data = bytes.fromhex(
    hmac.new(finished_key, finished_hash, sha384).hexdigest())

  writer = ByteWriter()
  writer.write_u8(HandshakeType.FINISHED)  # handshake type
  writer.write_u24(len(verify_data))
  writer.write_bytes(verify_data)
  writer.write_u8(0x16)  # record type
  handshake_finished = writer.data

  cipher = AES.new(
    server_handshake_key,
    AES.MODE_GCM,
    (int.from_bytes(server_handshake_iv, "big") ^ 3).to_bytes(12, "big")
  )
  cipher.update(b"\x17\x03\x03" + (len(handshake_finished) + 16).to_bytes(2, "big"))
  encrypted_data, mac_tag = cipher.encrypt_and_digest(handshake_finished)

  server_application_data_4 = Record(
    RecordContentType.APPLICATION_DATA,
    RecordVersion.TLS_1_2,
    encrypted_data + mac_tag
  )

  #print(server_application_data_4.to_bytes().hex())

  client.send(
    server_hello_record.to_bytes() + \
    server_change_cipher_spec.to_bytes() + \
    server_application_data_1.to_bytes() + \
    server_application_data_2.to_bytes() + \
    server_application_data_3.to_bytes() + \
    server_application_data_4.to_bytes()
  )


def main2() -> None:
  with open("samples/client_hello.bin", "rb") as f:
    data = f.read()
  parse(data, None)


def main() -> None:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen(5)

  print(f"Start listening on {HOST}:{PORT} ...")

  while True:
    client, _ = s.accept()
    print("Accepted a new client", end="\n\n")

    while True:
      try:
        data = client.recv(4 * 1024)

        if not data:
          sleep(0.5)
          continue
      except ConnectionResetError as e:
        print("Connection has been reset by peer", end="\n\n")
        break

      parse(data, client)

if __name__ == "__main__":
  main()
  #main2()

