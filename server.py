#!/usr/bin/env python3

import socket
from random import randbytes
from time import sleep

from utils import ByteReader

from x25519 import multscalar

from tls import (
  Handshake,
  HandshakeType,
  HandshakeVersion,
  HandshakeExtension,
  HandshakeExtensionType,
  KeyShareEntry
)
from record import Record, RecordContentType, RecordVersion
from cipher_suites import CipherSuite

HOST = "127.0.0.1"
PORT = 1443

def main() -> None:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen(5)

  print(f"Start listening on {HOST}:{PORT} ...", end="\n\n")

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

      record = Record.from_bytes(data)
      print(record, end="\n\n")

      if record.content_type == RecordContentType.HANDSHAKE:  # client hello
        handshake = Handshake.from_bytes(record.data)
        print(handshake, end="\n\n")

        if CipherSuite.TLS_AES_256_GCM_SHA384 not in handshake.cipher_suites:
          print("TLS_AES_256_GCM_SHA384 Cipher Suite is not supported, aborting", end="\n\n")
          break

        # read the client's public key
        client_key_share = next((ext for ext in handshake.extensions if ext.type == HandshakeExtensionType.KEY_SHARE), None)
        if client_key_share is None:
          print("Client Hello does not contain the Key Share extension, aborting", end="\n\n")
          break

        reader = ByteReader(client_key_share.data)

        client_pub_key_share_len = reader.read_u16()
        client_pub_key_share_unknown = reader.read_bytes(5)
        client_pub_key_group = reader.read_u16()
        client_pub_key_len = reader.read_u16()
        client_pub_key = reader.read_bytes(client_pub_key_len)

        print(f"Client's public key: 0x{client_pub_key[:8].hex()} ...", end="\n\n")

        # server key exchange generation
        key = KeyShareEntry(group=29, key=randbytes(32))
        print(key, end="\n\n")

        # server handshake keys calc
        shared_secret = multscalar(client_pub_key, key.key)

        # server hello
        server_hello = Handshake(
          type=HandshakeType.SERVER_HELLO,
          version=HandshakeVersion.TLS_1_2,
          random=randbytes(32),
          session_id=randbytes(32),
          cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
          compression_methods=[0],
          extensions=[
            HandshakeExtension(type=HandshakeExtensionType.SUPPORTED_VERSIONS, data=HandshakeVersion.TLS_1_3.to_bytes(2)),
            HandshakeExtension(type=HandshakeExtensionType.KEY_SHARE, data=key.to_bytes()),
          ]
        )

        record = Record(
          RecordContentType.HANDSHAKE,
          RecordVersion.TLS_1_2,
          server_hello.to_bytes()
        )

        print("Sending Server Hello...", end="\n\n")
        client.send(record.to_bytes())

        # server change cipher spec
        server_change_cipher_spec = 0x01

        record = Record(
          RecordContentType.CHANGE_CIPHER_SPEC,
          RecordVersion.TLS_1_2,
          server_change_cipher_spec.to_bytes()
        )

        print("Sending Server Change Cipher Spec...", end="\n\n")
        client.send(record.to_bytes())

        # wrapped record: 
      elif record.content_type == RecordContentType.CHANGE_CIPHER_SPEC:  # client change cipher spec
        continue
      elif record.content_type == RecordContentType.ALERT:  # alert
        continue

if __name__ == "__main__":
  main()

