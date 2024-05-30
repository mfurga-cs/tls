#!/usr/bin/env python3

import socket
import struct
from random import randbytes

from tls import Handshake, HandshakeType, HandshakeVersion, HandshakeExtension
from record import Record, RecordContentType, RecordVersion
from cipher_suites import CipherSuite

HOST = "127.0.0.1"
PORT = 1443

def main() -> None:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen(5)

  print(f"Start listening on {HOST}:{PORT} ...")

  client, _ = s.accept()
  while True:
    data = client.recv(4 * 1024)
    if not data:
      break

    # client hello
    record = Record.from_bytes(data)
    if record.content_type == RecordContentType.HANDSHAKE:
      handshake = Handshake.from_bytes(record.data)
      print(handshake)

    # server hello
    server_hello = Handshake(
      type=HandshakeType.SERVER_HELLO,
      version=HandshakeVersion.TLS_1_2,
      random=randbytes(32),
      session_id=randbytes(32),
      cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
      compression_methods=[0],
      extensions=[
        HandshakeExtension(type=43, data=b"\x03\x04"),   # supported_versions: TLS 1.3
        HandshakeExtension(type=51, data=randbytes(32)), # key_share: ...
      ]
    )

    record = Record(
      RecordContentType.HANDSHAKE,
      RecordVersion.TLS_1_2,
      server_hello.to_bytes()
    )

    client.send(record.to_bytes())

if __name__ == "__main__":
  main()

