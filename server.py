#!/usr/bin/env python3
# https://tls13.xargs.org/

from enum import Enum
from typing import List

from cipher_suites import CipherSuite
from tls import ByteReader, Handshake

import socket
import struct

HOST = "127.0.0.1"
PORT = 1443

def parse_tls_handshake(data: bytes):
  reader = ByteReader(data)

  # parse record header
  content_type = reader.read_u8()
  version = reader.read_u16()
  length = reader.read_u16()

  # parse handshake header
  handshake = Handshake.from_bytes(reader.read_bytes(length))
  print(handshake)

  data = data[5:]
  data2 = handshake.to_bytes()

  print(len(data))
  print(len(data2))
  print(data == data2)

def main() -> None:
  with open("samples/client_hello.bin", "rb") as f:
    data = f.read()
  parse_tls_handshake(data)
  return

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

    print(data)
    print(len(data))

    with open("tls.bin", "wb") as f:
      f.write(data)

    break

if __name__ == "__main__":
  main()

