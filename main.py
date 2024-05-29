#!/usr/bin/env python3
# https://tls13.xargs.org/

import sys

from tls import Handshake
from record import Record, RecordContentType, RecordVersion

def parse_tls_packet(data: bytes) -> None:
  record = Record.from_bytes(data)
  print(record)

  assert data[:len(record)] == record.to_bytes()

  if record.content_type == RecordContentType.HANDSHAKE:
    handshake = Handshake.from_bytes(record.data)
    print(handshake)

    assert record.data[:len(handshake)] == handshake.to_bytes()


def main() -> None:
  if len(sys.argv) < 2:
    print(f"Usage: ./{sys.argv[0]} <filename to TLS raw data>")
    sys.exit(1)

  with open(sys.argv[1], "rb") as f:
    data = f.read()

  parse_tls_packet(data)

if __name__ == "__main__":
  main()

