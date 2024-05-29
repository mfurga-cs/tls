#!/usr/bin/env python3

import socket
import struct

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

    print(data)
    print(len(data))

    """
    with open("tls.bin", "wb") as f:
      f.write(data)
    break
    """

if __name__ == "__main__":
  main()

