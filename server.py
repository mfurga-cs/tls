#!/usr/bin/env python3

import socket
from random import randbytes
from time import sleep
from hashlib import sha384
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from OpenSSL import crypto
import hmac

from utils import ByteWriter

from x25519 import multscalar, base_point_mult
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
PORT = 443

CRT_PATH = "newcerts/agh.edu.pl.crt"
KEY_PATH = "newcerts/priv.pem"

def main() -> None:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen(5)

  print(f"Start listening on https://{HOST}:{PORT} ...", end="\n\n")

  while True:
    client, _ = s.accept()
    print("Accepted a new client", end="\n\n")

    while True:
      try:
        data = client.recv(16 * 1024)

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

        client_key_share_ext = KeyShareExtension.from_bytes(client_key_share.data)
        client_pub_key = next((entry for entry in client_key_share_ext.entries if entry.group == 29), None)

        if client_pub_key is None:
          print("Handshake does not contain the x25519 Key Share Entry")
          return

        client_pub_key = client_pub_key.key

        print(f"Client's public key: 0x{client_pub_key[:8].hex()} ...", end="\n\n")

        # server key exchange generation
        server_priv_key_entry = KeyShareEntry(group=29, key=randbytes(32))
        print(f"Server Private Key:\n{server_priv_key_entry}", end="\n\n")

        server_pub_key = bytes.fromhex(''.join([str(hex(ord(char))[2:]).zfill(2) for char in base_point_mult(server_priv_key_entry.key)]))
        server_pub_key_entry = KeyShareEntry(group=29, key=server_pub_key)
        print(f"Server Public Key:\n{server_pub_key_entry}", end="\n\n")

        # server hello
        server_hello = Handshake(
          type=HandshakeType.SERVER_HELLO,
          version=HandshakeVersion.TLS_1_2,
          random=randbytes(32),
          session_id=handshake.session_id,
          cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
          compression_methods=[0],
          extensions=[
            HandshakeExtension(type=HandshakeExtensionType.SUPPORTED_VERSIONS, data=HandshakeVersion.TLS_1_3.to_bytes(2)),
            HandshakeExtension(type=HandshakeExtensionType.KEY_SHARE, data=server_pub_key_entry.to_bytes())
          ]
        )

        server_hello_record = Record(
          RecordContentType.HANDSHAKE,
          RecordVersion.TLS_1_2,
          server_hello.to_bytes()
        )

        # server handshake keys calc
        handshakes_hash = bytes.fromhex(sha384(record.to_bytes()[5:] + server_hello_record.to_bytes()[5:]).hexdigest())
        shared_secret = bytes.fromhex(''.join([str(hex(ord(char))[2:]).zfill(2) for char in multscalar(server_priv_key_entry.key, client_pub_key)]))
        zero_key = bytes.fromhex("0" * 96)
        early_secret = hkdf_extract(bytes.fromhex("00"), zero_key, hash=sha384)
        empty_hash = bytes.fromhex(sha384("".encode()).hexdigest())
        derived_secret = hkdf_expand_label(early_secret, label="derived".encode(), hash_value=empty_hash, length=48, hash=sha384)
        handshake_secret = hkdf_extract(derived_secret, shared_secret, hash=sha384)
        csecret = hkdf_expand_label(handshake_secret, label="c hs traffic".encode(), hash_value=handshakes_hash, length=48, hash=sha384)
        ssecret = hkdf_expand_label(handshake_secret, label="s hs traffic".encode(), hash_value=handshakes_hash, length=48, hash=sha384)
        client_handshake_key = hkdf_expand_label(csecret, label="key".encode(), hash_value="".encode(), length=32, hash=sha384)
        server_handshake_key = hkdf_expand_label(ssecret, label="key".encode(), hash_value="".encode(), length=32, hash=sha384)
        client_handshake_iv = hkdf_expand_label(csecret, label="iv".encode(), hash_value="".encode(), length=12, hash=sha384)
        server_handshake_iv = hkdf_expand_label(ssecret, label="iv".encode(), hash_value="".encode(), length=12, hash=sha384)

        # server change cipher spec
        server_change_cipher_spec = 0x01

        server_change_cipher_spec_record = Record(
          RecordContentType.CHANGE_CIPHER_SPEC,
          RecordVersion.TLS_1_2,
          server_change_cipher_spec.to_bytes()
        )

        # print("Sending Server Hello and Server Change Cipher Spec...", end="\n\n")
        # client.send(server_hello_record.to_bytes() + server_change_cipher_spec_record.to_bytes())

        # wrapped record: encrypted extensions
        record_header = RecordContentType.APPLICATION_DATA.value.to_bytes() + RecordVersion.TLS_1_2.value.to_bytes(2) + (7 + 16).to_bytes(2)

        extra_extensions = bytes.fromhex("080000020000")

        cipher = AES.new(server_handshake_key, AES.MODE_GCM, (int.from_bytes(server_handshake_iv) ^ 0).to_bytes(12))  # XOR with 0 (the first encrypted record)
        cipher.update(record_header)
        extra_extensions_encrypted, mac_tag = cipher.encrypt_and_digest(extra_extensions + b'\x16')

        encrypted_extensions_record = record_header + extra_extensions_encrypted + mac_tag

        # wrapped record: server certificate
        # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=PL/L=Krakow/O=AGH/CN=localhost"
        # openssl x509 -outform der < cert.pem | xxd -p -c 1000000
        cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, open(CRT_PATH).read())
        certificate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_pem)
        
        record_header = RecordContentType.APPLICATION_DATA.value.to_bytes() + RecordVersion.TLS_1_2.value.to_bytes(2) + (13 + len(certificate) + 1 + 16).to_bytes(2)

        writer = ByteWriter()

        writer.write_u8(HandshakeType.CERTIFICATE)  # handshake type
        writer.write_u24(1 + 3 + 3 + len(certificate) + 2)  # length of the data
        writer.write_u8(0x00)  # request context
        writer.write_u24(3 + len(certificate) + 2)  # length of certificates
        writer.write_u24(len(certificate))  # length of the first (and only) certificate
        writer.write_bytes(certificate)  # certificate
        writer.write_u16(0x0000)  # certificate extensions

        server_certificate = writer.data

        cipher = AES.new(server_handshake_key, AES.MODE_GCM, (int.from_bytes(server_handshake_iv) ^ 1).to_bytes(12))  # XOR with 1 (the second encrypted record)
        cipher.update(record_header)
        server_certificate_encrypted, mac_tag = cipher.encrypt_and_digest(server_certificate + b'\x16')

        server_certificate_record = record_header + server_certificate_encrypted + mac_tag

        # wrapped record: certificate verify
        handshakes_hash = bytes.fromhex(sha384(record.to_bytes()[5:] + server_hello_record.to_bytes()[5:] + extra_extensions + server_certificate).hexdigest())
        cert_private_key = RSA.import_key(open(KEY_PATH, "rb").read())  # key.pem
        h = SHA256.new(b'\x20' * 64 + "TLS 1.3, server CertificateVerify".encode() + b'\x00' + handshakes_hash)
        signature = pss.new(cert_private_key).sign(h)

        certificate_verify = HandshakeType.CERTIFICATE_VERIFY.value.to_bytes() + (2 + 2 + len(signature)).to_bytes(3)
        certificate_verify += 0x0804.to_bytes(2)  # reserved value for RSA-PSS-RSAE-SHA256 signature
        certificate_verify += len(signature).to_bytes(2)  # length of the signature
        certificate_verify += signature

        record_header = RecordContentType.APPLICATION_DATA.value.to_bytes() + RecordVersion.TLS_1_2.value.to_bytes(2) + (len(certificate_verify) + 1 + 16).to_bytes(2)

        cipher = AES.new(server_handshake_key, AES.MODE_GCM, (int.from_bytes(server_handshake_iv) ^ 2).to_bytes(12))  # XOR with 2 (the third encrypted record)
        cipher.update(record_header)
        certificate_verify_encrypted, mac_tag = cipher.encrypt_and_digest(certificate_verify + b'\x16')

        certificate_verify_record = record_header + certificate_verify_encrypted + mac_tag

        # wrapped record: server handshake finished
        finished_key = hkdf_expand_label(ssecret, label="finished".encode(), hash_value="".encode(), length=48, hash=sha384)
        finished_hash = bytes.fromhex(sha384(record.to_bytes()[5:] + server_hello_record.to_bytes()[5:] + extra_extensions + 
                                             server_certificate + certificate_verify).hexdigest())
        verify_data = bytes.fromhex(hmac.new(finished_key, finished_hash, sha384).hexdigest())

        server_handshake_finished = HandshakeType.FINISHED.value.to_bytes() + len(verify_data).to_bytes(3) + verify_data

        record_header = RecordContentType.APPLICATION_DATA.value.to_bytes() + RecordVersion.TLS_1_2.value.to_bytes(2) + (len(server_handshake_finished) + 1 + 16).to_bytes(2)

        cipher = AES.new(server_handshake_key, AES.MODE_GCM, (int.from_bytes(server_handshake_iv) ^ 3).to_bytes(12))  # XOR with 3 (the forth encrypted record)
        cipher.update(record_header)
        server_handshake_finished_encrypted, mac_tag = cipher.encrypt_and_digest(server_handshake_finished + b'\x16')

        server_handshake_finished_record = record_header + server_handshake_finished_encrypted + mac_tag

        print("Sending Server Hello and Server Change Cipher Spec...", end="\n\n")
        client.send(server_hello_record.to_bytes() + server_change_cipher_spec_record.to_bytes())

        print("Sending Wrapped Records: Encrypted Extensions, Server Certificate, Certificate Verify, Server Handshake Finished...", end="\n\n")
        client.send(encrypted_extensions_record + server_certificate_record + certificate_verify_record + server_handshake_finished_record)

        # server application keys calc
        handshakes_hash = bytes.fromhex(sha384(record.to_bytes()[5:] + server_hello_record.to_bytes()[5:] + extra_extensions + 
                                               server_certificate + certificate_verify + server_handshake_finished).hexdigest())
        empty_hash = bytes.fromhex(sha384("".encode()).hexdigest())
        zero_key = bytes.fromhex("0" * 96)
        derived_secret = hkdf_expand_label(handshake_secret, label="derived".encode(), hash_value=empty_hash, length=48, hash=sha384)
        master_secret = hkdf_extract(derived_secret, zero_key, hash=sha384)
        client_secret = hkdf_expand_label(master_secret, label="c ap traffic".encode(), hash_value=handshakes_hash, length=48, hash=sha384)
        server_secret = hkdf_expand_label(master_secret, label="s ap traffic".encode(), hash_value=handshakes_hash, length=48, hash=sha384)
        client_application_key = hkdf_expand_label(client_secret, label="key".encode(), hash_value="".encode(), length=32, hash=sha384)
        server_application_key = hkdf_expand_label(server_secret, label="key".encode(), hash_value="".encode(), length=32, hash=sha384)
        client_application_iv = hkdf_expand_label(client_secret, label="iv".encode(), hash_value="".encode(), length=12, hash=sha384)
        server_application_iv = hkdf_expand_label(server_secret, label="iv".encode(), hash_value="".encode(), length=12, hash=sha384)
      elif record.content_type == RecordContentType.CHANGE_CIPHER_SPEC:  # client change cipher spec
        record = Record.from_bytes(data[6:])  # additional data after client 
        print(record, end="\n\n")

        encrypted_data = record.data[:-16]
        auth_tag = record.data[-16:]

        cipher = AES.new(client_handshake_key, AES.MODE_GCM, (int.from_bytes(client_handshake_iv) ^ 0).to_bytes(12))
        cipher.update(record.to_bytes()[:5])

        try:
          message = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        except ValueError:
          print("The message was modified!")
          continue

        print(f"Decrypted message: {message.hex()}")
      elif record.content_type == RecordContentType.ALERT:  # alert
        continue
      elif record.content_type == RecordContentType.APPLICATION_DATA:  # application data:
        # read GET HTTP request
        encrypted_data = record.data[:-16]
        auth_tag = record.data[-16:]

        cipher = AES.new(client_application_key, AES.MODE_GCM, (int.from_bytes(client_application_iv) ^ 0).to_bytes(12))
        cipher.update(record.to_bytes()[:5])

        try:
          message = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        except ValueError:
          print("The message was modified!")
          continue

        print(f"Decrypted message: {message}")

        # send a simple HTTP response
        http_response = "HTTP/1.0 200 OK\nContent-Type: text/html; charset=utf-8\n\n <h1><b>💩</b></h1> \n\n".encode()

        record_header = RecordContentType.APPLICATION_DATA.value.to_bytes() + RecordVersion.TLS_1_2.value.to_bytes(2) + (len(http_response) + 1 + 16).to_bytes(2)

        cipher = AES.new(server_application_key, AES.MODE_GCM, (int.from_bytes(server_application_iv) ^ 0).to_bytes(12))  # XOR with 0 (the first encrypted application data)
        cipher.update(record_header)
        http_response_encrypted, mac_tag = cipher.encrypt_and_digest(http_response + b'\x17')

        http_response_record = record_header + http_response_encrypted + mac_tag

        print(f"Sending a simple HTTP response...", end="\n\n")
        client.send(http_response_record)

        exit(0)

if __name__ == "__main__":
  main()

