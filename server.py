#!/usr/bin/env python3

import socket
from random import randbytes
from time import sleep
from hashlib import sha384
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import hmac

from utils import ByteReader, ByteWriter

from x25519 import multscalar
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

        key_share_ext = KeyShareExtension.from_bytes(client_key_share.data)
        client_pub_key = next((entry for entry in key_share_ext.entries if entry.group == 29), None)

        if client_pub_key is None:
          print("Handshake does not contain the x25519 Key Share Entry")
          return

        client_pub_key = client_pub_key.key

        print(f"Client's public key: 0x{client_pub_key[:8].hex()} ...", end="\n\n")

        # server key exchange generation
        key = KeyShareEntry(group=29, key=randbytes(32))
        print(key, end="\n\n")

        # server hello
        server_hello = Handshake(
          type=HandshakeType.SERVER_HELLO,
          version=HandshakeVersion.TLS_1_2,
          random=randbytes(32),
          session_id=handshake.session_id,
          cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384],
          compression_methods=[0],
          extensions=[
            HandshakeExtension(type=HandshakeExtensionType.KEY_SHARE, data=key.to_bytes()),
            HandshakeExtension(type=HandshakeExtensionType.SUPPORTED_VERSIONS, data=HandshakeVersion.TLS_1_3.to_bytes(2))
          ]
        )

        server_hello_record = Record(
          RecordContentType.HANDSHAKE,
          RecordVersion.TLS_1_2,
          server_hello.to_bytes()
        )

        # server handshake keys calc
        handshakes_hash = bytes.fromhex(sha384(record.to_bytes()[5:] + server_hello_record.to_bytes()[5:]).hexdigest())
        shared_secret = bytes.fromhex(''.join([str(hex(ord(char))[2:]).zfill(2) for char in multscalar(key.key, client_pub_key)]))
        zero_key = bytes.fromhex("0" * 96)
        early_secret = hkdf_extract(bytes.fromhex("00"), zero_key, hash=sha384)
        empty_hash = bytes.fromhex(sha384("".encode()).hexdigest())
        derived_secret = hkdf_expand_label(early_secret, label="derived".encode(), hash_value=empty_hash, length=48, hash=sha384)
        handshake_secret = hkdf_extract(derived_secret, shared_secret, hash=sha384)
        ssecret = hkdf_expand_label(handshake_secret, label="s hs traffic".encode(), hash_value=handshakes_hash, length=48, hash=sha384)
        server_handshake_key = hkdf_expand_label(ssecret, label="key".encode(), hash_value="".encode(), length=32, hash=sha384)
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
        certificate = bytes.fromhex("3082056130820349a003020102021468bce59c2acde12367446ea82f8a4ea8d07cbcb9300d06092a864886f70d01010b05003040310b300906035504061302504c310f300d06035504070c064b72616b6f77310c300a060355040a0c034147483112301006035504030c096c6f63616c686f7374301e170d3234303533313230313035315a170d3334303532393230313035315a3040310b300906035504061302504c310f300d06035504070c064b72616b6f77310c300a060355040a0c034147483112301006035504030c096c6f63616c686f737430820222300d06092a864886f70d01010105000382020f003082020a02820201009afda8f6965993bf7758a08a2bcf5fa249f6cc988c341d1b864a052f3debd76fce215fd9b2d8b1002e116c369d1d25b58a1e1c9fdc54077128856024c3fe3fc6671cbb9feb8eef55d36f7221e34a2241959b6204dff2cc93ca25bc97ae6334f6569cbbfbfb5cbc431100b61809cd711696fcf1eb19ac7f5a1c1833ca4959c4bbe6f8424981c1d00b65228ddcbabe0e10d5b68ea37b4d39c54a489b3ca2c50805f715b4696fe0cc65fdb170672dda08d5995a799a0fd2f209d03c2766bb7ad4045d280fcf92307830d31d6ef3a681e09905646ab92bd466936914b275241822eba8b98a4383e19bdfbd6e13675a69c61d2a1f699e88ecb3a434decdd68690c9c18dcca81cadfd37151d416828a4112df4160f1978a8b4941bc9ce9b38e39cacc5f43d13b25f3b965436b5748ffe9ccc05c2b2de80221d607cf007ec1565260d0f41a17688205bf92d68602ab3b1c2820fe70e59c98b99fbfdf056e2acdad8ae532976c9b1318ef740249308b36fbf07d43cc587b7bbb92440cde62ed56d85d8b70e47806a1e2dd4e5b1d0b9fe9bd324f9172115d95b4e9fb1e62073d79b02a8e2725a997290c33af4f139aa6595616b95c2103feab38ac4d53894388657dca2be2c986d42bc52aaf191ddc0c7ba596b62d35a13278df0925b78446bb4b25145be3f086991afef580e1539dcd531c55c7554c8ce1f80181486bfc5d99aefd27ab50203010001a3533051301d0603551d0e041604146bfc50bdad75ad3d4efe7760dbf8969f3b809d5d301f0603551d230418301680146bfc50bdad75ad3d4efe7760dbf8969f3b809d5d300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038202010000855b6306bd9d861b31c376c41168642f76f9ed3d32778831855436826eac7888aa0b5a0752eee558532acd93b90f6b82b68711d7a16a00791fb3b1f321d54d234b46efcedf8a525916a0e1b738055d097b5949b66db20666f024e02643ab9a3df2d30ee59405f5198a5cd3794f6a0a2a162d0ea173427f63014f06c445d85d4b1a8a026afce2f8b3d4c2fe1c32a8ad27577751abfd719ec2e5d13bc1713e696a69566a5d53871233a6f89817cdbb934091928876b88fd1fbab419bc413023da2ddadd35b3037366e6166dcfd9aadd7e4bea93be9a4d1c50947ec1a1e9c20767010c99763be82f7b0db350aea7c1f62e9c31f6647411893d5e462b2b1c4a9e2befc3b9a75bbab09321a354d117201e17c3a7cca243933e8bfc84b061ae64fb87de3f07782b1e56d305f29474346efa37f839aa05c3ae7231025b80b78d63d0abf458685048ea003c74442bce679c328e30de69ccfd27844833870a01da3614b7a3febc9f9c5603b1ab1f4b09f3a284c2e7326d712f14c1020581b4ae78e8f3e0ca1b1cb9f9899a7856b790daea2aac206a30728da7345fb96294d716236db64ffb93bb0ccfa662bc9e3d229f7e173d90795b0acae076c015024a932852713a4fca621c58c81cd93ee422eee0d6146630b5e28e603598a762bf4614166945cce8ff331da9b78165eda3072e9ccaf8bd3d9eb6b6ace602de69f39b76b17a50f89")
        # openssl x509 -outform der < cert.pem | xxd -p -c 1000000

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
        cert_private_key = RSA.import_key(open("certs/key.pem", "rb").read())
        h = SHA256.new(handshakes_hash)
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
        finished_hash = bytes.fromhex(sha384(record.data[5:] + server_hello_record.to_bytes()[5:] + encrypted_extensions_record[1:] + 
                                             server_certificate_record[1:] + certificate_verify_record[1:]).hexdigest())
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
        record = Record.from_bytes(data[6:])  # "hidden" application data
        print(record, end="\n\n")

        encrypted_data = record.data[:-16]
        auth_tag = record.data[-16:]

        print(f"client_application_key: {client_application_key.hex()}")
        print(f"client_application_iv: {client_application_iv.hex()}")
        print(f"encrypted_data: {encrypted_data.hex()}")
        print(f"auth_tag: {auth_tag.hex()}")

        cipher = AES.new(client_application_key, AES.MODE_GCM, (int.from_bytes(client_application_iv) ^ 0).to_bytes(12))
        cipher.update(record.to_bytes()[:5])

        try:
          message = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        except ValueError:
          print("The message was modified!")
          continue

        print(f"Decrypted message: {message}")
      elif record.content_type == RecordContentType.ALERT:  # alert
        continue
      elif record.content_type == RecordContentType.APPLICATION_DATA:  # application data:
        continue

if __name__ == "__main__":
  main()

