# Working implementation using payloads from https://tls13.xargs.org
from hashlib import sha384
from Crypto.Cipher import AES
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


record = Record.from_bytes(bytes.fromhex("16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"))

handshake = Handshake.from_bytes(record.data)
print(handshake, end="\n\n")

if CipherSuite.TLS_AES_256_GCM_SHA384 not in handshake.cipher_suites:
    print("TLS_AES_256_GCM_SHA384 Cipher Suite is not supported, aborting", end="\n\n")
    exit(1)

# read the client's public key
client_key_share = next((ext for ext in handshake.extensions if ext.type == HandshakeExtensionType.KEY_SHARE), None)
if client_key_share is None:
    print("Client Hello does not contain the Key Share extension, aborting", end="\n\n")
    exit(1)

client_key_share_ext = KeyShareExtension.from_bytes(client_key_share.data)
client_pub_key = next((entry for entry in client_key_share_ext.entries if entry.group == 29), None)

if client_pub_key is None:
    print("Handshake does not contain the x25519 Key Share Entry")
    exit(1)

client_pub_key = client_pub_key.key

print(f"Client's public key: 0x{client_pub_key[:8].hex()} ...", end="\n\n")

# server key exchange generation
server_priv_key_entry = KeyShareEntry(group=29, key=bytes.fromhex("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
print(f"Server Private Key:\n{server_priv_key_entry}", end="\n\n")

server_pub_key = bytes.fromhex(''.join([str(hex(ord(char))[2:]).zfill(2) for char in base_point_mult(server_priv_key_entry.key)]))
server_pub_key_entry = KeyShareEntry(group=29, key=server_pub_key)
print(f"Server Public Key:\n{server_pub_key_entry}", end="\n\n")

# server hello
server_hello = Handshake(
    type=HandshakeType.SERVER_HELLO,
    version=HandshakeVersion.TLS_1_2,
    random=bytes.fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
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
certificate = bytes.fromhex("3082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a0")

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
# cert_private_key = RSA.import_key(open("certs/key.pem", "rb").read())
# h = SHA256.new(handshakes_hash)
# signature = pss.new(cert_private_key).sign(h)

signature = bytes.fromhex("5cbb24c0409332daa920bbabbdb9bd50170be49cfbe0a4107fca6ffb1068e65f969e6de7d4f9e56038d67c69c031403a7a7c0bcc8683e65721a0c72cc6634019ad1d3ad265a812615ba36380372084f5daec7e63d3f4933f27227419a611034644dcdbc7be3e74ffac473faaadde8c2fc65f3265773e7e62de33861fa705d19c506e896c8d82f5bcf35fece259b71538115e9c8cfba62e49bb8474f58587b11b8ae317c633e9c76c791d466284ad9c4ff735a6d2e963b59bbca440a307091a1b4e46bcc7a2f9fb2f1c898ecb19918be4121d7e8ed04cd50c9a59e987980107bbbf299c232e7fdbe10a4cfdae5c891c96afdff94b54ccd2bc19d3cdaa6644859c")

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
# client.send(server_hello_record.to_bytes() + server_change_cipher_spec_record.to_bytes())

print("Sending Wrapped Records: Encrypted Extensions, Server Certificate, Certificate Verify, Server Handshake Finished...", end="\n\n")
# client.send(encrypted_extensions_record + server_certificate_record + certificate_verify_record + server_handshake_finished_record)

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

print(f"server_application_key: {server_application_key.hex()}")
print(f"server_application_iv: {server_application_iv.hex()}")

print(f"client_application_key: {client_application_key.hex()}")
print(f"client_application_iv: {client_application_iv.hex()}")