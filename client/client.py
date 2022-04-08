#!/usr/bin/env python3

import asyncio
import json
import sys
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils, padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from datetime import datetime


BUFFER_SIZE = 2000
CA_CERTIFICATE = b"""
-----BEGIN CERTIFICATE-----
MIIEsjCCApqgAwIBAgIUbWCkd8cQetL3zu4gf3YzoHHHmC0wDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIUFYyMDQgQ0EwHhcNMjIwNDA3MTkxMzAyWhcNMjMwNDA3
MTkxMzAyWjATMREwDwYDVQQDDAhQVjIwNCBDQTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAK9jhuIpv1eAN/2bUNWdmqbY8YanVfeBKqnnTfErCKZ2dZHF
RqSAC8pCsjsiGwuX/FBpwosHHqLk4MAD0nmVs9mCxPgy4yPk4D9iH301c/RU3Xn/
Cw29dmOUOi8B5QYgycu3A+cQSWh3AOumxuFt77nyssbqwMb2umwweXPRFd2DCuCN
pqFeiuyA4GZVEZ3J4UD7w2VgWcT9bubDlULIFUJwRrThoZ+S3VvIf7K8sgiZZox1
sBvO5B8st5f4SYer6Y6GwSjOFol8OlTGxlvZgHMS1XZTHV1unDb6pKdwHaps0As6
a9Cgmfr5lbPaqGCT6/nNimSuhYgvX/YiQeifvxyBN9+e0m98P11Tu7R0CA2fWTUj
yuN9QDTCUbjBSlTXolIaaUsKQRVHmu3isAbmAnc4c6jBP6aLLKVv8jDJmNB+J1VA
9WK8QXMim0q1WirKEgkZmSBAr1j9kCGxGM2l4z32kPSXJfXb//OVxqFjLUHQsdlP
NnsNisjhYbm8sO2kLEK2th1xtBreG/bWAeQLTh3pgfCg3TIE420Eefq6BQ5bla5S
7jULzlvfQrUHDV1WPjW9X5ag1TLjzPnRgZ46fzwJS/Sa1PIAu0Kmg4MSrRBE0UeF
GnAE3JnOGysrbvNYinzPbkvtUFYZoLIhQmDbRLzcx4cGzAxRizJpnePW1mQ9AgMB
AAEwDQYJKoZIhvcNAQELBQADggIBAHLhPStY8ucz7URT2/VxRpdSnP84qTllIJKg
Gt55BetSF71Sb9S6XkqucLTlTrUHIMdAEyK4oLdnmOfAvSUSpZt4c0+IzK7uZpva
RGhIrZGXKlNS60qcKO6UKAf6uFeLpDoOYL7vv75Auc03KcbbdRrm0QhheuT49jLB
+MmcGnm7JpPuQDzGnGLgbEP6GK5DXz6YpcydXULsjpL1Y/fKadYPxgeU+yVKfciL
+SjA30nSEE3cBKxJkPqIEKk0izUT8mVuT97hwFvS98GcoC3lRQlMMKyVnu2/V3zv
m4BtS7R5yn6qCD4ZJHHKr9iFf209WK00zCQrQNhunshUGFJUKG7mduBci6VygCDW
26WtXE5ZkbRQsZ5yadSgTkFCab+nPxiFEn4ijFhcQ4Xip294xH5SKCDiuDOfbKb9
5FtXmrh0OkuWqiwZldCHiXJBChyiWA3XfDe9LzslsODmbbYWP1kH25TQYfPNPbmn
XhgJDythaNR62ydN/WTuKvDVibVHo3QEx0KQ0gkwVpd2xsOr16rk+S7/9+XECX9k
5yIxmhX42fYNiX9CNcIKTg60FfQtditxhi0dKyFB3AaR/I5aIGqEA0Rah1CtOqcO
JrV/yAFGzOZrE1tAIpwbaBF5OzWtRgeUrvUU0JLujsqCAirtYRWL4+DPPNQOTaWW
a/AEwkAi
-----END CERTIFICATE-----
"""


class TMPCClient:
    def __init__(self, hostname, port) -> None:
        self.hostname = hostname
        self.port = port

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.hostname, self.port
        )

    def send_data(self, data):
        self.writer.write(bytes(data, encoding="utf-8"))

    async def receive_data(self):
        return (await self.reader.read(BUFFER_SIZE)).decode()

    def close(self):
        self.writer.close()


def hash_document(filename: str) -> str:
    digest = hashes.Hash(hashes.SHA3_256())
    with open(filename, "r") as f:
        for line in f:
            digest.update(line.encode("utf-8"))

    return digest.finalize()


async def sign_document(client: TMPCClient, filename: str):
    await client.connect()
    hash_of_document = b64encode(hash_document(filename)).decode()
    client.send_data(json.dumps({"command": "sign", "data": hash_of_document}))
    resp = await client.receive_data()
    print(resp)


def verify_certificate(name, certificate, ca_certificate):
    # Check the signature
    try:
        ca_certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
    except InvalidSignature:
        return False

    # Check the name
    common_names = [name.value for name in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if name not in common_names:
        return False

    # Check the time validity
    if certificate.not_valid_after < datetime.now() or certificate.not_valid_before > datetime.now():
        return False

    return True


def verify_signature(filename: str, response_filename: str):
    with open(response_filename) as f:
        response = json.load(f)

    ca_certificate = x509.load_pem_x509_certificate(CA_CERTIFICATE)
    certificate = x509.load_pem_x509_certificate(response.get("certificate").encode())

    data_to_verify = hash_document(filename) + response.get("timestamp").encode()

    if not verify_certificate("TimestaMPC", certificate, ca_certificate):
        print("certificate invalid")
        return
    print("certificate valid")

    signature_raw = b64decode(response.get("signature").encode())
    r = int.from_bytes(signature_raw[:32], byteorder="big")
    s = int.from_bytes(signature_raw[32:], byteorder="big")
    signature = utils.encode_dss_signature(r, s)

    try:
        certificate.public_key().verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("signature invalid")
        return
    print("signature valid")

    unix_timestamp = int(response.get("timestamp"))
    print("timestamp: {}".format(datetime.fromtimestamp(unix_timestamp)))


def main():
    if len(sys.argv) == 3:
        _, _, filename = sys.argv
        client = TMPCClient("localhost", 15555)
        asyncio.run(sign_document(client, filename))
    elif len(sys.argv) == 4:
        _, _, filename, response_file = sys.argv
        verify_signature(filename, response_file)
    else:
        print(
            "USAGE: ./client.py sign filename\n      ./client.py verify filename response_file"
        )


if __name__ == "__main__":
    main()
