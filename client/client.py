#!/usr/bin/env python3

import asyncio
import json
import sys
import argparse
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils, padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from datetime import datetime

SERVER_HOST = "localhost"
SERVER_NAME = "TimestaMPC"
SERVER_PORT = 15555
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
    def __init__(self, hostname: str, port: int) -> None:
        self.hostname = hostname
        self.port = port

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            self.hostname, self.port
        )

    def send_data(self, data: str) -> None:
        self.writer.write(data.encode())

    async def receive_data(self) -> str:
        return (await self.reader.read(BUFFER_SIZE)).decode()

    def close(self) -> None:
        self.writer.close()


def hash_document(filename: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    with open(filename, "r") as f:
        for line in f:
            digest.update(line.encode())
    return digest.finalize()


async def sign_document(client: TMPCClient, filename: str) -> None:
    await client.connect()
    document_hash = b64encode(hash_document(filename)).decode()
    client.send_data(
        json.dumps(
            {
                "command": "sign",
                "data": document_hash
            }
        )
    )
    resp = await client.receive_data()
    resp_json = json.loads(resp)
    print(json.dumps(resp_json, indent=4))


def verify_certificate(
    name: str,
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate
) -> bool:
    # Check the signature in the certificate
    try:
        ca_certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
    except InvalidSignature:
        print("invalid signature in the certificate")
        return False

    # Check the name, it must match the given one
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if name not in [n.value for n in names]:
        print("invalid name in the certificate")
        return False

    # Check the time validity
    if certificate.not_valid_after < datetime.now():
        print("certificate is expired")
        return False

    if certificate.not_valid_before > datetime.now():
        print("certificate is not yet valid")
        return False

    return True


def verify_signature(document_filename: str, response) -> None:
    # We will need the CA public key to verify the received certificate
    ca_certificate = x509.load_pem_x509_certificate(CA_CERTIFICATE)

    if "certificate" not in response:
        print("no certificate in the response")
        return

    certificate = x509.load_pem_x509_certificate(
        response["certificate"].encode()
    )

    # Verify that the received certificate is valid
    if not verify_certificate(SERVER_NAME, certificate, ca_certificate):
        print("certificate invalid")
        return
    print("certificate valid")

    if "timestamp" not in response:
        print("no timestamp in the response")
        return

    # The signature should be done on H(H(document) || timestamp)
    document_hash = hash_document(document_filename)
    data_to_verify = document_hash + response["timestamp"].encode()

    if "signature" not in response:
        print("no signature in the response")
        return

    # Load the signature from the received raw format
    signature_raw = b64decode(response["signature"].encode())
    r = int.from_bytes(signature_raw[:32], byteorder="big")
    s = int.from_bytes(signature_raw[32:], byteorder="big")
    signature = utils.encode_dss_signature(r, s)

    # Verify that the signature is valid
    try:
        certificate.public_key().verify(
            signature, data_to_verify, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        print("signature invalid")
        return
    print("signature valid")

    # If valid, print the received timestamp and signature
    unix_timestamp = int(response["timestamp"])
    print("timestamp: {}".format(datetime.fromtimestamp(unix_timestamp)))
    print("signature: {}".format(response["signature"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("document_file")
    args = parser.parse_args()

    if args.command == "sign":
        client = TMPCClient(SERVER_HOST, SERVER_PORT)
        try:
            asyncio.run(sign_document(client, args.document_file))
        except OSError:
            print("could not connect to the server")
        return

    if args.command == "verify":
        try:
            response = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("the response does not contain valid JSON data")
            return
        verify_signature(args.document_file, response)
        return


if __name__ == "__main__":
    main()
