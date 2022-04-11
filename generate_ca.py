from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--ca-key", default="ca_key.pem")
parser.add_argument("--ca-cert", default="ca_cert.pem")
args = parser.parse_args()

private_key = rsa.generate_private_key(65537, 4096)
private_key_pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption()
)

with open(args.ca_key, "wb") as private_key_file:
    private_key_file.write(private_key_pem)

subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"PV204 CA")])
cert = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).public_key(
        private_key.public_key()
    ).issuer_name(
        issuer
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(
        private_key, hashes.SHA256()
    )

with open(args.ca_cert, "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
