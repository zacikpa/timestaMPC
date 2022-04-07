from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

CA_PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
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
/n1pERiA/Enays7z8C6W6jlbPGUY2Q==
-----END PRIVATE KEY-----
"""

CA_CERTIFICATE = """
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


def issue_cert(name, public_key):
    ca_private_key = serialization.load_pem_public_key(CA_PRIVATE_KEY)
    ca_cert = x509.load_pem_x509_certificate(CA_CERTIFICATE)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).public_key(
        public_key
    ).issuer_name(
        ca_cert.issuer
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(
        ca_private_key, hashes.SHA256()
    )
    return cert
