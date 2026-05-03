import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)

CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_ca")
CA_KEY_PATH = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CA_DIR, "ca_cert.pem")

CERT_VALIDITY_DAYS = 90

DEVELOPER_ROLE_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")

def init_ca():
    os.makedirs(CA_DIR, exist_ok=True)

    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        print("Dev CA already exists, skipping generation.")
        return

    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Starforge Robotics Developer CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Starforge Robotics Developer CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    os.chmod(CA_KEY_PATH, 0o600)

    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    fingerprint = ca_cert.fingerprint(hashes.SHA256()).hex(":")
    print(f"Dev CA created. Fingerprint (SHA-256): {fingerprint}")


def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


MAX_PEM_SIZE = 1024

def sign_developer_cert(public_key_pem, developer_name, org_name, developer_id):
    if len(public_key_pem.encode()) > MAX_PEM_SIZE:
        raise ValueError("Public key PEM exceeds maximum allowed size of 1 KiB")

    dev_pubkey = serialization.load_pem_public_key(public_key_pem.encode())

    if not isinstance(dev_pubkey, ec.EllipticCurvePublicKey):
        raise ValueError("Only ECDSA keys are accepted")
    if not isinstance(dev_pubkey.curve, ec.SECP256R1):
        raise ValueError("Only P-256 (secp256r1) curve is accepted")

    ca_key, ca_cert = load_ca()

    serial = x509.random_serial_number()

    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, developer_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.USER_ID, str(developer_id)),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(dev_pubkey)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
            ]),
            critical=False
        )
        .add_extension(
            x509.UnrecognizedExtension(DEVELOPER_ROLE_OID, b"developer"),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = format(serial, "x")

    return cert_pem, serial_hex, cert.not_valid_after_utc

def generate_crl(revoked_certs):
    ca_key, ca_cert = load_ca()

    now = datetime.now(timezone.utc)
    builder = CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=1))

    for cert_record in revoked_certs:
        serial = int(cert_record.serial_number, 16)
        revoked_at = cert_record.revoked_at or now

        revoked_builder = RevokedCertificateBuilder()
        revoked_builder = revoked_builder.serial_number(serial)
        revoked_builder = revoked_builder.revocation_date(revoked_at)

        reason_map = {
            "key_compromise": x509.ReasonFlags.key_compromise,
            "developer_removed": x509.ReasonFlags.affiliation_changed,
            "org_suspended": x509.ReasonFlags.cessation_of_operation,
            "admin_action": x509.ReasonFlags.unspecified,
        }

        reason_flag = reason_map.get(
            cert_record.revocation_reason, x509.ReasonFlags.unspecified
        )

        revoked_builder = revoked_builder.add_extension(
            x509.CRLReason(reason_flag), critical=False
        )

        builder = builder.add_revoked_certificate(revoked_builder.build())

    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


def get_ca_cert_pem():
    with open(CA_CERT_PATH, "r") as f:
        return f.read()
    

def get_ca_cert_info():
    _, ca_cert = load_ca()
    pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = ca_cert.fingerprint(hashes.SHA256()).hex(":")
    subject = ca_cert.subject.rfc4514_string()
    expires_at = ca_cert.not_valid_after_utc.isoformat()
    return {
        "certificate_pem": pem,
        "subject": subject,
        "fingerprint_sha256": fingerprint,
        "expires_at": expires_at,
    }