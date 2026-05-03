from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Organization(db.Model):
    __tablename__ = "organizations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    developers = db.relationship("Developer", backref="organization", lazy=True)


class Developer(db.Model):
    __tablename__ = "developers"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="developer")
    tos_accepted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificates = db.relationship("Certificate", backref="developer", lazy=True)


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(64), unique=True, nullable=False)
    developer_id = db.Column(db.Integer, db.ForeignKey("developers.id"), nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    key_source = db.Column(db.String(20), nullable=False, default="uploaded")
    certificate_pem = db.Column(db.Text, nullable=False)
    issued_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(255), nullable=True)