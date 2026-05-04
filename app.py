import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify, g, render_template, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, Organization, Developer, Certificate
from auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    login_required,
)
from cert_service import sign_developer_cert, generate_crl, get_ca_cert_pem, get_ca_cert_info

app = Flask(__name__)


def _build_db_uri() -> str:
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    db_host = os.environ.get("DB_HOST")
    if db_host:
        user = os.environ.get("DB_USER", "")
        password = os.environ.get("DB_PASSWORD", "")
        name = os.environ.get("DB_NAME", "")
        port = os.environ.get("DB_PORT", "5432")
        return f"postgresql+psycopg2://{user}:{password}@{db_host}:{port}/{name}"
    return "sqlite:///developer_portal.db"


app.config["SQLALCHEMY_DATABASE_URI"] = _build_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# ------------------------------------------------------------------
# HTML routes
# ------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    dev = db.session.get(Developer, g.developer_id)
    certs = Certificate.query.filter_by(developer_id=dev.id).order_by(Certificate.issued_at.desc()).all()
    ca_cert_pem = get_ca_cert_pem()
    now = datetime.utcnow()
    return render_template("dashboard.html", developer=dev, certificates=certs, ca_cert_pem=ca_cert_pem, now=now)


# ------------------------------------------------------------------
# API: Auth
# ------------------------------------------------------------------

@app.route("/api/v1/auth/register", methods=["POST"])
def api_register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    email = data.get("email", "").strip()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    org_name = data.get("org_name", "").strip()
    tos_accepted = data.get("tos_accepted") in (True, "true", "on", "1")

    if not all([email, password, name, org_name]):
        error = "All fields are required"
        if request.is_json:
            return jsonify({"error": error}), 400
        return render_template("register.html", error=error), 400

    if not tos_accepted:
        error = "You must accept the Terms of Service"
        if request.is_json:
            return jsonify({"error": error}), 400
        return render_template("register.html", error=error), 400

    if Developer.query.filter_by(email=email).first():
        error = "Email already registered"
        if request.is_json:
            return jsonify({"error": error}), 409
        return render_template("register.html", error=error), 409

    org = Organization.query.filter_by(name=org_name).first()
    if not org:
        org = Organization(name=org_name)
        db.session.add(org)
        db.session.flush()

    role = "developer"

    dev = Developer(
        email=email,
        password_hash=generate_password_hash(password),
        name=name,
        org_id=org.id,
        role=role,
        tos_accepted=True,
    )
    db.session.add(dev)
    db.session.commit()

    if request.is_json:
        return jsonify({"message": "Account created", "developer_id": dev.id, "role": dev.role}), 201

    access_token = create_access_token(dev.id)
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("access_token", access_token, httponly=True, samesite="Lax")
    return resp


@app.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    email = data.get("email", "").strip()
    password = data.get("password", "")

    dev = Developer.query.filter_by(email=email).first()
    if not dev or not check_password_hash(dev.password_hash, password):
        error = "Invalid email or password"
        if request.is_json:
            return jsonify({"error": error}), 401
        return render_template("login.html", error=error), 401

    access_token = create_access_token(dev.id)
    refresh_token = create_refresh_token(dev.id)

    if request.is_json:
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
        })

    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("access_token", access_token, httponly=True, samesite="Lax")
    return resp


@app.route("/api/v1/auth/refresh", methods=["POST"])
def api_refresh():
    data = request.get_json() or {}
    token = data.get("refresh_token", "")

    payload = decode_token(token, expected_type="refresh")
    if not payload:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    access_token = create_access_token(payload["sub"])
    return jsonify({"access_token": access_token, "token_type": "Bearer"})


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login_page")))
    resp.delete_cookie("access_token")
    return resp


# ------------------------------------------------------------------
# API: Developer keys / certificates
# ------------------------------------------------------------------

@app.route("/api/v1/developers/keys", methods=["POST"])
@login_required
def api_upload_key():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    public_key_pem = data.get("public_key", "").strip()
    if not public_key_pem:
        error = "public_key is required (PEM-encoded ECDSA P-256)"
        if request.is_json:
            return jsonify({"error": error}), 400
        return redirect(url_for("dashboard"))
    
    key_source = data.get("key_source", "uploaded")
    if key_source not in ("generated", "uploaded"):
        key_source = "uploaded"

    dev = db.session.get(Developer, g.developer_id)

    try:
        cert_pem, serial_hex, expires_at = sign_developer_cert(
            public_key_pem, dev.name, dev.organization.name, dev.id
        )
    except ValueError as e:
        if request.is_json:
            return jsonify({"error": str(e)}), 400
        return redirect(url_for("dashboard"))
    except Exception as e:
        if request.is_json:
            return jsonify({"error": f"Certificate signing failed: {e}"}), 500
        return redirect(url_for("dashboard"))

    cert = Certificate(
        serial_number=serial_hex,
        developer_id=dev.id,
        public_key_pem=public_key_pem,
        key_source=key_source,
        certificate_pem=cert_pem,
        expires_at=expires_at,
    )
    db.session.add(cert)
    db.session.commit()

    if request.is_json:
        ca_info = get_ca_cert_info()
        return jsonify({
            "certificate_id": cert.id,
            "serial_number": cert.serial_number,
            "certificate_pem": cert.certificate_pem,
            "ca_certificate_pem": ca_info["certificate_pem"],
            "fingerprint_sha256": ca_info["fingerprint_sha256"],
            "issued_at": cert.issued_at.isoformat(),
            "expires_at": cert.expires_at.isoformat(),
        }), 201

    return redirect(url_for("dashboard"))


@app.route("/api/v1/developers/keys", methods=["GET"])
@login_required
def api_list_keys():
    certs = Certificate.query.filter_by(developer_id=g.developer_id).order_by(Certificate.issued_at.desc()).all()
    return jsonify([
        {
            "id": c.id,
            "serial_number": c.serial_number,
            "issued_at": c.issued_at.isoformat(),
            "expires_at": c.expires_at.isoformat(),
            "is_revoked": c.is_revoked,
            "revocation_reason": c.revocation_reason,
        }
        for c in certs
    ])


@app.route("/api/v1/developers/keys/<int:cert_id>", methods=["DELETE"])
@login_required
def api_revoke_key(cert_id):
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    dev = db.session.get(Developer, g.developer_id)

    if cert.developer_id != dev.id:
        if dev.role != "admin" or cert.developer.org_id != dev.org_id:
            return jsonify({"error": "Not authorized to revoke this certificate"}), 403

    if cert.is_revoked:
        return jsonify({"error": "Certificate is already revoked"}), 400

    reason = "admin_action" if cert.developer_id != dev.id else "key_compromise"
    if request.is_json:
        data = request.get_json(silent=True) or {}
        reason = data.get("reason", reason)

    cert.is_revoked = True
    cert.revoked_at = datetime.now(timezone.utc)
    cert.revocation_reason = reason
    db.session.commit()

    return jsonify({"message": "Certificate revoked", "serial_number": cert.serial_number})


@app.route("/revoke/<int:cert_id>", methods=["POST"])
@login_required
def revoke_cert_html(cert_id):
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        return redirect(url_for("dashboard"))

    dev = db.session.get(Developer, g.developer_id)
    if cert.developer_id != dev.id and not (dev.role == "admin" and cert.developer.org_id == dev.org_id):
        return redirect(url_for("dashboard"))

    if not cert.is_revoked:
        cert.is_revoked = True
        cert.revoked_at = datetime.now(timezone.utc)
        cert.revocation_reason = "key_compromise"
        db.session.commit()

    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------
# API: CRL (public)
# ------------------------------------------------------------------

@app.route("/api/v1/crl", methods=["GET"])
def api_crl():
    revoked = Certificate.query.filter_by(is_revoked=True).all()
    crl_der = generate_crl(revoked)
    response = make_response(crl_der)
    response.headers["Content-Type"] = "application/pkix-crl"
    response.headers["Content-Disposition"] = "attachment; filename=developer.crl"
    return response


# ------------------------------------------------------------------
# API: CA certificate (public)
# ------------------------------------------------------------------

@app.route("/api/v1/ca/certificate", methods=["GET"])
def api_ca_certificate():
    return jsonify(get_ca_cert_info())


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5100)