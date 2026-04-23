import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify, g, redirect, url_for

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production!")  # 32 bytes min for HS256
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=7)


def create_access_token(developer_id):
    payload = {
        "sub": str(developer_id),
        "type": "access",
        "exp": datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRY,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(developer_id):
    payload = {
        "sub": str(developer_id),
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token, expected_type="access"):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        if not token:
            token = request.cookies.get("access_token")

        if not token:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))

        payload = decode_token(token, expected_type="access")
        if not payload:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Invalid or expired token"}), 401
            return redirect(url_for("login_page"))

        g.developer_id = int(payload["sub"])
        return f(*args, **kwargs)

    return decorated