#!/usr/bin/env python3
"""
HumanCheck reference server.

Offline derivation model:
1. Server keeps a long-lived P-256 master private key (secret).
2. Registration QR shares master_public (raw X||Y).
3. Client derives child public keys locally for each time counter.
4. Server derives matching child private keys and verifies the OTP.

Endpoints:
  GET  /                      - web dashboard
  GET  /how-it-works          - technical protocol details
  GET  /key                   - current derived child public key (debug/status)
  POST /register/start        - start QR registration session
  GET  /register/status/<id>  - poll registration status
  POST /register/complete     - device submits pubkey after scanning QR
  POST /verify                - verify a 6-digit OTP
  GET  /users                 - list registered users
"""

import hmac
import os
import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, jsonify, request, send_from_directory, make_response

from biotp import MasterKey, verify_app_attest, verify_android_attestation
from biotp.app_attest import b64_decode

PERIOD = 30
MASTER_SECRET = bytes.fromhex(
    os.environ.get("MASTER_SECRET", os.urandom(32).hex())
)
SESSION_TTL = 300  # registration sessions expire after 5 minutes

master = MasterKey(MASTER_SECRET, period=PERIOD)

# Trusted iOS bundle IDs as "TEAMID.BUNDLEID" strings (comma-separated env var).
# When set, only attestations from these apps are accepted.
ALLOWED_APP_IDS: list[str] | None = None
_raw_app_ids = os.environ.get("ALLOWED_APP_IDS", "").strip()
if _raw_app_ids:
    ALLOWED_APP_IDS = [s.strip() for s in _raw_app_ids.split(",") if s.strip()]

ICON_COLOR_PALETTE = [
    "#6366f1",
    "#ec4899",
    "#14b8a6",
    "#f59e0b",
    "#8b5cf6",
    "#ef4444",
    "#06b6d4",
    "#22c55e",
]

# In-memory stores
users: dict[str, dict] = {}
registration_sessions: dict[str, dict] = {}

app = Flask(__name__, static_folder="static")


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------


def _derive_relying_party_color_seed(user_id: str, user_record) -> str:
    rp_name = None
    if isinstance(user_record, dict):
        public_key = user_record.get("public_key")
        if isinstance(public_key, str):
            trimmed_public_key = public_key.strip()
            if trimmed_public_key:
                return trimmed_public_key
        rp_name = user_record.get("rp_name")
    if isinstance(rp_name, str) and rp_name.strip():
        return rp_name.strip()

    if not user_id:
        return "HumanCheck"

    user_id_parts = user_id.rsplit("-", 1)
    if (
        len(user_id_parts) == 2
        and len(user_id_parts[1]) == 4
        and all(ch.isalnum() for ch in user_id_parts[1])
    ):
        return user_id_parts[0]

    return user_id


def _stable_fnv1a_64(value: str) -> int:
    normalized = value.strip().lower().encode("utf-8")
    hash_value = 1469598103934665603
    fnv_prime = 1099511628211
    for byte in normalized:
        hash_value ^= byte
        hash_value = (hash_value * fnv_prime) & 0xFFFFFFFFFFFFFFFF
    return hash_value


def _derive_relying_party_color(seed: str) -> str:
    if not isinstance(seed, str) or not seed.strip():
        return ICON_COLOR_PALETTE[0]
    index = _stable_fnv1a_64(seed) % len(ICON_COLOR_PALETTE)
    return ICON_COLOR_PALETTE[index]


def _cleanup_expired_sessions():
    now = time.time()
    expired = [
        sid
        for sid, s in registration_sessions.items()
        if now - s.get("created_at", 0) > SESSION_TTL
    ]
    for sid in expired:
        del registration_sessions[sid]


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    response = make_response(send_from_directory("static", "index.html"))
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/how-it-works")
def how_it_works():
    response = make_response(
        send_from_directory("static", "how-it-works.html")
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Key status endpoint (debug only)
# ---------------------------------------------------------------------------


@app.route("/key", methods=["GET"])
def get_key():
    counter = master.current_counter()
    remaining = PERIOD - int(time.time()) % PERIOD
    return jsonify(
        public_key=master.child_pubkey_hex(counter),
        counter=counter,
        expires_in=remaining,
        mode="offline-derived",
    )


# ---------------------------------------------------------------------------
# Registration flow
# ---------------------------------------------------------------------------


@app.route("/register/start", methods=["POST"])
def register_start():
    """Create a registration session. Returns QR data for the device."""
    _cleanup_expired_sessions()
    data = request.get_json(force=True) if request.is_json else {}
    rp_name = data.get("rp_name", "HumanCheck Demo")

    session_id = str(uuid.uuid4())
    public_base_url = (
        os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    )
    if public_base_url:
        server_url = public_base_url
    else:
        server_url = request.url_root.rstrip("/")
    if not public_base_url and (
        "localhost" in server_url or "127.0.0.1" in server_url
    ):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
        finally:
            s.close()
        server_url = f"http://{lan_ip}:8787"

    registration_sessions[session_id] = {
        "status": "pending",
        "rp_name": rp_name,
        "created_at": time.time(),
        "attest_challenge": base64.b64encode(os.urandom(32)).decode("ascii"),
    }

    callback_url = server_url + "/register/complete"

    qr_data = {
        "action": "register",
        "callback_url": callback_url,
        "rp_name": rp_name,
        "session_id": session_id,
        "master_public": master.public_raw.hex(),
        "period": PERIOD,
        "attest_challenge": registration_sessions[session_id][
            "attest_challenge"
        ],
    }

    return jsonify(session_id=session_id, qr_data=qr_data)


@app.route("/register/status/<session_id>", methods=["GET"])
def register_status(session_id: str):
    session = registration_sessions.get(session_id)
    if not session:
        return jsonify(error="session not found"), 404
    return jsonify(
        status=session["status"],
        user_id=session.get("user_id"),
    )


@app.route("/register/complete", methods=["POST"])
def register_complete():
    """Device calls this after scanning QR and generating a keypair."""
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    user_id = data.get("user_id")
    public_key = data.get("public_key")
    platform = data.get("platform", "ios")

    if not session_id or not user_id or not public_key:
        return (
            jsonify(error="session_id, user_id, and public_key required"),
            400,
        )

    if user_id in users:
        return jsonify(error="user_id already registered"), 409

    session = registration_sessions.get(session_id)
    if not session:
        return jsonify(error="invalid session"), 404
    if session["status"] != "pending":
        return jsonify(error="session already completed"), 400
    if time.time() - session.get("created_at", 0) > SESSION_TTL:
        del registration_sessions[session_id]
        return jsonify(error="session expired"), 410

    try:
        raw = bytes.fromhex(public_key)
        if len(raw) == 64:
            normalized = b"\x04" + raw
        else:
            normalized = raw
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), normalized
        )
    except ValueError:
        return jsonify(error="invalid public key"), 400

    session_challenge = session.get("attest_challenge")
    if not isinstance(session_challenge, str):
        return jsonify(error="invalid session state"), 500

    # Platform-specific attestation verification
    skip_attest = os.environ.get("SKIP_ATTESTATION", "").strip().lower() in ("1", "true", "yes")

    if platform == "android":
        android_chain = data.get("android_attestation_chain", [])
        try:
            challenge_bytes = b64_decode(session_challenge)
            ok, reason, attestation_details = verify_android_attestation(
                cert_chain_b64=android_chain,
                expected_challenge=challenge_bytes,
                user_public_key_hex=public_key,
            )
        except Exception as exc:
            if not skip_attest:
                return jsonify(error=f"attestation parsing failed: {exc}"), 500
            ok, reason, attestation_details = False, str(exc), {"error": str(exc)}
    else:
        # iOS App Attest
        attest_challenge = data.get("attest_challenge")
        attest_key_id = data.get("attest_key_id")
        attest_client_data_hash = data.get("attest_client_data_hash")
        attestation_object = data.get("attest_object")

        if (
            not attest_challenge
            or not attest_key_id
            or not attest_client_data_hash
            or not attestation_object
        ):
            if not skip_attest:
                return jsonify(error="app attest fields are required"), 400
            ok, reason, attestation_details = False, "fields missing", {"error": "fields missing"}
        else:
            try:
                client_hash = b64_decode(attest_client_data_hash)
                ok, reason, attestation_details = verify_app_attest(
                    attestation_b64=attestation_object,
                    attest_key_id_b64=attest_key_id,
                    expected_client_data_hash=client_hash,
                    user_public_key=public_key,
                    session_challenge_b64=session_challenge,
                    allowed_app_ids=ALLOWED_APP_IDS,
                )
            except Exception as exc:
                if not skip_attest:
                    return jsonify(error=f"attestation parsing failed: {exc}"), 500
                ok, reason, attestation_details = False, str(exc), {"error": str(exc)}

    if not ok and skip_attest:
        attestation_details["skipped"] = True
        attestation_details["original_reason"] = reason
        ok, reason = True, "skipped (attestation disabled)"

    if not ok:
        return jsonify(error=f"attestation failed: {reason}"), 401

    users[user_id] = {
        "public_key": normalized.hex(),
        "rp_name": session.get("rp_name"),
        "platform": platform,
        "attestation": {
            "valid": bool(ok),
            "details": attestation_details,
            "verified_at": time.time(),
        },
    }
    session["status"] = "completed"
    session["user_id"] = user_id

    print(f"[register] {user_id} -> {public_key[:20]}...")
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    otp = data.get("otp")

    if not user_id or not otp:
        return jsonify(error="user_id and otp required"), 400

    user_record = users.get(user_id)
    if isinstance(user_record, dict):
        user_pub = user_record.get("public_key", "")
    else:
        user_pub = user_record

    if not user_pub:
        print("[verify] unknown user_id attempted")
        return jsonify(valid=False), 401

    last_counter = (
        user_record.get("last_verified_counter", -1)
        if isinstance(user_record, dict)
        else -1
    )

    valid, matched_counter = master.verify_otp(
        user_pub, otp, skew=1, last_counter=last_counter
    )

    if valid:
        if isinstance(user_record, dict):
            user_record["last_verified_counter"] = matched_counter
        print(f"[verify] {user_id} OTP valid (counter={matched_counter})")
        return jsonify(valid=True, counter=matched_counter)

    print(f"[verify] {user_id} OTP rejected")
    return jsonify(valid=False), 401


# ---------------------------------------------------------------------------
# Users list
# ---------------------------------------------------------------------------


@app.route("/users", methods=["GET"])
def list_users():
    def serialize_attestation(attest_data):
        if not isinstance(attest_data, dict):
            if isinstance(attest_data, bool):
                return {"valid": attest_data, "verified_at": None}
            return None
        return {
            "valid": bool(attest_data.get("valid", False)),
            "verified_at": attest_data.get("verified_at"),
            "details": attest_data.get("details"),
        }

    return jsonify(
        users=[
            {
                "user_id": uid,
                "relying_party": (
                    user_record.get("rp_name")
                    if isinstance(user_record, dict)
                    else None
                )
                or uid,
                "platform": (
                    user_record.get("platform", "ios")
                    if isinstance(user_record, dict)
                    else "ios"
                ),
                "color_seed": _derive_relying_party_color_seed(
                    uid, user_record
                ),
                "icon_color": _derive_relying_party_color(
                    _derive_relying_party_color_seed(uid, user_record)
                ),
                "public_key": (
                    user_record["public_key"]
                    if isinstance(user_record, dict)
                    else user_record
                )[:20]
                + "...",
                "attestation": serialize_attestation(
                    user_record.get("attestation") or user_record.get("app_attest")
                    if isinstance(user_record, dict)
                    else None
                ),
            }
            for uid, user_record in users.items()
        ]
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Master public (raw): {master.public_raw.hex()}")
    print(
        "Public base URL override: "
        + (os.environ.get("PUBLIC_BASE_URL", "<none>").strip() or "<none>")
    )
    print(f"Allowed app IDs: {ALLOWED_APP_IDS or '<any (not configured)>'}")
    print(f"Period: {PERIOD}s")
    print("Serving on http://0.0.0.0:8787")
    print()
    app.run(host="0.0.0.0", port=8787, debug=False)
