"""
Public OOB callback endpoints.

These endpoints are the "catch" side of the OOB canary mechanism.
Payloads injected into target MCP servers contain a URL under
``/api/v1/callbacks/oob/<token>``. When the target executes the payload
(e.g. a successful command injection, SSRF, blind XSS), it makes an
HTTP request here, we record the hit, and the attack script's call to
``oob.wait(token)`` returns — producing side-channel proof.

NOTE: Unlike the rest of /api/v1, the OOB route is intentionally
unauthenticated. The token itself (128 bits of randomness) is the
capability. Rate-limit at the edge if deploying publicly.
"""

from flask import request, jsonify

from app.api import api_bp
from app.services import oob_callback


@api_bp.route("/callbacks/oob/<token>",
              methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def oob_hit(token: str):
    """Record an incoming OOB callback. Always returns 204 so the target
    can't distinguish valid vs invalid tokens, limiting enumeration."""
    body = None
    try:
        body = request.get_data(as_text=True)
    except Exception:
        pass
    source_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
    )
    oob_callback.record_hit(
        token,
        source_ip=source_ip,
        method=request.method,
        path=request.path,
        headers={k: v for k, v in request.headers.items()},
        query={k: v for k, v in request.args.items()},
        body=body,
    )
    return ("", 204)


# Admin / debugging — authenticated listing of active tokens.
from flask_jwt_extended import jwt_required


@api_bp.route("/callbacks/oob", methods=["GET"])
@jwt_required()
def list_tokens():
    out = []
    for t in oob_callback.all_tokens():
        out.append({
            "token": t.token,
            "url": t.url,
            "attack_id": t.attack_id,
            "created_at": t.created_at,
            "expires_at": t.expires_at,
            "hit_count": len(oob_callback.hits(t.token)),
            "metadata": t.metadata or {},
        })
    return jsonify(out), 200


@api_bp.route("/callbacks/oob/<token>/hits", methods=["GET"])
@jwt_required()
def token_hits(token: str):
    return jsonify(oob_callback.hits(token)), 200
