"""
Compliance mapping API.

Surfaces the data/compliance_mapping.json contents to the frontend so
finding-detail panels and report templates can render OWASP / ATLAS /
ATT&CK / CWE / NIST badges.
"""

from __future__ import annotations

from flask import jsonify
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.services import compliance


@api_bp.route("/compliance/mappings", methods=["GET"])
@jwt_required()
def get_all_mappings():
    return jsonify({
        "frameworks": compliance.frameworks(),
        "mappings": compliance.all_mappings(),
    }), 200


@api_bp.route("/compliance/category/<category>", methods=["GET"])
@jwt_required()
def get_for_category(category):
    return jsonify({"category": category,
                    "compliance": compliance.for_category(category)}), 200
