"""Feature extraction schema and vectorizer for URL classification model.
Shared between training pipeline and runtime inference.
TRD §5, PRD §7 FR-3, FR-6.
"""
from __future__ import annotations
from typing import Sequence
from app.analyzers.url.features import extract_url_features

FEATURE_NAMES: list[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "query_param_count",
    "subdomain_count",
    "label_count",
    "digit_count",
    "special_count",
    "is_ip_host",
    "punycode",
    "is_https",
    "is_unusual_port",
    "shortener",
    "has_userinfo",
    "encoded",
    "double_encoded",
    "has_nested_redirect_url",
    "suspicious_structure",
    "login_path",
    "payment_path",
    "has_credential_terms",
    "has_payment_terms",
    "host_kws_count",
    "path_kws_count",
    "query_kws_count",
    "has_trailing_dot",
]


def extract_url_feature_vector(normalized_url: str) -> list[float]:
    """Extracts a fixed-order numerical feature vector from a normalized URL."""
    f = extract_url_features(normalized_url)
    return [
        float(f.get("url_length", 0)),
        float(f.get("hostname_length", 0)),
        float(f.get("path_length", 0)),
        float(f.get("query_length", 0)),
        float(f.get("query_param_count", 0)),
        float(f.get("subdomain_count", 0)),
        float(f.get("label_count", 0)),
        float(f.get("digit_count", 0)),
        float(f.get("special_count", 0)),
        1.0 if f.get("is_ip_host") else 0.0,
        1.0 if f.get("punycode") else 0.0,
        1.0 if f.get("is_https") else 0.0,
        1.0 if f.get("is_unusual_port") else 0.0,
        1.0 if f.get("shortener") else 0.0,
        1.0 if f.get("has_userinfo") else 0.0,
        1.0 if f.get("encoded") else 0.0,
        1.0 if f.get("double_encoded") else 0.0,
        1.0 if f.get("has_nested_redirect_url") else 0.0,
        1.0 if f.get("suspicious_structure") else 0.0,
        1.0 if f.get("login_path") else 0.0,
        1.0 if f.get("payment_path") else 0.0,
        1.0 if f.get("has_credential_terms") else 0.0,
        1.0 if f.get("has_payment_terms") else 0.0,
        float(len(f.get("suspicious_keywords_host", []))),
        float(len(f.get("suspicious_keywords_path", []))),
        float(len(f.get("suspicious_keywords_query", []))),
        1.0 if f.get("has_trailing_dot") else 0.0,
    ]


def vector_to_dict(vec: Sequence[float]) -> dict[str, float]:
    """Converts a feature vector to a named mapping."""
    return dict(zip(FEATURE_NAMES, vec))
