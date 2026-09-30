"""Unit tests for core scoring/rules/hashing (TRD §21). Run: pytest backend/tests"""
import sys
sys.path.insert(0, "backend")

from app.analyzers.url.features import extract_url_features
from app.analyzers.url.rules import apply_url_rules
from app.analyzers.message.normalize import extract_urls
from app.analyzers.qr.decoder import classify_payload
from app.analyzers.document.validator import sha256_bytes
from app.scoring.engine import score_from_signals


def test_url_features_ip():
    f = extract_url_features("http://192.168.1.1/login")
    assert f["is_ip_host"] is True


def test_url_rules_produce_evidence_not_decision():
    f = extract_url_features("https://secure-login-verify.tk/login")
    ev, sig = apply_url_rules(f)
    assert len(ev) >= 2
    assert "URL_SUSPICIOUS_KEYWORD" in sig


def test_url_extraction():
    urls = extract_urls("visit https://example.com/a and www.test.com now")
    assert len(urls) == 2


def test_qr_routing():
    assert classify_payload("https://example.com") == "URL"
    assert classify_payload("hello world this is text") == "TEXT"
    assert classify_payload("user@example.com") == "EMAIL"


def test_sha256():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_scoring_weighted():
    s = score_from_signals({"threat_intelligence_match": 1.0})
    assert s == 35
    s2 = score_from_signals({})
    assert s2 == 0
