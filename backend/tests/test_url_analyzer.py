"""Comprehensive test suite for TRUSTSHIELD URL Analyzer improvements (TRD §21, PRD §8).

Covers:
- Validation & normalization edge cases (PSL, IDNA, IPv4/IPv6, userinfo, ports, trailing dots, fragments)
- False-positive controls (legitimate login, payment, shorteners, search queries, multi-subdomains)
- Threat intelligence caching, bounded timeouts, and status normalization
- Trained URL classification model inference & graceful fallback
- End-to-end API integration and scoring fusion
"""
from __future__ import annotations
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.analyzers.url.validation import validate_url, validate_url_detailed, is_valid_ipv4, is_valid_ipv6
from app.analyzers.url.normalization import normalize_url, normalize_url_details
from app.analyzers.url.features import extract_url_features, extract_domain_info
from app.analyzers.url.rules import apply_url_rules
from app.scoring.engine import score_from_signals, level_from_score
from app.ml.url_classifier import URLClassifier, get_classifier
from app.ml.url_ml import url_ml_probability, get_url_ml_info
from app.threat_intel.base import ThreatIntelResult
from app.threat_intel.manager import check_all, clear_cache

client = TestClient(app)


# =====================================================================
# 1. Validation & Parsing Tests (PRD FR-1, §8)
# =====================================================================

def test_validate_standard_urls():
    ok, _ = validate_url("https://example.com/path")
    assert ok is True
    ok, _ = validate_url("http://example.org:8080/test?q=1")
    assert ok is True


def test_validate_schemeless_input():
    res = validate_url_detailed("example.com/login")
    assert res.is_valid is True
    assert res.scheme_inferred is True
    assert "inferred https://" in res.warnings[0]
    assert res.candidate_url == "https://example.com/login"


def test_reject_unsupported_schemes():
    for bad in ["javascript:alert(1)", "data:text/html,test", "file:///etc/passwd", "ftp://ftp.example.com"]:
        ok, reason = validate_url(bad)
        assert ok is False
        assert "Only http/https" in reason or "not supported" in reason.lower()


def test_reject_control_characters_and_whitespace():
    assert validate_url("https://example.com/path with spaces")[0] is False
    assert validate_url("https://example.com/path\nwith\nnewlines")[0] is False
    assert validate_url("https://example.com/\x00evil")[0] is False


def test_reject_overlong_and_empty():
    assert validate_url("")[0] is False
    assert validate_url("   ")[0] is False
    assert validate_url("https://" + "a" * 2050 + ".com")[0] is False


def test_ipv4_and_ipv6_validation():
    # Valid IPv4
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("8.8.8.8") is True
    assert is_valid_ipv4("256.1.1.1") is False
    assert is_valid_ipv4("1.2.3") is False

    # Valid IPv6
    assert is_valid_ipv6("2001:db8::1") is True
    assert is_valid_ipv6("[::1]") is True
    assert is_valid_ipv6("2001:xyz::1") is False

    # URL level
    assert validate_url("http://192.168.1.1/login")[0] is True
    assert validate_url("http://[2001:db8::1]:8080/path")[0] is True
    assert validate_url("http://999.999.999.999/")[0] is False


def test_userinfo_handling_never_confuses_host():
    res = validate_url_detailed("http://google.com@attacker.com/path")
    assert res.is_valid is True
    assert any("userinfo" in w for w in res.warnings)

    norm = normalize_url_details("http://google.com@attacker.com/path")
    assert norm.effective_host == "attacker.com"
    assert norm.original_userinfo == "google.com"


def test_port_validation():
    assert validate_url("https://example.com:443/")[0] is True
    assert validate_url("https://example.com:8443/")[0] is True
    assert validate_url("https://example.com:70000/")[0] is False  # > 65535
    assert validate_url("https://example.com:abc/")[0] is False


# =====================================================================
# 2. Normalization & PSL Domain Extraction (PRD FR-2, FR-3)
# =====================================================================

def test_psl_registrable_domain_extraction():
    # Multi-label public suffixes
    reg, suffix, sub, sub_count = extract_domain_info("sub.portal.example.co.uk")
    assert reg == "example.co.uk"
    assert suffix == "co.uk"
    assert sub == "sub.portal"
    assert sub_count == 2

    # Standard .com
    reg, suffix, sub, sub_count = extract_domain_info("accounts.google.com")
    assert reg == "google.com"
    assert suffix == "com"
    assert sub == "accounts"
    assert sub_count == 1

    # Base domain with no subdomains
    reg, suffix, sub, sub_count = extract_domain_info("example.co.uk")
    assert reg == "example.co.uk"
    assert sub_count == 0

    # IP address
    reg, suffix, sub, sub_count = extract_domain_info("192.168.1.1")
    assert reg == "192.168.1.1"
    assert sub_count == 0


def test_normalization_preserves_non_default_ports():
    assert normalize_url("https://example.com:443/path") == "https://example.com/path"
    assert normalize_url("http://example.com:80/path") == "http://example.com/path"
    assert normalize_url("https://example.com:8080/path") == "https://example.com:8080/path"
    assert normalize_url("http://example.com:443/path") == "http://example.com:443/path"


def test_normalization_trailing_dot_and_fragment():
    details = normalize_url_details("https://example.com./path#section1")
    assert details.has_trailing_dot is True
    assert details.original_fragment == "section1"
    assert details.normalized_url == "https://example.com/path"
    assert any("trailing dot" in t.lower() for t in details.transformations)
    assert any("fragment" in t.lower() for t in details.transformations)


# =====================================================================
# 3. False-Positive Controls & Benign Counterexamples (PRD FR-4, §8)
# =====================================================================

def test_legitimate_login_page_not_high_risk():
    feats = extract_url_features("https://accounts.google.com/signin/v2/identifier")
    ev, sig = apply_url_rules(feats)
    score = score_from_signals(sig, ml_phishing_prob=0.05)
    level = level_from_score(score)
    # Legitimate login over HTTPS with 1 subdomain should remain LOW
    assert score < 25
    assert level == "LOW"


def test_legitimate_payment_page_not_high_risk():
    feats = extract_url_features("https://checkout.stripe.com/c/pay/cs_live_123")
    ev, sig = apply_url_rules(feats)
    score = score_from_signals(sig, ml_phishing_prob=0.05)
    level = level_from_score(score)
    assert score < 25
    assert level == "LOW"


def test_benign_query_keywords_do_not_flag_host():
    feats = extract_url_features("https://www.google.com/search?q=bank+account+login+verify")
    ev, sig = apply_url_rules(feats)
    assert "URL_SUSPICIOUS_KEYWORD" not in sig
    score = score_from_signals(sig, ml_phishing_prob=0.03)
    assert score < 25


def test_legitimate_international_domain():
    norm = normalize_url("https://xn--bcher-kva.de/katalog")
    feats = extract_url_features(norm)
    assert feats["punycode"] is True
    ev, sig = apply_url_rules(feats)
    # Punycode on benign site without compound lure triggers an informative medium finding, but remains <= 25 without ML/TI
    score = score_from_signals(sig, ml_phishing_prob=0.05)
    assert score <= 25


# =====================================================================
# 4. Threat Intelligence Resilience & Concurrency (PRD FR-5, §8)
# =====================================================================

class DummyProvider:
    def __init__(self, name: str, status: str, matched: bool = False, category: str | None = None, delay: float = 0.0, error: bool = False):
        self.name = name
        self.status = status
        self.matched = matched
        self.category = category
        self.delay = delay
        self.error = error
        self.call_count = 0
        self.timeout = 2

    async def check_url(self, url: str) -> ThreatIntelResult:
        import asyncio
        self.call_count += 1
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        if self.error:
            raise ConnectionError("Network unreachable")
        return ThreatIntelResult(provider=self.name, status=self.status, matched=self.matched, category=self.category, detail="mock")


@pytest.mark.anyio
async def test_threat_intel_fanout_and_caching():
    clear_cache()
    p1 = DummyProvider("p1", "no_match", matched=False)
    p2 = DummyProvider("p2", "match", matched=True, category="phishing")
    p3 = DummyProvider("p3", "unavailable", error=True)

    results = await check_all([p1, p2, p3], "https://test-check.example.com/")
    assert len(results) == 3

    r_map = {r.provider: r for r in results}
    assert r_map["p1"].status == "no_match"
    assert r_map["p2"].status == "match"
    assert r_map["p3"].status == "unavailable"

    # Verify second call hits cache for p1 and p2
    results_2 = await check_all([p1, p2], "https://test-check.example.com/")
    assert p1.call_count == 1  # cached
    assert p2.call_count == 1  # cached


@pytest.mark.anyio
async def test_threat_intel_timeout_does_not_crash():
    clear_cache()
    slow_p = DummyProvider("slow", "match", delay=3.0)
    slow_p.timeout = 0.1  # fast timeout
    results = await check_all([slow_p], "https://timeout-test.example.com/", timeout=1)
    assert len(results) == 1
    assert results[0].status == "unavailable"
    assert "timed out" in results[0].detail.lower()


# =====================================================================
# 5. Model Inference & Non-Duplicative Fusion (PRD FR-6, FR-9)
# =====================================================================

def test_url_classifier_loaded():
    info = get_url_ml_info()
    assert info["status"] == "available"
    assert info["is_trained_model"] is True
    assert "url-classifier-tabular" in info["version"]


def test_url_model_predictions():
    # Benign URL prediction
    p_benign = url_ml_probability("https://www.wikipedia.org/")
    assert p_benign < 0.20

    # Phishing lure prediction
    p_phish = url_ml_probability("http://secure-login-verify.tk/login")
    assert p_phish > 0.70


def test_scoring_fusion_prevents_double_counting():
    # IP host + long URL + unencrypted HTTP + model
    signals = {
        "URL_IP_HOST": 1.0,
        "URL_LONG": 1.0,
        "URL_NO_HTTPS": 1.0,
        "suspicious_url": 1.0,  # Aggregate flag should NOT be double-counted with URL_IP_HOST
    }
    score = score_from_signals(signals, ml_phishing_prob=0.8)
    # Host category cap = 15, Obf subtotal = 4+4 = 8, ML contribution = 25*0.8 = 20 -> total = 43 (MEDIUM)
    assert score == 43
    assert level_from_score(score) == "MEDIUM"


def test_threat_intel_match_escalates_score():
    signals = {"threat_intelligence_match": 1.0}
    score = score_from_signals(signals, ml_phishing_prob=0.0)
    assert score >= 35
    assert level_from_score(score) in ("MEDIUM", "HIGH", "CRITICAL")


# =====================================================================
# 6. End-to-End API Tests (PRD §7, §8)
# =====================================================================

def test_api_analyze_url_benign():
    resp = client.post("/api/v1/analyze/url", json={"url": "https://www.google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["inputType"] == "URL"
    assert data["rawUrl"] == "https://www.google.com"
    assert data["normalizedUrl"] == "https://www.google.com/"
    assert data["riskLevel"] in ("LOW", "UNKNOWN")
    assert data["modelStatus"] == "available"
    assert len(data["evidence"]) >= 1


def test_api_analyze_url_phishing_lure():
    resp = client.post("/api/v1/analyze/url", json={"url": "http://paypal.verify-account-security.cf/webapps/mpp/home"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["riskScore"] >= 25
    assert data["riskLevel"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("hostname" in e["title"].lower() or "keyword" in e["title"].lower() for e in data["evidence"])


def test_api_analyze_url_invalid_yields_unknown():
    resp = client.post("/api/v1/analyze/url", json={"url": "ftp://malformed-scheme.example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["riskLevel"] == "UNKNOWN"
    assert any("validate" in lim.lower() for lim in data["limitations"])
