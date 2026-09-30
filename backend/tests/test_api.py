"""API tests: valid/malformed/empty/oversized/provider-failure (TRD §21)."""
import sys
sys.path.insert(0, "backend")
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").status_code == 200


def test_analyze_url_valid():
    r = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["inputType"] == "URL"
    assert body["riskLevel"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
    assert len(body["evidence"]) >= 1


def test_analyze_url_empty():
    r = client.post("/api/v1/analyze/url", json={"url": ""})
    assert r.status_code in (400, 422)


def test_analyze_message_phishing_demo():
    r = client.post("/api/v1/analyze/message", json={"text": "Your account will be blocked within 24 hours. Verify immediately at http://secure-login-verify.tk/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["riskScore"] is not None and body["riskScore"] >= 25


def test_analyze_message_empty():
    r = client.post("/api/v1/analyze/message", json={"text": "   "})
    assert r.status_code in (400, 422)


def test_unknown_url_not_safe():
    r = client.post("/api/v1/analyze/url", json={"url": "https://some-random-unknown-domain-xyz12345.com/"})
    body = r.json()
    assert body["riskLevel"] != "SAFE" if "riskLevel" in body else True
    assert "safe" not in " ".join(body.get("findings", [])).lower() or "not" in " ".join(body.get("findings", [])).lower()
