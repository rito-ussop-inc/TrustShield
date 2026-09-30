"""Transparent TF-IDF + LogisticRegression baseline (TRD §8).

Classes: LEGITIMATE / SPAM / PHISHING.
Stores model probability + version. Probability is not certainty.
Trains on small built-in seed corpus + data/samples if available; artifacts versioned.
"""
from __future__ import annotations
import os
from pathlib import Path
import joblib

MODEL_VERSION = "msg-tfidf-lr-v1.0.0"

SEED_CORPUS: list[tuple[str, str]] = [
    ("Hi, just checking if we are still on for lunch tomorrow?", "LEGITIMATE"),
    ("Please find attached the meeting notes from today.", "LEGITIMATE"),
    ("Your order has shipped and will arrive Thursday. Track it in the app.", "LEGITIMATE"),
    ("Thanks for your help with the project documentation.", "LEGITIMATE"),
    ("Reminder: team standup at 10am in conference room B.", "LEGITIMATE"),
    ("Can you review the pull request when you get a chance?", "LEGITIMATE"),
    ("Win a free iPhone now! Click here to claim your prize urgently!", "SPAM"),
    ("Congratulations you won a lottery! Claim free cashback now!", "SPAM"),
    ("Limited offer! Buy now get 90% off, hurry last chance!", "SPAM"),
    ("Earn money fast from home, no investment, click this link!", "SPAM"),
    ("Your account will be blocked within 24 hours. Verify immediately at http://secure-login-verify.tk/login", "PHISHING"),
    ("Urgent: your bank account is suspended. Confirm your password and OTP here: http://bank-verify-login.ml/signin", "PHISHING"),
    ("Security alert: unusual login detected. Sign in to verify: http://account-secure-update.ga/login", "PHISHING"),
    ("Your UPI payment failed. Refund requires OTP verification, share OTP now urgently.", "PHISHING"),
    ("Dear customer your KYC is pending, account will be deactivated. Update now via link.", "PHISHING"),
    ("Income tax refund pending, click to claim by sharing bank details and OTP.", "PHISHING"),
]

_vectorizer = None
_model = None
_loaded_version = MODEL_VERSION


def _artifact_path(configured: str | None = None) -> Path:
    if configured:
        p = Path(configured)
        if not p.is_absolute():
            # resolve relative to repo root (two levels above backend/app/ml)
            here = Path(__file__).resolve()
            root = here.parents[3] if len(here.parents) >= 4 else here.parent
            # try backend-relative then repo-relative
            cand = (Path.cwd() / configured)
            return cand
        return p
    return Path.cwd() / "ml" / "artifacts" / "message_classifier.joblib"


def train_and_save(path: Path | None = None) -> Path:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    texts = [t for t, _ in SEED_CORPUS]
    labels = [l for _, l in SEED_CORPUS]
    # also load samples if present: data/samples/messages.csv with text,label
    extra = _load_extra_samples()
    texts += [t for t, _ in extra]
    labels += [l for _, l in extra]
    vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=3000)
    X = vec.fit_transform(texts)
    clf = LogisticRegression(max_iter=500)
    clf.fit(X, labels)
    path = path or _artifact_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vec, "model": clf, "version": MODEL_VERSION}, path)
    global _vectorizer, _model
    _vectorizer, _model = vec, clf
    return path


def _load_extra_samples() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for cand in [Path.cwd() / "data" / "samples" / "messages.csv", Path.cwd() / "ml" / "datasets" / "messages.csv"]:
        try:
            if cand.exists():
                import csv
                with cand.open(newline="", encoding="utf-8") as f:
                    r = csv.DictReader(f)
                    for row in r:
                        t = (row.get("text") or "").strip()
                        l = (row.get("label") or "").strip().upper()
                        if t and l in ("LEGITIMATE", "SPAM", "PHISHING"):
                            out.append((t, l))
        except Exception:
            continue
    return out


def _ensure_loaded():
    global _vectorizer, _model
    if _vectorizer is not None and _model is not None:
        return
    # try env-configured path
    cfg_path = os.getenv("MODEL_PATH", "")
    candidates = []
    if cfg_path:
        candidates.append(Path(cfg_path))
    candidates += [
        Path.cwd() / "ml" / "artifacts" / "message_classifier.joblib",
        Path(__file__).resolve().parents[3] / "ml" / "artifacts" / "message_classifier.joblib" if len(Path(__file__).resolve().parents) >= 4 else Path("ml/artifacts/message_classifier.joblib"),
    ]
    for c in candidates:
        try:
            if c.exists():
                blob = joblib.load(c)
                _vectorizer, _model = blob["vectorizer"], blob["model"]
                return
        except Exception:
            continue
    # fallback: train in-memory from seed (no disk write failure should break analysis)
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        texts = [t for t, _ in SEED_CORPUS]
        labels = [l for _, l in SEED_CORPUS]
        vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=3000)
        X = vec.fit_transform(texts)
        clf = LogisticRegression(max_iter=500)
        clf.fit(X, labels)
        _vectorizer, _model = vec, clf
    except Exception:
        _vectorizer, _model = None, None


def classify_message(text: str) -> dict:
    """Returns {label, phishing_prob, version}."""
    _ensure_loaded()
    if _vectorizer is None or _model is None:
        # heuristic fallback
        low = (text or "").lower()
        score = sum(k in low for k in ["otp", "password", "blocked", "suspended", "urgent", "verify", "account", "click"])
        prob = min(0.9, 0.2 + 0.1 * score)
        label = "PHISHING" if prob >= 0.5 else "LEGITIMATE"
        return {"label": label, "phishing_prob": prob, "version": MODEL_VERSION + "-fallback"}
    try:
        X = _vectorizer.transform([text or ""])
        proba = _model.predict_proba(X)[0]
        classes = list(_model.classes_)
        label = classes[int(proba.argmax())]
        # phishing_prob = P(PHISHING) + 0.5*P(SPAM) as suspicious mass
        p_phish = float(proba[classes.index("PHISHING")]) if "PHISHING" in classes else 0.0
        p_spam = float(proba[classes.index("SPAM")]) if "SPAM" in classes else 0.0
        suspicious = min(1.0, p_phish + 0.5 * p_spam)
        return {"label": label, "phishing_prob": round(suspicious, 3), "version": MODEL_VERSION}
    except Exception:
        return {"label": "UNKNOWN", "phishing_prob": 0.0, "version": MODEL_VERSION + "-error"}
