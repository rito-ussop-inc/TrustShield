"""URL Classifier runtime inference loader with schema and version checks.
TRD §8, PRD §7 FR-6, FR-8.
"""
from __future__ import annotations
import logging
import os
from pathlib import Path
from typing import Any
import joblib
import numpy as np

from training.url_model.features import FEATURE_NAMES, extract_url_feature_vector

logger = logging.getLogger(__name__)

DEFAULT_MODEL_VERSION = "url-classifier-tabular-v1.0.0"

_classifier_instance: URLClassifier | None = None


class URLClassifier:
    def __init__(self, artifact_path: Path | None = None):
        self.artifact_path = artifact_path or self._resolve_artifact_path()
        self.model: Any = None
        self.version: str = DEFAULT_MODEL_VERSION
        self.is_loaded: bool = False
        self.load_error: str | None = None
        self._load()

    def _resolve_artifact_path(self) -> Path:
        env_path = os.getenv("URL_MODEL_PATH")
        if env_path:
            return Path(env_path)

        candidates = [
            Path.cwd() / "ml" / "artifacts" / "url_classifier.joblib",
            Path.cwd() / "backend" / "app" / "ml" / "artifacts" / "url_classifier.joblib",
            Path(__file__).resolve().parent / "artifacts" / "url_classifier.joblib",
        ]
        for c in candidates:
            if c.exists():
                return c
        return candidates[0]

    def _load(self):
        if not self.artifact_path.exists():
            self.load_error = f"Artifact not found at {self.artifact_path}"
            self.is_loaded = False
            logger.warning("URL classifier artifact not found. Graceful fallback active.")
            return

        try:
            blob = joblib.load(self.artifact_path)
            if not isinstance(blob, dict) or "model" not in blob:
                raise ValueError("Corrupt artifact schema (missing 'model' dictionary key)")

            self.model = blob["model"]
            self.version = blob.get("model_version", DEFAULT_MODEL_VERSION)
            self.is_loaded = True
            self.load_error = None
        except Exception as e:
            self.load_error = f"Failed to load artifact: {type(e).__name__}: {e}"
            self.is_loaded = False
            self.model = None
            logger.warning(f"URL classifier failed to load: {e}. Graceful fallback active.")

    def predict_probability(self, normalized_url: str) -> float | None:
        """Returns calibrated suspicious probability (0.0 to 1.0) or None if model unavailable."""
        if not self.is_loaded or self.model is None:
            return None

        try:
            vec = extract_url_feature_vector(normalized_url)
            X = np.array([vec])
            probs = self.model.predict_proba(X)[0]
            # Probability of malicious class (index 1)
            p_malicious = float(probs[1]) if len(probs) > 1 else float(probs[0])
            return round(max(0.0, min(1.0, p_malicious)), 3)
        except Exception as e:
            logger.warning(f"Inference error in URL classifier: {e}")
            return None

    def get_status(self) -> dict:
        return {
            "status": "available" if self.is_loaded else "unavailable",
            "version": self.version,
            "error": self.load_error,
        }


def get_classifier() -> URLClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = URLClassifier()
    return _classifier_instance
