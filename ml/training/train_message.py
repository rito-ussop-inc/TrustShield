"""Train message classifier artifact (TRD §15, §8)."""
import sys
sys.path.insert(0, "backend")
from pathlib import Path
from app.ml.message_classifier import train_and_save

if __name__ == "__main__":
    out = train_and_save(Path("ml/artifacts/message_classifier.joblib"))
    print(f"saved -> {out}")
