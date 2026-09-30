"""Evaluate: train/test split report for message baseline."""
import sys
sys.path.insert(0, "backend")
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from app.ml.message_classifier import SEED_CORPUS

texts = [t for t, _ in SEED_CORPUS]
labels = [l for _, l in SEED_CORPUS]
Xtr, Xte, ytr, yte = train_test_split(texts, labels, test_size=0.3, random_state=42)
vec = TfidfVectorizer(ngram_range=(1, 2), max_features=3000)
Xtrv = vec.fit_transform(Xtr)
Xtev = vec.transform(Xte)
clf = LogisticRegression(max_iter=500).fit(Xtrv, ytr)
pred = clf.predict(Xtev)
print(classification_report(yte, pred, zero_division=0))
print("confusion:", confusion_matrix(yte, pred).tolist())
