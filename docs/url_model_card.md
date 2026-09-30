# TRUSTSHIELD URL Classifier — Model Card & Documentation

**Model Name:** `url-classifier-tabular-v1.0.0`  
**Task:** Binary URL threat classification (Benign vs Malicious/Phishing/Malware)  
**Release Date:** September 2026  
**Pipeline:** Component-aware feature extraction -> Calibrated Tabular Classifier (Random Forest + Sigmoid Calibration)

---

## 1. Intended Use and Scope
- **Intended Use:** Assisting security analysis of arbitrary user-submitted URLs by assessing structural and component features. Acts as a supporting signal alongside deterministic rules and threat intelligence providers.
- **Out of Scope / Non-Goals:** The model is **not** an infallible verdict. It does not inspect dynamically rendered JavaScript, execute malware, or follow live network redirects. A low score from this model does **not** prove a link is safe.

---

## 2. Training Data and Provenance
- **Dataset Snapshot:** `data/url_dataset_v1.csv` (Version: `url-corpus-v1.0.0`)
- **Sources:**
  - *Benign Traffic & Popular Platforms:* Tranco Top Sites research sample and common web applications.
  - *Hard Negatives:* Legitimate authentication portals (Google, Microsoft, GitHub, Apple, Okta, Amazon), payment checkouts (Stripe, Shopify, PayPal), link shorteners (Bitly, TinyURL), and internationalized domains (IDN/Punycode).
  - *Phishing:* Confirmed phishing feeds from PhishTank verified research archive and OpenPhish public samples.
  - *Malware:* URLhaus (abuse.ch) active research feed snapshots.
- **Domain-Grouped Split Strategy:**
  - URLs are partitioned strictly by `registrable_domain` (using Public Suffix List). No domain appears in more than one split, guaranteeing **zero domain leakage** across training, validation, and held-out test splits.
  - Split: 70% Train (107 samples), 15% Validation (21 samples), 15% Frozen Held-Out Test (22 samples).

---

## 3. Features Schema
The model uses 27 component-aware numerical features:
1. `url_length`
2. `hostname_length`
3. `path_length`
4. `query_length`
5. `query_param_count`
6. `subdomain_count` (PSL-based)
7. `label_count`
8. `digit_count`
9. `special_count`
10. `is_ip_host` (binary)
11. `punycode` (binary)
12. `is_https` (binary)
13. `is_unusual_port` (binary)
14. `shortener` (binary)
15. `has_userinfo` (binary)
16. `encoded` (binary)
17. `double_encoded` (binary)
18. `has_nested_redirect_url` (binary)
19. `suspicious_structure` (binary)
20. `login_path` (binary)
21. `payment_path` (binary)
22. `has_credential_terms` (binary)
23. `has_payment_terms` (binary)
24. `host_kws_count`
25. `path_kws_count`
26. `query_kws_count`
27. `has_trailing_dot` (binary)

---

## 4. Model Selection and Validation Comparison
During training, candidate architectures were trained on the Train split and evaluated on the Validation split:
- **Logistic Regression (Standardized):** Val PR-AUC = 1.000, ROC-AUC = 1.000, F1 = 1.000, Log Loss = 0.0237
- **Random Forest (100 estimators, max depth 6):** Val PR-AUC = 1.000, ROC-AUC = 1.000, F1 = 1.000, Log Loss = 0.0436
- **Gradient Boosting (100 estimators, learning rate 0.08):** Val PR-AUC = 1.000, ROC-AUC = 1.000, F1 = 1.000, Log Loss = 0.0002

**Selected Architecture:** Random Forest was selected for robustness against feature scaling and resistance to outliers, followed by cross-validated probability calibration (`CalibratedClassifierCV`).

---

## 5. Held-Out Test Set Performance
Evaluated on the frozen, domain-independent test set:
- **ROC-AUC:** 1.000
- **PR-AUC:** 1.000
- **Inference Latency:** ~0.63 ms per URL
- **Artifact Size:** ~550 KB

### Operating Threshold Trade-offs:
| Operating Threshold | Precision | Recall | F1 Score | False Positive Rate | False Negative Rate |
|---------------------|-----------|--------|----------|---------------------|---------------------|
| **0.30 (Aggressive)** | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 |
| **0.50 (Balanced)**   | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 |
| **0.70 (Conservative)** | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 |

*Confusion Matrix on Held-Out Test Set:*
- True Negatives (TN): 10
- False Positives (FP): 0
- False Negatives (FN): 0
- True Positives (TP): 12

---

## 6. Limitations and Safety
1. **Zero-Day Obfuscation:** Attackers frequently register new legitimate-looking domains or utilize compromised trusted domains. Structural URL features alone cannot identify compromised benign sites without threat intelligence or content analysis.
2. **Shorteners:** Shorteners hide destination components; the model can flag the shortener structure, but cannot inspect destination features without expansion.
3. **No Safety Guarantees:** Output is an estimated probability of suspicious characteristics, not a guarantee that a link is harmless.
