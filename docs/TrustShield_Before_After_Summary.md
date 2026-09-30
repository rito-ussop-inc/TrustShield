# TrustShield URL Analyzer — Before & After Summary

A simple, non-technical explanation of how the TrustShield URL Analyzer worked **before** and how it works **after** the recent security and user-experience upgrades.

> **Implementation status (verified 2026-09-30 against `main`):** items 1, 2, 4 (timeout/cache/sanitize), 5, 6, 7 are implemented as described. See notes under §3 and §4 for two honest corrections: the versioned URL-classifier artifact ships with a 150-sample curated, domain-grouped corpus snapshot (`data/url_dataset_v1.csv`, `url-corpus-v1.0.0`) rather than 40,000+ rows locally; per-provider threat-intel timeout is a strict 3 seconds (`DEFAULT_PROVIDER_TIMEOUT = 3`).

---

### 1. Link & Website Understanding (Domain Parsing)

* **Before:**
  * It read web links in a very basic way (just splitting words at dots `.`).
  * If a link was something like `amazon.co.uk` or `sbi.bank.gov.in`, it got confused about what the actual main company website was versus what was just a prefix or a country domain.
* **After:**
  * It now uses an offline global domain registry list (**Public Suffix List**).
  * It instantly identifies the real owner/website (e.g., discovering that `login.paypal.com.account-verify.xyz` actually sends you to `account-verify.xyz`, not PayPal).
* **Where in code:** `backend/app/analyzers/url/features.py` (`tldextract`, offline PSL, `extract_domain_info`).

---

### 2. Checking for Scam Words (Heuristic Rules)

* **Before:**
  * If the word `"login"` or `"verify"` appeared anywhere in a link (even in a safe link like `wikipedia.org/wiki/Login_security`), it would mistakenly treat it as dangerous (false alarm).
* **After:**
  * It is much smarter about **where** words appear. 
  * If someone puts `paypal-login` in the website domain to pretend to be PayPal, it flags it as an impersonation scam. But if you visit a normal educational page discussing logins, it won't panic or give false warnings.
* **Where in code:** `backend/app/analyzers/url/rules.py` — host-keyword hits (`URL_SUSPICIOUS_KEYWORD`, MEDIUM) vs path/query hits (`URL_PATH_KEYWORD`, LOW).

---

### 3. AI / Machine Learning Phishing Detection

* **Before:**
  * There was no real trained AI model in place — it was just a placeholder script with no real trained weights.
* **After:**
  * We ship a real, versioned Machine Learning URL classifier (`url-classifier-tabular-v1.0.0`, calibrated Random Forest over 27 component-aware features) plus the message classifier (`msg-tfidf-lr-v1.0.0`).
  * It was trained so that it doesn't just memorize website names; it looks at patterns, hidden redirects, and link structures to give a genuine probability score (e.g. *"92% likely to be a scam"*). Train/test splits are grouped by registrable domain, so no domain leaks between splits.
  * **Honest note:** the curated corpus snapshot in this repo is 150 rows (`data/url_dataset_v1.csv`, 107 train / 21 validation / 22 held-out test) — see `docs/url_model_card.md`. Any larger production training set lives outside this snapshot.
* **Where in code:** `backend/app/ml/url_classifier.py`, `backend/training/url_model/`, `ml/artifacts/`, `docs/url_model_card.md`.

---

### 4. Security Blacklist Checks (Threat Intelligence)

* **Before:**
  * It checked external threat databases one by one in a row. If one website database was slow or down, the whole app would freeze or take forever to load.
  * If you typed a link containing a password (`http://admin:1234@site.com`), that password could accidentally be sent over the internet to external databases.
* **After:**
  * All checks now run simultaneously with a strict **3-second timeout**. If one is unreachable, it doesn't hold up the rest.
  * It automatically scrubs and removes passwords before sending anything out.
  * It remembers recently checked links for 5 minutes so repeat checks appear instantly.
* **Where in code:** `backend/app/threat_intel/manager.py` (`asyncio.gather`, `Semaphore(5)`, `DEFAULT_PROVIDER_TIMEOUT = 3`, 300 s cache, `_sanitize_url_for_provider`).

---

### 5. Final Risk Scoring (How the Score is Calculated)

* **Before:**
  * It simply added up numbers without limits. A link with multiple minor flags could easily blow up the score unfairly.
* **After:**
  * It uses category caps so minor issues don't stack up unfairly.
  * **Honest Security Guarantee:** If a link is clean locally but live blacklist databases couldn't be contacted, it honestly tells you **`UNKNOWN / UNVERIFIED` (0/100)**. It will **never** mislead you by calling an unverified link "100% Guaranteed Safe".
* **Where in code:** `backend/app/scoring/engine.py` (`SCORING_VERSION = "scoring-v2.0.0"`, host cap 25 / lure cap 20 / obfuscation cap 15, ML channel max 25), `backend/app/trust_engine/engine.py` (UNKNOWN handling).

---

### 6. Results for Everyday Users (Plain Language UX)

* **Before:**
  * It only showed cryptic developer codes like `URL_PUNYCODE`, `tldextract match`, or `CalibratedClassifierCV`. A normal user couldn't tell what the problem was or what they should do.
* **After:**
  * A colorful, clear **Plain-Language Banner** is shown right at the top:
    * **Headline:** (e.g., `⚠️ Warning: Potential Fake Website / Phishing Lure`)
    * **What's Happening:** (e.g., *"This link mentions 'login' and 'paypal', but will actually take you to 'account-verify.xyz'"*)
    * **What You Should Do:** (e.g., *"🛑 Do NOT type your password or credit card here"*)
    * **Real Destination:** Shows the exact registered website you are about to visit.
    * **Unencrypted Warning:** Alerts you if the link is not secure (`http://`) and passwords can be spied on.
  * All technical details are tucked neatly into a collapsible section below.
* **Where in code:** `backend/app/schemas/models.py` (`PlainLanguageSummary`), `frontend/src/components/result.tsx` (`PlainLanguageBanner`), `frontend/src/pages/ResultPage.tsx`.

---

### 7. Recent Verifications (Activity History)

* **Before:**
  * Tested links were either not appearing in recent activity or showed random, unreadable IDs like `cb4af811-3d92...`.
* **After:**
  * As soon as you test any link, message, QR code, or file, it is automatically stored in your history.
  * The history shows the **actual URL/domain preview**, colored risk badges (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), and exact timestamps, with a 1-click button to view the full report anytime.
* **Where in code:** `backend/app/database/db.py` (`Analysis.input_summary`), `backend/app/api/routes/analyze.py` (`GET /analyses`), `frontend/src/pages/Dashboard.tsx`.

---

### Quick Summary Matrix

| Feature | Before | After |
| :--- | :--- | :--- |
| **Domain Reading** | Naive dot splitting | Smart Public Suffix List (PSL) extraction |
| **Scam Word Checks** | High false alarms on safe links | Context-aware (distinguishes fakes from legitimate pages) |
| **AI Classifier** | Placeholder stub | Versioned, calibrated AI with zero domain leakage (150-row curated snapshot in repo) |
| **Database Checks** | Slow, could hang or leak passwords | Fast (3s timeout), parallel, sanitized & cached |
| **Scoring** | Raw addition | Fair category caps + honest "Unverified" labels |
| **User Interface** | Technical jargon only | Plain-English summary & clear safety advice |
| **Recent Activity** | Blank or unreadable random IDs | Instant history with URL previews & risk tags |
