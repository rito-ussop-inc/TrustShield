# Demo test cases (TRD §22) — all must pass without hard-coded detection

1. Benign URL `https://example.com` → low observed risk
2. Phishing-style URL `http://secure-login-verify.tk/login` → elevated risk via lexical evidence
3. Phishing message with URL → combined message + URL evidence
4. QR containing suspicious URL → decode + URL analysis
5. Document matching reference hash → integrity match (not authenticity)
6. Modified document → integrity mismatch
7. Unknown URL → UNKNOWN / low observed risk, never "SAFE"
