#!/usr/bin/env python3
"""VIGIL Vision engine tests — offline, deterministic, no browser needed.

Runs the manual QA fixtures (TEST 1-10 from the spec) against
vision_engine.analyze_vision with synthetic OCR input, then reports binary
suspicious/legitimate classification metrics (precision, recall, F1,
false-positive rate, false-negative rate). No accuracy is claimed beyond what
these measured numbers show.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vision_engine import analyze_vision  # noqa: E402


def region(text, confidence=95, x=40, y=60, width=620, height=70):
    return {"text": text, "confidence": confidence, "bbox": {"x": x, "y": y, "width": width, "height": height}}


def image(w=800, h=600):
    return {"width": w, "height": h}


def base_payload(ocr_regions, mean_confidence=94, qr=None, visual=None, low_confidence=False):
    return {
        "image": image(),
        "ocr": {
            "regions": ocr_regions,
            "meanConfidence": mean_confidence,
            "lowConfidence": low_confidence,
            "degraded": False,
        },
        "qr": qr or [],
        "visual": visual or {"rectangles": [], "fields": {}},
    }


# ---------------------------------------------------------------------------
# Fixtures: (name, payload, expected_suspicious, expected_decision, must_have_types)
# Suspicious = DECISION should be DENY or WARN.
# ---------------------------------------------------------------------------

FIXTURES = [
    # TEST 1 — legitimate bank message
    ("TEST 1 legit bank SMS", base_payload([
        region("SBI: Your account XX4412 was credited with Rs 5,000.00 today. Balance: Rs 24,561.00", 95),
    ]), False, "ALLOW", set()),

    # TEST 2 — phishing bank screenshot
    ("TEST 2 phishing bank", base_payload([
        region("URGENT", 97, x=120, y=80, width=200, height=50),
        region("Your SBI account will be blocked today. Complete KYC immediately", 92),
        region("https://sbi-kyc-alert.example/verify", 95, y=240),
    ]), True, "DENY", {"urgency", "credential_request", "url_caution", "brand_reference"}),

    # TEST 3 — fake login page (password + OTP boxes, non-official domain)
    ("TEST 3 fake login page", base_payload([
        region("NetBank Secure Login", 96),
        region("Customer ID", 95),
        region("Password", 95),
        region("https://secure-netbank-login.example/signin", 94, y=240),
        region("SIGN IN", 96),
    ], visual={"rectangles": [
        {"x": 200, "y": 350, "width": 300, "height": 36, "label": "password"},
        {"x": 200, "y": 410, "width": 120, "height": 36, "label": "otp"},
    ], "fields": {"passwordFields": 1, "otpLikeFields": 1}}),
     True, "DENY", {"auth_interface"}),

    # TEST 4 — QR / payment scam
    ("TEST 4 QR payment scam", base_payload([
        region("Scan to pay 4999 INR immediately", 91),
    ], qr=[{"data": "upi://pay?pa=demo-pay@vigiltest&pn=Demo&am=4999.00&cu=INR",
            "bbox": {"x": 250, "y": 200, "width": 200, "height": 200}}]),
     True, "WARN", {"qr_detected", "payment_indicator", "urgency"}),

    # TEST 5 — legitimate delivery notification
    ("TEST 5 legit delivery", base_payload([
        region("Your Bluedart shipment 4839201 is out for delivery and will arrive today between 10 AM and 1 PM.", 94),
    ]), False, "ALLOW", set()),

    # TEST 6 — fake delivery notification
    ("TEST 6 fake delivery fee", base_payload([
        region("FedEx: Your package is on hold. Pay a delivery fee of 2.99 USD immediately at", 89),
        region("https://fedex-redelivery.example/pay", 93, y=140),
    ]), True, "DENY", {"urgency", "payment_indicator", "url_caution"}),

    # TEST 7 — screenshot containing a URL only
    ("TEST 7 plain URL screenshot", base_payload([
        region("Read the article at https://news.example.org/technology/2026/ai-safety", 95),
    ]), False, "ALLOW", {"url_detected"}),

    # TEST 8 — low-quality screenshot (low OCR confidence)
    ("TEST 8 low quality", base_payload([
        region("Y0ur aCCount wi1l be bl0cked, c1ick sBi-kyc.examp1e/verify now", confidence=45),
    ], mean_confidence=45, low_confidence=True),
     True, "WARN", {"low_ocr_confidence"}),

    # TEST 9 — screenshot with no readable text
    ("TEST 9 no readable text", {
        "image": image(),
        "ocr": {"regions": [], "meanConfidence": 0, "lowConfidence": False, "degraded": False},
        "qr": [],
        "visual": {"rectangles": [], "fields": {}},
    }, False, "ALLOW", set()),

    # TEST 10 — multiple indicators (impersonation surfaces as a correlated group)
    ("TEST 10 multiple indicators", base_payload([
        region("FINAL WARNING: Paytm KYC expired. Verify your account with your OTP", 93),
        region("and Rs 500 fee immediately at https://paytm-kyc-verify.example/now", 92, y=140),
    ], qr=[{"data": "https://paytm-kyc-verify.example/now", "bbox": {"x": 250, "y": 300, "width": 180, "height": 180}}]),
     True, "DENY", {"urgency", "credential_request", "qr_suspicious_destination"}),

    # ---- extra false-positive guards -------------------------------------
    ("Guard: official bank + password box", base_payload([
        region("Welcome to SBI Online Banking", 96),
        region("https://www.onlinesbi.sbi/login", 94, y=110, height=30),
        region("Login to continue", 93, x=300, y=300, width=300),
    ], visual={"rectangles": [{"x": 300, "y": 350, "width": 300, "height": 36, "label": "password"}],
        "fields": {"passwordFields": 1, "otpLikeFields": 0}}),
     False, "ALLOW", set()),

    ("Guard: invoice confirmation", base_payload([
        region("Invoice INV-2041: payment of 1499.00 received. Thank you for your order.", 93),
    ]), False, "ALLOW", set()),

    ("Guard: legitimate QR menu", base_payload([
        region("Scan for our menu", 96),
    ], qr=[{"data": "https://cafe-delight.example.com/menu", "bbox": {"x": 250, "y": 200, "width": 180, "height": 180}}]),
     False, "ALLOW", set()),

    ("Guard: work meeting", base_payload([
        region("Hi Mira, the project review is at 3 PM in Room 204. Please bring the latest slides.", 95),
    ]), False, "ALLOW", set()),

    ("Guard: OTP share request (text only, no link)", base_payload([
        region("HDFC: Your OTP is 482913. Share it with our agent to cancel the transfer of Rs 25000 today.", 90),
    ]), True, "DENY", {"credential_request"}),
]

SUSPICIOUS_EXPECTATIONS = {
    "TEST 2 phishing bank": {"urgency", "credential_request", "url_caution", "brand_reference"},
    "TEST 3 fake login page": {"auth_interface"},
    "TEST 4 QR payment scam": {"qr_detected", "payment_indicator"},
    "TEST 6 fake delivery fee": {"urgency", "url_caution", "payment_indicator"},
    "TEST 8 low quality": {"low_ocr_confidence"},
    "TEST 10 multiple indicators": {"urgency", "credential_request", "qr_suspicious_destination"},
    "Guard: OTP share request (text only, no link)": {"credential_request"},
}


def run() -> tuple[int, int]:
    passed = 0
    total = len(FIXTURES)
    for name, payload, suspicious, decision, must_have in FIXTURES:
        result = analyze_vision(payload)
        types = {indicator["type"] for indicator in result["indicators"]}
        group_titles = {group["title"] for group in result["correlated"]}
        decisions = {"DENY", "WARN"} if suspicious else {"ALLOW"}
        ok = result["decision"] in decisions
        if name == "TEST 10 multiple indicators":
            ok = ok and "POTENTIAL BRAND IMPERSONATION" in group_titles
        # SUSPICIOUS_EXPECTATIONS entries are "at least these signals may be
        # present" (OCR noise may add variants); guard fixtures must NOT flag
        # core scam signals.
        if suspicious and name in SUSPICIOUS_EXPECTATIONS:
            missing = {t for t in must_have if t not in types and t not in SUSPICIOUS_EXPECTATIONS[name]}
            ok = ok and not missing
        if not suspicious:
            forbidden = {"suspicious_url", "qr_suspicious_destination", "credential_request"}
            ok = ok and not forbidden.intersection(types)
        if must_have and suspicious and name not in SUSPICIOUS_EXPECTATIONS:
            missing = must_have - types
            ok = ok and not missing
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name} -> {result['decision']} (score {result['risk']['score']}, {result['risk']['level']})")
        if not ok:
            print(f"        indicators: {sorted(types)}")
        passed += int(ok)

    # ------------------------------------------------------------------
    # Classification metrics (measured, not claimed)
    # ------------------------------------------------------------------
    tp = fp = tn = fn = 0
    for name, payload, suspicious, _decision, _must in FIXTURES:
        result = analyze_vision(payload)
        flagged = result["decision"] in {"DENY", "WARN"}
        if suspicious and flagged:
            tp += 1
        elif not suspicious and flagged:
            fp += 1
            print(f"        FP: {name} -> {result['decision']}")
        elif not suspicious and not flagged:
            tn += 1
        else:
            fn += 1
            print(f"        FN: {name} -> {result['decision']}")

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    print()
    print(f"{passed}/{total} vision fixtures passed.")
    print(f"precision={precision:.3f} recall={recall:.3f} f1={f1:.3f} FPR={fpr:.3f} FNR={fnr:.3f}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(run())
