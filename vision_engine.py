"""VIGIL Vision — server-side security correlation for screenshot analysis.

Vision mode analyzes a screenshot in three layers:

1. OCR regions — text with its location on the image (produced in the browser
   by Tesseract.js, then verified and re-anchored here).
2. Deterministic security rules — VIGIL's existing content engine
   (``analyze_content``) runs on the OCR text so Vision reuses the same rules,
   URL analyzer, and decision logic as Message/URL/HTML modes.
3. Evidence correlation — co-located visual and contextual signals are grouped
   into correlated clusters that raise risk together, so no single weak
   indicator (a logo, a login form, one URL) can produce a scam verdict alone.

The browser never decides risk. This module owns detection, correlation, and
scoring, and it never invents evidence: every indicator cites either an OCR
region, a QR payload, or measured image properties.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Reuse VIGIL's existing engines — Vision must not fork the rule base.
from app import (
    BRAND_DOMAIN_TERMS,
    MAX_CONTENT_CHARS,
    analyze_urls,
    normalize_scan_text,
    parse_hostname,
    policy_decision,
)

VISION_MAX_IMAGE_BYTES = 10 * 1024 * 1024
VISION_MAX_DIMENSION = 5000
VISION_MAX_TEXT_CHARS = 200_000

# --------------------------------------------------------------------------
# Signal lexicons
# --------------------------------------------------------------------------

URGENCY_PATTERN = re.compile(
    r"(?i)\b(urgent|urgently|immediately|final warning|last warning|"
    r"act now|expires?(?: today)?|within \d+ (?:hours?|minutes?|days?)|"
    r"today only|right now|account (?:will be|is|has been) "
    r"(?:blocked|suspended|closed|deactivated)|limited time)\b"
)
CREDENTIAL_EXPLICIT_PATTERN = re.compile(
    r"(?i)\b(otp|one[- ]?time (?:password|code)|verification code|password|"
    r"credentials?|passcode|cvv|\bpin\b(?: number)?)\b"
)
# Soft credential terms: only escalate with a non-official destination nearby,
# so a legitimate bank's own "complete your KYC" notice is not over-flagged.
CREDENTIAL_SOFT_PATTERN = re.compile(
    r"(?i)\b(kyc|e[- ]?kyc|verify your (?:account|identity)|re[- ?]?verify|"
    r"identity verification|update your (?:account|details|records))\b"
)
PAYMENT_PATTERN = re.compile(
    r"(?i)\b(upi|payment|pay|fee|charges|transfer|cvv|card number|bank account|"
    r"neft|imps|rtgs|wallet|refund|processing fee|amount)\b"
)
CURRENCY_SYMBOLS = ("₹", "$", "€", "£", "¥")
MONEY_AMOUNT_PATTERN = re.compile(
    r"(?:(?:rs\.?|inr|usd|eur|gbp)\s?[\d,]+(?:\.\d{1,2})?)"
    r"|(?:(?i:₹|\$|€|£|¥)\s?\d[\d,]*(?:\.\d{1,2})?)"
    r"|(?:\d[\d,]{2,}(?:\.\d{1,2})?\s?(?i:rs|inr|usd|dollars?|rupees?|euros?))"
)
AUTH_BUTTON_PATTERN = re.compile(
    r"(?i)\b(login|log[- ]?in|sign[- ]?in|verify(?: account| now)?|continue|"
    r"submit|reset password|unlock account|confirm identity)\b"
)
URL_TEXT_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
BARE_DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![\w@.])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|in|io|co|info|biz|xyz|online|site|shop|link|app|"
    r"dev|top|club|icu|live|me|us|uk|example|invalid|test|localhost))\b(?!\.\w)"
)

# OCR often misreads “/” as l, I, i, |, or ! (e.g. "https:lisbi-kyc-alert
# .examplelverify"). URL recovery rewrites ONLY such fuzzy tokens for
# analysis; the raw OCR text stays displayed and recovered URLs are labeled.
FUZZY_URL_TOKEN = re.compile(r"(?i)\bhttps?[|lIi!1:;./]{1,6}\S{3,}|\bwww[|lIi!1:;.,]\S{3,}")
KNOWN_TLDS = (
    "example", "localhost", "invalid", "test", "info", "online", "club",
    "site", "shop", "link", "biz", "xyz", "app", "dev", "top", "icu",
    "live", "com", "net", "org", "edu", "gov", "in", "io", "co", "me",
    "us", "uk",
)
TLD_BOUNDARY = re.compile(
    r"\.(" + "|".join(sorted(KNOWN_TLDS, key=len, reverse=True)) + r")([a-z0-9].*)?$",
    re.I,
)

def recover_fuzzy_url_token(token: str) -> str | None:
    """Rewrite one OCR-mangled URL token into a analyzable candidate.

    Returns something like https://sbi-kyc-alert.example/verify, or None when
    the token cannot be confidently interpreted. Never mutates raw text.
    """
    token = token.strip().rstrip(".,;:!?)\"'")
    candidate = re.sub(r"(?i)^(https?)[:;|lIi!1./]{1,6}", r"\1://", token)
    if candidate == token:
        candidate = re.sub(r"(?i)^www[:;|lIi!1.,]{1,4}", "www.", token)
        if candidate == token:
            return None
        candidate = "https://" + candidate
    match = re.match(r"(?i)^(https?://)([a-z0-9-]+(?:\.[a-z0-9-]+)*)(.*)$", candidate)
    if not match:
        return None
    scheme, host_part, remainder = match.group(1), match.group(2), match.group(3)
    # Host must end at a known TLD boundary; anything glued after it is a
    # path whose leading “/” was misread as a letter.
    boundary = TLD_BOUNDARY.search(host_part)
    if not boundary:
        return None
    host = host_part[: boundary.end(1)]
    glued_path = (boundary.group(2) or "") + remainder
    return scheme + host + ("/" + glued_path.lstrip("/|lIi!1") if glued_path else "")

def recover_urls_from_ocr(text: str) -> list[str]:
    recovered: list[str] = []
    seen: set[str] = set()
    for match in FUZZY_URL_TOKEN.finditer(text):
        candidate = recover_fuzzy_url_token(match.group(0))
        if not candidate:
            continue
        host_pair = parse_hostname(candidate)
        key = host_pair[1] or candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        recovered.append(candidate)
    return recovered
PHONE_PATTERN = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s-]?)?(?:\(?\d[\d\s().-]{7,15}\d)"
)
EMAIL_PATTERN = re.compile(
    r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"
)

# Brand references are treated as *context only*. A brand name in a screenshot
# is never impersonation on its own — it needs corroborating evidence.
BRAND_REFERENCES = {
    "sbi": "SBI",
    "state bank": "SBI",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis bank": "Axis Bank",
    "paytm": "Paytm",
    "googlepay": "Google Pay",
    "google pay": "Google Pay",
    "gpay": "Google Pay",
    "phonepe": "PhonePe",
    "amazon": "Amazon",
    "flipkart": "Flipkart",
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "google": "Google",
    "apple": "Apple",
    "netflix": "Netflix",
    "whatsapp": "WhatsApp",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "dhl": "DHL",
    "fedex": "FedEx",
    "bluedart": "Bluedart",
    "india post": "India Post",
}

# Well-known legitimate domains live in app.BRAND_DOMAIN_TERMS (shared with
# the message/HTML rules) so Vision and the other modes never disagree about
# what counts as an official brand domain.

# Display names for brand terms, keyed exactly like app.BRAND_DOMAIN_TERMS.
BRAND_REFERENCE_BY_KEY: dict[str, str] = {
    "sbi": "SBI",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis bank": "Axis Bank",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "google pay": "Google Pay",
    "gpay": "Google Pay",
    "amazon": "Amazon",
    "flipkart": "Flipkart",
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "google": "Google",
    "apple": "Apple",
    "netflix": "Netflix",
    "whatsapp": "WhatsApp",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "dhl": "DHL",
    "fedex": "FedEx",
    "bluedart": "Bluedart",
    "india post": "India Post",
}

ALLOWED_URL_SCHEMES = ("http", "https")

# OCR-noise tolerance: common character substitutions (0/O, 1/I/L, 3/E, 4/A,
# 5/S, 7/T, 8/B) inside mixed letter+digit tokens. Applied ONLY to a normalized
# copy of the text used for pattern/URL matching — displayed evidence always
# shows the raw OCR text, and any match found only in the normalized copy is
# labeled as such.
_LEET_MAP_A = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})
_LEET_MAP_B = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
_MIXED_TOKEN = re.compile(r"(?<![\w])[A-Za-z0-9@$_-]*[A-Za-z][A-Za-z0-9@$_-]*\d[A-Za-z0-9@$_-]*|[A-Za-z0-9@$_-]*\d[A-Za-z0-9@$_-]*[A-Za-z][A-Za-z0-9@$_-]*(?![\w])")

def _normalize_mixed_tokens(text: str, table) -> str:
    """Apply `table` only to tokens that mix letters and digits (or @/$)."""
    def replace_token(match: re.Match) -> str:
        token = match.group(0)
        letters = any(char.isalpha() for char in token)
        digits = any(char.isdigit() for char in token)
        if letters and digits:
            return token.translate(table)
        return token
    return _MIXED_TOKEN.sub(replace_token, text)

def matching_variants(raw_text: str) -> list[str]:
    """[raw, leet-A, leet-B] variants for matching; raw stays first."""
    if not raw_text:
        return [""]
    variants = [raw_text]
    for table in (_LEET_MAP_A, _LEET_MAP_B):
        normalized = _normalize_mixed_tokens(raw_text, table)
        if normalized not in variants:
            variants.append(normalized)
    return variants

def find_pattern(variants: list[str], pattern: re.Pattern) -> tuple[re.Match | None, bool]:
    """Match `pattern` against variants; returns (match, is_normalized)."""
    match = pattern.search(variants[0])
    if match:
        return match, False
    for variant in variants[1:]:
        match = pattern.search(variant)
        if match:
            return match, True
    return None, False


def locate_indicator_bbox(indicator: dict, regions: list[dict]) -> None:
    """Anchor an indicator to the OCR region(s) containing its evidence.

    Sets indicator["bbox"] (union of matching regions) and regionIndexes.
    Indicators that already carry a bbox (QR codes, visual structures) or have
    no locatable text are left untouched. This is what makes the evidence
    overlay possible: every text-derived finding points at WHERE it appears.
    """
    if indicator.get("bbox") is not None or not regions:
        return
    detected = normalize_scan_text(str(indicator.get("detected", ""))).strip().lower()
    if not detected:
        return
    tokens = [token for token in re.split(r"[^a-z0-9]+", detected) if len(token) >= 4]
    scored: list[tuple[int, dict]] = []
    for region in regions:
        region_text = normalize_scan_text(region["text"]).strip().lower()
        if not region_text:
            continue
        score = 0
        if detected in region_text:
            score = 100 + len(detected)
        else:
            score = sum(1 for token in tokens if token in region_text)
            # Long-token bonus: a rare token (e.g. a hostname) is strong evidence.
            if score and max((len(token) for token in tokens), default=0) >= 6:
                score += 1
        if score > 0:
            scored.append((score, region))
    if not scored:
        return
    best_score = max(score for score, _ in scored)
    matched = [region for score, region in scored if score >= max(1, best_score - 1)][:3]
    indicator["bbox"] = region_union_bbox(matched)
    indicator["regionIndexes"] = [region["index"] for region in matched]

# Weights. Vision borrows VIGIL's severity ladder: high findings gate the
# decision; medium findings warn. Weights only inform the displayed score and
# the WHY breakdown — the decision itself comes from VIGIL's policy engine.
SIGNAL_WEIGHTS = {
    "suspicious_url": 25,
    "url_caution": 15,
    "qr_suspicious_destination": 22,
    "qr_detected": 8,
    "credential_request": 20,
    "auth_interface": 15,
    "payment_indicator": 10,
    "urgency": 15,
    "brand_reference": 5,
    "potential_impersonation": 15,
    "low_ocr_confidence": 0,
    "no_text_detected": 0,
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _clamp(value: int | float, low: int, high: int) -> int | float:
    return max(low, min(high, value))


def _decode_region_text(value: object) -> str:
    """Regions arrive as JSON strings; accept str or list-of-int fallback."""
    if isinstance(value, str):
        return value
    return ""


def region_union_bbox(regions: list[dict]) -> dict | None:
    """Smallest box covering all given OCR regions, or None."""
    boxes = [region["bbox"] for region in regions if region.get("bbox")]
    if not boxes:
        return None
    x1 = min(box["x"] for box in boxes)
    y1 = min(box["y"] for box in boxes)
    x2 = max(box["x"] + box["width"] for box in boxes)
    y2 = max(box["y"] + box["height"] for box in boxes)
    return {"x": x1, "y": y1, "width": x2 - x1, "height": y2 - y1}


def normalize_ocr_regions(regions: object, image_size: dict | None) -> list[dict]:
    """Validate and clamp OCR regions from the client. Drops anything unsafe.

    Expected region: {"text": str, "confidence": 0-100, "bbox": {x,y,w,h}}
    """
    if not isinstance(regions, list):
        return []
    image_w = 0
    image_h = 0
    if isinstance(image_size, dict):
        try:
            image_w = int(image_size.get("width") or 0)
            image_h = int(image_size.get("height") or 0)
        except (TypeError, ValueError):
            image_w = image_h = 0

    normalized: list[dict] = []
    for index, raw in enumerate(regions):
        if not isinstance(raw, dict):
            continue
        text = _decode_region_text(raw.get("text"))
        if not text.strip():
            continue
        try:
            confidence = float(raw.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = _clamp(confidence, 0, 100)
        bbox = raw.get("bbox")
        box: dict | None = None
        if isinstance(bbox, dict):
            try:
                x = _clamp(int(float(bbox.get("x", 0))), 0, max(image_w, 1) - 1) if image_w else int(float(bbox.get("x", 0)))
                y = _clamp(int(float(bbox.get("y", 0))), 0, max(image_h, 1) - 1) if image_h else int(float(bbox.get("y", 0)))
                w = int(float(bbox.get("width", 0)))
                h = int(float(bbox.get("height", 0)))
            except (TypeError, ValueError):
                box = None
            else:
                if w > 0 and h > 0 and (not image_w or (x + w <= image_w + 8 and y + h <= image_h + 8)):
                    box = {"x": x, "y": y, "width": w, "height": h}
        if box is None:
            continue
        normalized.append({
            "index": len(normalized),
            "text": text,
            "confidence": confidence,
            "bbox": box,
        })
    return normalized


def join_region_text(regions: list[dict]) -> str:
    """Rebuild flowing text from regions, breaking lines between rows.

    Regions whose rows differ by more than 60% of a height are separated by a
    newline so rule matching sees structure similar to what was rendered.
    """
    if not regions:
        return ""
    ordered = sorted(regions, key=lambda r: (r["bbox"]["y"], r["bbox"]["x"]))
    lines: list[list[dict]] = []
    for region in ordered:
        placed = False
        if lines:
            last_line = lines[-1]
            reference = last_line[0]["bbox"]
            height = max(reference["height"], region["bbox"]["height"], 1)
            delta = abs(reference["y"] - region["bbox"]["y"])
            if delta <= height * 0.6:
                last_line.append(region)
                placed = True
        if not placed:
            lines.append([region])
    parts: list[str] = []
    for line in lines:
        line.sort(key=lambda r: r["bbox"]["x"])
        parts.append(" ".join(region["text"].strip() for region in line))
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Indicator builders
# --------------------------------------------------------------------------

def make_indicator(
    kind: str,
    severity: str,
    label: str,
    detected: str,
    source: str,
    confidence: float,
    reason: str,
    bbox: dict | None = None,
    region_indexes: list[int] | None = None,
) -> dict:
    indicator = {
        "type": kind,
        "severity": severity,  # high | medium | low | info — matches VIGIL's ladder
        "label": label,
        "detected": detected[:240],
        "source": source,
        "confidence": round(_clamp(confidence, 0, 100), 1),
        "reason": reason,
    }
    if bbox is not None:
        indicator["bbox"] = bbox
    if region_indexes:
        indicator["regionIndexes"] = region_indexes
    return indicator


def severity_to_color(severity: str) -> str:
    return {"high": "red", "medium": "orange", "low": "blue", "info": "blue"}.get(severity, "blue")


# --------------------------------------------------------------------------
# URL analysis (routes through VIGIL's existing URL analyzer)
# --------------------------------------------------------------------------

def extract_urls_from_text(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_TEXT_PATTERN.findall(text):
        found.append(match.rstrip(".,;:!?)\"'"))
    if not found:
        for match in BARE_DOMAIN_PATTERN.finditer(text):
            candidate = match.group(1)
            # Require at least two labels and a plausible length to avoid
            # treating file names or version numbers as hosts.
            if candidate.count(".") >= 1 and len(candidate) >= 4:
                tail = text[match.end():match.end() + 2]
                if not tail.startswith("/"):
                    found.append(candidate)
                else:
                    # Capture a trailing path when directly attached.
                    path_match = re.match(r"[^\s<>\"'`]+", text[match.start():])
                    if path_match:
                        found.append(path_match.group(0).rstrip(".,;:!?)\"'"))
    deduped: list[str] = []
    seen_hosts: set[str] = set()
    for url in found:
        host_pair = parse_hostname(url)
        key = host_pair[1] or url.lower()
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        deduped.append(url)
    return deduped[:8]


def analyze_single_url(url: str) -> dict:
    """Run VIGIL's URL analyzer on one URL and shape the result for Vision.

    Returns {"url", "host", "findings": [{id, severity, fact}], "risky": bool}.
    Never invents threat-intelligence results and never calls a network.
    """
    findings = analyze_urls(url)
    shaped = [
        {"id": item["id"], "severity": item["severity"], "fact": item["fact"]}
        for item in findings
    ]
    original_host, ascii_host = parse_hostname(url)
    risky = any(item["severity"] in {"medium", "high"} for item in shaped)
    scheme = ""
    try:
        candidate = url.strip().rstrip(".,;:!?)]")
        if not re.match(r"(?i)^https?://", candidate):
            candidate = "https://" + candidate
        scheme = urlsplit(candidate).scheme.lower()
    except ValueError:
        scheme = ""
    return {
        "url": url,
        "host": ascii_host or original_host or "",
        "scheme": scheme,
        "findings": shaped,
        "risky": risky,
    }


def brand_official_match(brand_key: str, host: str) -> bool:
    """True if `host` is (a subdomain of) an official domain for `brand_key`.

    Uses the shared BRAND_DOMAIN_TERMS table from app.py. Brands with no
    confident official-domain list (the "official:" marker) never match here.
    """
    official_all = BRAND_DOMAIN_TERMS.get(brand_key, ())
    official = tuple(d for d in official_all if not d.startswith("official:"))
    if not official or not host:
        return False
    host = host.lower().lstrip(".").rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in official)


# --------------------------------------------------------------------------
# Main pipeline
# --------------------------------------------------------------------------

def analyze_vision(payload: dict) -> dict:
    """Full Vision pipeline. Input keys (all produced client-side, verified here):

    - image: {width, height, sizeBytes, type}
    - ocr: {regions: [...], meanConfidence, lowConfidence: bool, degraded: bool}
    - qr: [{data, bbox}] (bbox optional; decoded locally by jsQR)
    - visual: {rectangles: [{x,y,width,height,label}], fields: {...}}
    - editedText: optional user-corrected text (marked as user-edited)
    """
    image = payload.get("image") if isinstance(payload.get("image"), dict) else {}
    ocr = payload.get("ocr") if isinstance(payload.get("ocr"), dict) else {}
    qr_codes = payload.get("qr") if isinstance(payload.get("qr"), list) else []
    visual = payload.get("visual") if isinstance(payload.get("visual"), dict) else {}
    edited_text = payload.get("editedText")
    edited_text = edited_text if isinstance(edited_text, str) and edited_text.strip() else None
    was_edited = bool(edited_text)

    image_size = {
        "width": image.get("width") or 0,
        "height": image.get("height") or 0,
    }

    # ---- 1. Validate & normalize the OCR regions -------------------------
    regions = normalize_ocr_regions(ocr.get("regions"), image_size)
    text = edited_text[:VISION_MAX_TEXT_CHARS] if edited_text else join_region_text(regions)[:VISION_MAX_TEXT_CHARS]
    text = normalize_scan_text(text)  # strip zero-width chars; reuse VIGIL's normalizer
    scan_text = text[:MAX_CONTENT_CHARS]

    mean_confidence = 0.0
    try:
        mean_confidence = float(ocr.get("meanConfidence") or 0)
    except (TypeError, ValueError):
        mean_confidence = 0.0
    mean_confidence = _clamp(mean_confidence, 0, 100)
    low_confidence = bool(ocr.get("lowConfidence")) or (
        bool(regions) and mean_confidence < 60
    )
    degraded = bool(ocr.get("degraded")) or (not regions and bool(text.strip()) is False and bool(payload.get("ocr")))
    no_text = not text.strip() and not regions

    indicators: list[dict] = []
    correlated_groups: list[dict] = []
    extracted: dict = {
        "text": text if text.strip() else "",
        "textWasEdited": was_edited,
        "urls": [],
        "phones": [],
        "emails": [],
        "qrCodes": [],
        "brandReferences": [],
        "paymentIndicators": [],
    }

    # ---- 2. Low-confidence / no-text notices ------------------------------
    if degraded and not low_confidence:
        low_confidence = True
    if low_confidence and not no_text:
        indicators.append(make_indicator(
            "low_ocr_confidence", "info", "Low-confidence text",
            "Some text could not be confidently extracted.",
            "OCR", max(mean_confidence, 1) if mean_confidence else 40,
            "OCR confidence was low; treat extracted text as a lead, not proof. You can edit the text and re-run the analysis.",
        ))

    # ---- 3. URL extraction + VIGIL URL analyzer ---------------------------
    url_results: list[dict] = []
    variants = matching_variants(text)
    recovered_url_set = set(recover_urls_from_ocr(text)) if text.strip() else set()
    if text.strip():
        seen_url_keys: set[str] = set()
        ordered_urls: list[str] = []
        for variant_index, variant in enumerate(variants):
            for url in extract_urls_from_text(variant):
                host_pair = parse_hostname(url)
                key = host_pair[1] or url.lower()
                if key in seen_url_keys:
                    continue
                seen_url_keys.add(key)
                ordered_urls.append(url)
        raw_urls = extract_urls_from_text(variants[0]) if variants else []
        # Second chance: recover URLs whose “/” was misread as a letter by OCR.
        for recovered in recover_urls_from_ocr(text):
            host_pair = parse_hostname(recovered)
            key = host_pair[1] or recovered.lower()
            if key in seen_url_keys:
                continue
            seen_url_keys.add(key)
            ordered_urls.append(recovered)
        for url in ordered_urls[:8]:
            result = analyze_single_url(url)
            result["fromNormalized"] = url not in raw_urls
            result["recovered"] = url in recovered_url_set
            url_results.append(result)
    extracted["urls"] = [{"url": r["url"], "host": r["host"], "risky": r["risky"]} for r in url_results]

    for result in url_results:
        host = result["host"] or ""
        # Brand-in-domain caution: a brand term embedded in a NON-official
        # hostname is a caution signal, never a certainty.
        brand_mismatch_brands: list[str] = []
        host_lower = host.lower()
        host_compact = host_lower.replace("-", "")
        for brand_key, display in BRAND_REFERENCE_BY_KEY.items():
            if len(brand_key) < 3:
                continue
            if brand_key not in host_compact and brand_key not in host_lower:
                continue
            if not brand_official_match(brand_key, host):
                if display not in brand_mismatch_brands:
                    brand_mismatch_brands.append(display)
        if brand_mismatch_brands and not any(ind["type"] == "url_caution" and ind["detected"] == result["url"] for ind in indicators):
            source = "URL analyzer · recovered from OCR" if result.get("recovered") else "URL analyzer"
            confidence = 72 if result.get("recovered") else 85
            extra = (
                " (the “/” characters were likely misread as letters by OCR — the address was recovered for analysis and may be imperfect)"
                if result.get("recovered") else ""
            )
            indicators.append(make_indicator(
                "url_caution", "medium", "Brand reference in address",
                result["url"], source, confidence,
                "The address contains the brand term "
                + " / ".join(brand_mismatch_brands)
                + " but is not an official domain for that brand. Verify the address carefully before trusting it."
                + extra,
                region_indexes=result.get("regionIndexes") or None,
            ))
            continue
        if result["risky"]:
            worst = max(
                (f for f in result["findings"] if f["severity"] in {"medium", "high"}),
                key=lambda f: {"high": 2, "medium": 1}.get(f["severity"], 0),
                default=None,
            )
            reason = worst["fact"] if worst else "VIGIL's URL analyzer flagged structural warning signs in this address."
            indicators.append(make_indicator(
                "suspicious_url", "high", "Suspicious URL",
                result["url"], "URL analyzer" + (" · recovered from OCR" if result.get("recovered") else ""),
                80 if result.get("recovered") else 95, reason,
            ))
        else:
            indicators.append(make_indicator(
                "url_detected", "info", "URL detected",
                result["url"], "URL analyzer", 95,
                "No structural warning signs were found for this address. This is not a safety guarantee — VIGIL does not visit links.",
            ))

    # ---- 4. QR codes -------------------------------------------------------
    qr_results: list[dict] = []
    for qr in qr_codes[:6]:
        if not isinstance(qr, dict):
            continue
        data = qr.get("data")
        if not isinstance(data, str) or not data.strip():
            continue
        data = data.strip()
        bbox = qr.get("bbox") if isinstance(qr.get("bbox"), dict) else None
        entry: dict = {"data": data[:500], "bbox": bbox}
        url_result = None
        looks_url = bool(re.match(r"(?i)^(https?://|www\.)", data)) or bool(BARE_DOMAIN_PATTERN.search(data.split("/")[0]))
        if looks_url:
            url_result = analyze_single_url(data if re.match(r"(?i)^https?://", data) else "https://" + data.lstrip("/"))
            entry["urlAnalysis"] = {
                "host": url_result["host"],
                "risky": url_result["risky"],
                "findings": url_result["findings"],
            }
            if url_result["risky"]:
                worst = max(
                    (f for f in url_result["findings"] if f["severity"] in {"medium", "high"}),
                    key=lambda f: {"high": 2, "medium": 1}.get(f["severity"], 0),
                    default=None,
                )
                indicators.append(make_indicator(
                    "qr_suspicious_destination", "high", "QR code with suspicious destination",
                    data, "QR decoder + URL analyzer", 95,
                    worst["fact"] if worst else "The QR code encodes an address with structural warning signs.",
                    bbox=bbox,
                ))
            else:
                indicators.append(make_indicator(
                    "qr_detected", "low", "QR code detected",
                    data, "QR decoder", 99,
                    "The QR code encodes a web address. No structural warning signs were found in the address itself, and VIGIL did not open it. QR destinations should always be checked before opening — see the URL security analysis below.",
                    bbox=bbox,
                ))
        elif re.match(r"(?i)^(upi://|bitcoin:|ether:|pay:)", data):
            entry["payment"] = True
            extracted["paymentIndicators"].append(f"QR payment intent: {data[:120]}")
            indicators.append(make_indicator(
                "qr_detected", "medium", "QR payment request",
                data, "QR decoder", 99,
                "The QR code encodes a payment intent (UPI or wallet URI). Verify the payee before paying.",
                bbox=bbox,
            ))
        else:
            indicators.append(make_indicator(
                "qr_detected", "info", "QR code detected",
                data, "QR decoder", 99,
                "A QR code was decoded. Its payload is not a web address; inspect the decoded value before acting on it.",
                bbox=bbox,
            ))
        qr_results.append(entry)
    extracted["qrCodes"] = [
        {"data": entry["data"], "risky": bool(entry.get("urlAnalysis", {}).get("risky"))}
        for entry in qr_results
    ]

    # ---- 5. Visual structures (measured, not guessed) ----------------------
    rectangles = visual.get("rectangles") if isinstance(visual.get("rectangles"), list) else []
    fields = visual.get("fields") if isinstance(visual.get("fields"), dict) else {}
    password_fields = int(fields.get("passwordFields") or 0)
    otp_like_fields = int(fields.get("otpLikeFields") or 0)
    auth_words = visual.get("authWords") if isinstance(visual.get("authWords"), list) else []

    password_regions = [r for r in rectangles if r.get("label") == "password"]
    otp_regions = [r for r in rectangles if r.get("label") == "otp"]

    # Credential requests: explicit asks are high-severity on their own; soft
    # KYC/verify terms escalate only when a non-official destination exists.
    explicit_match, explicit_normalized = find_pattern(variants, CREDENTIAL_EXPLICIT_PATTERN) if text else (None, False)
    soft_match, soft_normalized = find_pattern(variants, CREDENTIAL_SOFT_PATTERN) if text else (None, False)
    unofficial_destinations = [
        r for r in url_results
        if not any(
            brand_official_match(key, r["host"])
            for key in BRAND_DOMAIN_TERMS
        )
    ]
    has_unofficial_destination = bool(unofficial_destinations) or any(
        entry.get("urlAnalysis", {}).get("risky") for entry in qr_results
    )
    has_credential_text = bool(explicit_match) or (bool(soft_match) and has_unofficial_destination)
    if explicit_match:
        indicators.append(make_indicator(
            "credential_request", "high", "Credential or code request",
            explicit_match.group(0), "Rules engine", 92,
            "The text asks for a password, OTP, or verification code — credentials should never be shared in response to a message.",
        ))
    elif soft_match and has_unofficial_destination:
        indicators.append(make_indicator(
            "credential_request", "high", "Verification / KYC request",
            soft_match.group(0), "Rules engine", 85,
            "The screenshot asks for identity verification or KYC while pointing at a non-official destination — a common account-takeover pattern.",
        ))
    elif soft_match:
        indicators.append(make_indicator(
            "verification_request", "info", "Verification request",
            soft_match.group(0), "Rules engine", 85,
            "The content mentions identity verification or KYC. Check that the request comes from the organization's official app or website.",
        ))

    # Authentication interface: password/OTP input boxes (measured geometry)
    if password_regions or otp_like_fields > 0:
        if password_regions:
            box = password_regions[0]
            reason = "A masked password input was detected by its dot-mask pattern."
            detected = "Password input field"
        else:
            box = otp_regions[0] if otp_regions else None
            reason = "A single-digit input pattern typical of OTP/PIN entry was detected."
            detected = "OTP/PIN-style input field"
        indicators.append(make_indicator(
            "auth_interface", "medium", "Authentication interface",
            detected, "Visual pattern detection", 80, reason,
            bbox=box if isinstance(box, dict) else None,
        ))

    # Urgency / time pressure — exact quoted evidence from the rules
    if text.strip():
        urgency_match, urgency_normalized = find_pattern(variants, URGENCY_PATTERN)
        if urgency_match:
            indicators.append(make_indicator(
                "urgency", "medium", "Urgency / time pressure" + (" (normalized text)" if urgency_normalized else ""),
                urgency_match.group(0), "Rules engine" + (" · normalized" if urgency_normalized else ""), 78 if urgency_normalized else 90,
                "Pressure to act immediately is a common social-engineering cue." + (" This match was found after normalizing OCR noise (for example 0→o, 1→l); verify it against the screenshot." if urgency_normalized else ""),
            ))

    # Payment indicators
    payment_hits: list[str] = []
    payment_match = PAYMENT_PATTERN.search(text) if text else None
    if payment_match:
        payment_hits.append(payment_match.group(0))
    for symbol in CURRENCY_SYMBOLS:
        if symbol in text:
            payment_hits.append(symbol)
    amount_match = MONEY_AMOUNT_PATTERN.search(text) if text else None
    if amount_match:
        payment_hits.append(amount_match.group(0))
    payment_hits = list(dict.fromkeys(hit.strip() for hit in payment_hits))[:4]
    if payment_hits:
        extracted["paymentIndicators"].extend(payment_hits)
        # Corroboration rule: payment content alone must not push a verdict.
        # It becomes a caution-level (orange) signal only when urgency, a QR
        # payment intent, or a non-official destination appears alongside it.
        payment_corroborated = (
            any(ind["type"] == "urgency" for ind in indicators)
            or has_unofficial_destination
            or any(entry.get("payment") for entry in qr_results)
        )
        indicators.append(make_indicator(
            "payment_indicator", "medium" if payment_corroborated else "low",
            "Payment indicator",
            ", ".join(payment_hits), "Rules engine", 85,
            "Payment-related content appears in this screenshot. Payment content alone does not prove a scam — check who is requesting it.",
        ))

    # Contact indicators — contextual only, never proof of malice
    if text.strip():
        phones = list(dict.fromkeys(m.group(0).strip() for m in PHONE_PATTERN.finditer(text)))[:4]
        emails = list(dict.fromkeys(m.group(0) for m in EMAIL_PATTERN.finditer(text)))[:4]
        # Filter obvious non-phone numbers (dates, amounts already matched as money)
        phones = [p for p in phones if len(re.sub(r"\D", "", p)) >= 8]
        extracted["phones"] = phones
        extracted["emails"] = emails
        if phones or emails:
            sample = phones[0] if phones else emails[0]
            indicators.append(make_indicator(
                "contact_indicator", "info", "Contact indicators",
                ", ".join((phones[:2] if phones else []) + (emails[:2] if emails else [])),
                "Pattern extraction", 80,
                "Contact details appear in the screenshot. Their presence alone is not evidence of a scam.",
            ))

    # Brand references — context only
    brand_hits: list[tuple[str, str]] = []
    lower_text = text.lower()
    for key, display in BRAND_REFERENCES.items():
        idx = lower_text.find(key)
        if idx >= 0:
            brand_hits.append((display, text[idx:idx + len(key)]))
    brand_hits = list({display: (display, quote) for display, quote in brand_hits}.values())[:5]
    if brand_hits:
        extracted["brandReferences"] = [display for display, _ in brand_hits]
        for display, quote in brand_hits:
            indicators.append(make_indicator(
                "brand_reference", "info", "Brand reference",
                quote, "Text pattern", 80,
                f"This screenshot references {display}. A brand name alone is not impersonation — it is correlated with URLs, urgency, and requests below.",
            ))

    # ---- 6. Evidence correlation -------------------------------------------
    correlation_pairs: list[dict] = []
    has_url = any(ind["type"] in {"suspicious_url", "qr_suspicious_destination", "url_caution"} for ind in indicators)
    has_urgency = any(ind["type"] == "urgency" for ind in indicators)
    has_credential = any(ind["type"] in {"credential_request", "auth_interface"} for ind in indicators)
    has_payment = bool(payment_hits) or any(
        ind["type"] == "payment_indicator" and ind["severity"] == "medium"
        or ind["type"] == "qr_detected" and ind["severity"] in {"medium", "low"} and bool(entry.get("urlAnalysis"))
        for ind, entry in zip([i for i in indicators if i["type"] == "qr_detected"], qr_results)
    )
    # QR-detection info usable for correlation without over-claiming.
    qr_url_entries = [entry for entry in qr_results if entry.get("urlAnalysis")]
    has_payment = bool(payment_hits) or any(
        ind["type"] == "payment_indicator" and ind["severity"] == "medium" for ind in indicators
    ) or any(entry.get("payment") for entry in qr_results)
    has_brand = bool(brand_hits)
    # If every found URL sits on the referenced brand's official domain,
    # impersonation correlation must NOT fire — that is how a legitimate
    # banking page (bank logo + login form + bank domain) stays calm.
    no_official_brand_match = True
    if has_brand and url_results:
        official_any = False
        for display, _quote in brand_hits:
            for key, official_domains in BRAND_DOMAIN_TERMS.items():
                if BRAND_REFERENCE_BY_KEY.get(key) == display:
                    for r in url_results:
                        host = (r["host"] or "").lower()
                        if any(host == d or host.endswith("." + d) for d in official_domains):
                            official_any = True
        no_official_brand_match = not official_any

    # Correlated cluster A: brand + (suspicious URL | credential | urgency)
    # A QR encoding a non-official web address counts as "unverified link".
    if has_brand and no_official_brand_match and (has_url or has_credential or has_urgency or qr_url_entries):
        contributing = [display for display, _ in brand_hits]
        elements = ["Brand reference in the content"]
        if has_url or qr_url_entries:
            elements.append("External or unverified link")
        if has_credential:
            elements.append("Request for credentials or codes")
        if has_urgency:
            elements.append("Urgency / time pressure")
        group = {
            "title": "POTENTIAL BRAND IMPERSONATION",
            "summary": (
                "A brand reference appears together with "
                + (", ".join(elements[1:]) if len(elements) > 1 else "a suspicious request")
                + ". This combination is a common impersonation pattern, but VIGIL cannot verify the actual sender — treat it as a strong caution, not proof."
            ),
            "indicators": ["brand_reference"]
            + (["suspicious_url"] if has_url else [])
            + (["qr_suspicious_destination"] if any(i["type"] == "qr_suspicious_destination" for i in indicators) else [])
            + (["qr_detected"] if qr_url_entries else [])
            + (["credential_request", "auth_interface"] if has_credential else [])
            + (["urgency"] if has_urgency else []),
            "brands": contributing,
            "riskContribution": SIGNAL_WEIGHTS["potential_impersonation"],
            "severity": "medium",
        }
        correlated_groups.append(group)

    # Correlated cluster B: credential collection interface
    if has_credential and (has_url or has_payment or any(i["type"] == "qr_detected" for i in indicators)):
        group = {
            "title": "CREDENTIAL COLLECTION PATTERN",
            "summary": "A request for credentials or an authentication interface appears together with a link or payment context — a pattern seen in credential-harvesting pages.",
            "indicators": ["credential_request", "auth_interface"]
            + (["suspicious_url"] if has_url else [])
            + (["qr_detected", "qr_suspicious_destination"] if any(i["type"].startswith("qr_") for i in indicators) else [])
            + (["payment_indicator"] if has_payment else []),
            "riskContribution": 10,
            "severity": "medium",
        }
        correlated_groups.append(group)

    # Correlated cluster C: payment pressure
    if has_payment and has_urgency:
        group = {
            "title": "PAYMENT PRESSURE PATTERN",
            "summary": "Payment-related content combined with urgency language. Verify any payment request through the organization's official channel before paying.",
            "indicators": ["payment_indicator", "urgency"],
            "riskContribution": 8,
            "severity": "medium",
        }
        correlated_groups.append(group)

    correlated = [group["title"] for group in correlated_groups]

    # ---- 7. VIGIL's existing rules engine on the OCR text ------------------
    # This is the same deterministic engine Message/HTML modes use.
    from app import analyze_content

    vision_evidence: list[dict] = []
    rule_decision = "ALLOW"
    if scan_text.strip():
        content_result = analyze_content(scan_text)
        vision_evidence = content_result.get("evidence", [])
        rule_decision = content_result.get("decision", "ALLOW")
    else:
        # No text at all: still run the URL/QR payloads through the engine so
        # a QR destination or pasted URL is evaluated by the same rules.
        qr_urls = [entry["data"] for entry in qr_results if entry.get("urlAnalysis")]
        if qr_urls:
            content_result = analyze_content(" ".join(qr_urls))
            vision_evidence = content_result.get("evidence", [])
            rule_decision = content_result.get("decision", "ALLOW")

    # Merge rule findings that Vision didn't already surface as indicators
    seen_indicator_types = {ind["type"] for ind in indicators}
    rule_alias_to_indicator = {
        "sensitive_request": "credential_request",
        "payment_request": "payment_indicator",
        "urgency": "urgency",
        "instruction_text": "prompt_injection",
        "hidden_instruction": "prompt_injection",
        "brand_in_domain": "url_caution",  # per-URL check above already covers it
    }
    for item in vision_evidence:
        if item.get("type") == "baseline":
            continue
        alias = rule_alias_to_indicator.get(item["type"])
        if alias and alias in seen_indicator_types:
            continue
        if item["type"].startswith("url_") or item["type"] == "link_destination_mismatch":
            # URL rules already covered by the per-URL findings above
            continue
        indicators.append(make_indicator(
            f"rule_{item['type']}", item["severity"], item["type"].replace("_", " ").title(),
            item["fact"], "Rules engine", 85, item["fact"],
        ))
        seen_indicator_types.add(f"rule_{item['type']}")

    # ---- 8. Decision via VIGIL's policy engine -----------------------------
    # Vision-specific calibration, deliberately conservative:
    # - "url_caution" (brand term in a non-official domain) and
    #   "auth_interface" (a measured password/OTP box) are caution signals.
    #   Alone — with no corroboration — they must not escalate to DENY, because
    #   a legitimate bank login page also shows a password box next to its own
    #   brand. They keep their weight in the displayed score breakdown.
    CautionOnly = {"url_caution", "auth_interface", "payment_indicator"}
    corroborated_caution = []
    for ind in indicators:
        if ind["type"] in CautionOnly and ind["severity"] == "medium":
            has_other_medium_or_high = any(
                other is not ind and other["severity"] in {"medium", "high"}
                and other["type"] not in CautionOnly
                for other in indicators
            )
            if not has_other_medium_or_high:
                corroborated_caution.append(ind)
    severity_items = [
        {"id": ind["type"], "type": ind["type"], "severity": ind["severity"], "fact": ind["reason"]}
        for ind in indicators
        if ind["severity"] in {"high", "medium"} and ind not in corroborated_caution
    ]
    decision = policy_decision(severity_items)  # reuse of VIGIL's decision function
    if rule_decision == "DENY":
        decision = "DENY"

    # ---- 9. Risk score + WHY breakdown (display only) ----------------------
    contributions: list[dict] = []
    score = 0
    def add_contribution(label: str, points: int, color: str) -> None:
        nonlocal score
        if points > 0:
            contributions.append({"label": label, "points": points, "color": color})
            score += points

    seen_contribution_labels: set[str] = set()
    indicator_weights: dict[str, int] = {}
    for ind in indicators:
        if ind["type"] in seen_contribution_labels:
            continue
        if ind["type"] == "suspicious_url":
            add_contribution("Suspicious URL", SIGNAL_WEIGHTS["suspicious_url"], "red")
        elif ind["type"] == "url_caution":
            add_contribution("Brand term in address", SIGNAL_WEIGHTS["url_caution"], "orange")
        elif ind["type"] == "qr_suspicious_destination":
            add_contribution("QR with suspicious destination", SIGNAL_WEIGHTS["qr_suspicious_destination"], "red")
        elif ind["type"] == "credential_request":
            add_contribution("Credential request", SIGNAL_WEIGHTS["credential_request"], "red")
        elif ind["type"] == "auth_interface":
            add_contribution("Authentication interface", SIGNAL_WEIGHTS["auth_interface"], "orange")
        elif ind["type"] == "qr_detected" and ind["severity"] == "medium":
            add_contribution("QR payment request", SIGNAL_WEIGHTS["qr_detected"], "orange")
        elif ind["type"] == "urgency":
            add_contribution("Urgency", SIGNAL_WEIGHTS["urgency"], "orange")
        elif ind["type"] == "payment_indicator" and ind["severity"] == "medium":
            add_contribution("Payment indicator", SIGNAL_WEIGHTS["payment_indicator"], "orange")
        if ind["type"] in SIGNAL_WEIGHTS and ind["type"] not in indicator_weights:
            indicator_weights[ind["type"]] = SIGNAL_WEIGHTS[ind["type"]]
        seen_contribution_labels.add(ind["type"])

    # Echo each contributing indicator's weight so the browser evidence panel
    # never needs a hardcoded copy of SIGNAL_WEIGHTS (weight drift would show
    # stale numbers if the server's scoring changes).
    for ind in indicators:
        ind["riskContribution"] = indicator_weights.get(ind["type"], 0)

    for group in correlated_groups:
        label = "Potential impersonation" if group["title"] == "POTENTIAL BRAND IMPERSONATION" \
            else group["title"].title()
        add_contribution(label, group["riskContribution"], "orange")

    # Correlation bonus: combined evidence outweighs any single weak signal —
    # shown as its own line so the WHY list stays honest about what fired.
    if len(correlated_groups) >= 2:
        add_contribution("Multiple correlated patterns", 10, "red")

    score = int(_clamp(score, 0, 100))

    # Decision alignment: a rule-engine DENY implies high visual risk even if
    # the additive display score came out lower.
    if decision == "DENY":
        score = max(score, 70)
    elif decision == "WARN":
        score = max(score, 40)

    risk_level = "HIGH" if decision == "DENY" else "MODERATE" if decision == "WARN" else "LOW"
    color = {"HIGH": "red", "MODERATE": "orange", "LOW": "green"}[risk_level]

    # ---- 10. Recommended actions (deterministic, from actual findings) ------
    actions: list[str] = []
    if decision == "DENY":
        actions.append("Do not act on this screenshot: do not reply, click links, or call numbers shown in it.")
    if has_credential or decision == "DENY":
        actions.append("Never share passwords, OTPs, or verification codes in response to a message or page.")
    if has_url or qr_results:
        actions.append("Do not open links or QR destinations. If needed, reach the organization through its official app or website you already use.")
    if has_payment:
        actions.append("Do not send money based on payment instructions in a screenshot. Verify the payee through a trusted channel first.")
    if has_brand and decision in {"DENY", "WARN"}:
        actions.append("Contact the organization using the official app or the number printed on your card or statement — not details from this screenshot.")
    if low_confidence and not no_text:
        actions.append("Some text could not be confidently extracted. Edit the extracted text below and re-run the analysis if it looks wrong.")
    if not actions:
        actions.append("No high-risk indicators were found. Stay alert: an ALLOW result is not a guarantee that content is safe.")

    # ---- 11. Assembly -------------------------------------------------------
    confidence_notes: list[str] = []
    if no_text:
        confidence_notes.append("No readable text was detected. You can still inspect the visual analysis below.")
    elif low_confidence:
        confidence_notes.append(
            "High-risk indicators were detected, but some text could not be confidently extracted."
            if decision in {"DENY", "WARN"} else
            "Some text could not be confidently extracted. Edit it and re-run for a sharper result."
        )
    if degraded:
        confidence_notes.append("The image was preprocessed for OCR quality; results may still be imperfect on low-quality screenshots.")

    overlay_indicators = [
        {**ind, "color": severity_to_color(ind["severity"])}
        for ind in indicators
        if ind.get("bbox") is not None
    ]
    if not was_edited:
        # Anchor text-derived indicators to OCR regions so the overlay can
        # highlight WHERE each finding appears. Skipped for user-edited text:
        # edited content is not directly extracted from the screenshot.
        for ind in indicators:
            locate_indicator_bbox(ind, regions)
        overlay_indicators = [
            {**ind, "color": severity_to_color(ind["severity"])}
            for ind in indicators
            if ind.get("bbox") is not None
        ]

    return {
        "ok": True,
        "mode": "vision",
        "image": {
            "width": image_size.get("width") or 0,
            "height": image_size.get("height") or 0,
        },
        "ocr": {
            "regionCount": len(regions),
            "meanConfidence": round(mean_confidence, 1),
            "lowConfidence": low_confidence,
            "degraded": degraded,
            "noText": no_text,
        },
        "textWasEdited": was_edited,
        "extracted": extracted,
        "indicators": indicators,
        "overlayIndicators": overlay_indicators,
        "correlated": correlated_groups,
        "urls": url_results,
        "risk": {
            "score": score,
            "level": risk_level,
            "color": color,
            "contributions": contributions,
        },
        "decision": decision,
        "explanation": build_explanation(decision, indicators, correlated_groups, no_text, low_confidence),
        "recommendedActions": actions,
        "confidenceNotes": confidence_notes,
        "ruleEvidence": vision_evidence,
    }


def build_explanation(
    decision: str,
    indicators: list[dict],
    correlated_groups: list[dict],
    no_text: bool,
    low_confidence: bool,
) -> str:
    """Deterministic explanation generated ONLY from detected evidence."""
    high = [ind for ind in indicators if ind["severity"] == "high"]
    medium = [ind for ind in indicators if ind["severity"] == "medium"]
    parts: list[str] = []
    if decision == "DENY":
        lead = "VIGIL found high-risk indicators"
    elif decision == "WARN":
        lead = "VIGIL found indicators that need caution"
    else:
        lead = "No high-risk indicators were found"
    summary = lead
    if high:
        summary += ": " + ", ".join(sorted({ind["label"].lower() for ind in high}))
    if medium:
        suffix = ", plus " if high else ": "
        summary += suffix + ", ".join(sorted({ind["label"].lower() for ind in medium}))
    summary += "."
    parts.append(summary)
    for group in correlated_groups:
        parts.append(group["summary"])
    if no_text:
        parts.append("No readable text was detected; visual findings only.")
    elif low_confidence:
        parts.append("Some text could not be confidently extracted, so treat details as a lead rather than proof.")
    return " ".join(parts)[:1200]
