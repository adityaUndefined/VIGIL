# facts.py — the single shared fact sheet (guide Step 2).
# Every evidence ID gets one plain sentence. Detectors, template explanations,
# and the LLM explainer all read from this one table, so wording never drifts.
# The LLM only ever sees {"id", "fact"} pairs from here — never page text.

FACTS = {
    # Hidden content signals
    "HID-001":     "The page contains text a person cannot see.",
    "HID-INJ-01":  "Hidden text tells an AI assistant to ignore its rules.",
    "HID-INJ-02":  "Hidden text speaks directly to an AI assistant.",
    "HID-INJ-03":  "Hidden text asks for a code, password or payment detail to be sent out.",
    "HID-INJ-04":  "Hidden text tells the assistant to keep its actions secret from the user.",
    "HID-ZW-01":   "Invisible characters are mixed into the text.",
    # Action signals
    "ACT-SENS-01": "The proposed action sends data or money out.",
    "ACT-PROV-01": "The destination of the action came from hidden text, not from the user.",
}

PARENT_ACTION = {
    "DENY":  "Do not reply, click or forward anything. Show this message to someone you trust.",
    "WARN":  "Pause before doing anything. Check with the sender another way, such as a phone call.",
    "ALLOW": "Nothing risky was found, but stay careful with codes and passwords.",
}
