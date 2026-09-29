"""Bilingual (English / Devanagari) strings for findings and report sections.

Design rule: a missing translation is reported as missing, never substituted
with an empty string or a transliteration that would look translated but is
not. `translate()` returns `None` when a key is unknown so callers can decide
what to do; `finding_title()` falls back to English and flags the gap.
"""

from __future__ import annotations

import sys
from typing import Dict, Optional

LANGUAGES = ("en", "hi")

FINDING_TITLES: Dict[str, str] = {
    "cleartext_mail_session": "Cleartext mail session observed",
    "starttls_capability_suppressed": "STARTTLS capability suppressed in transit",
    "starttls_refused": "STARTTLS upgrade refused by the server",
    "starttls_not_offered": "STARTTLS not offered by the server",
    "starttls_downgrade": "STARTTLS downgrade signature present",
    "starttls_plaintext_after_upgrade": "Plaintext observed after a STARTTLS upgrade",
    "starttls_cross_flow_inconsistency": "STARTTLS behaviour differs between flows",
    "tampered_token": "Tampered STARTTLS token in transit",
    "weak_tls_version": "Weak TLS version negotiated",
    "broken_tls_version": "Deprecated TLS version negotiated",
    "weak_cipher_suite": "Weak cipher suite negotiated",
    "broken_cipher_suite": "Broken cipher suite negotiated",
    "no_forward_secrecy": "No forward secrecy",
    "weak_key_exchange_group": "Weak key exchange group",
    "weak_public_key": "Weak public key",
    "weak_signature_algorithm": "Weak signature algorithm",
    "certificate_expired": "Certificate expired at capture time",
    "certificate_not_yet_valid": "Certificate not yet valid at capture time",
    "certificate_expiring_soon": "Certificate expiring soon",
    "hostname_mismatch": "Certificate does not match the requested host",
    "incomplete_chain": "Incomplete certificate chain",
    "chain_signature_invalid": "Certificate chain signature did not verify",
    "self_signed_leaf": "Self-signed leaf certificate",
    "unknown_critical_extension": "Unknown critical TLS extension",
    "insufficient_reassembly": "TCP stream could not be fully reassembled",
    "passive_tls13_certificate_not_visible": "TLS 1.3 certificate not visible to passive analysis",
    "non_mail_cleartext": "Cleartext conversation on a non-mail port",
    "known_malicious_indicator": "Matched a supplied threat indicator",
    "A1_tamper_signature": "Tamper signature against a capture-local baseline",
    "A2_partial_upgrade": "Peer upgrades on only some of its sessions",
    "A3_plaintext_on_implicit_port": "Plaintext on an implicit-TLS port",
    "A4_certificate_inconsistency": "Peer presented several certificates in one capture",
    "A5_evidence_gap": "Evidence gap limits this conclusion",
    "A6_session_size_outlier": "Session size far from the capture mean",
}

SECTION_TITLES: Dict[str, str] = {
    "executive_summary": "Executive summary",
    "posture": "Encryption posture",
    "sessions": "Session analysis",
    "findings": "Findings",
    "compliance": "DPDP compliance mapping",
    "anomalies": "Anomalies",
    "limitations": "Limitations of this analysis",
    "evidence": "Evidence chain",
    "ioc": "Threat intelligence coverage",
    "remediation": "Remediation",
}

DISCLAIMER_EN = (
    "KryxAI is a technical analysis tool. This report is not legal advice and is "
    "not a compliance determination. A clean report is not proof of a compliant "
    "control; it reflects only the traffic present in the supplied capture."
)

DISCLAIMER_HI = (
    "KryxAI एक तकनीकी विश्लेषण उपकरण है। यह रिपोर्ट कानूनी सलाह नहीं है और न ही "
    "अनुपालन का निर्धारण। साफ़ रिपोर्ट अनुपालन का प्रमाण नहीं है; यह केवल दिए गए "
    "कैप्चर में मौजूद ट्रैफ़िक पर आधारित है।"
)


def translate(key: str, lang: str) -> Optional[str]:
    if lang == "en":
        return FINDING_TITLES.get(key) or SECTION_TITLES.get(key)
    if lang == "hi":
        return HINDI_TITLES.get(key)
    return None


def finding_title(code: str) -> Dict[str, object]:
    """English title plus the Devanagari one when it exists."""
    return {
        "title": FINDING_TITLES.get(code, code.replace("_", " ")),
        "title_hi": HINDI_TITLES.get(code),
        "translation_complete": code in HINDI_TITLES,
    }


def section_title(key: str, lang: str) -> str:
    if lang == "hi":
        return HINDI_SECTIONS.get(key) or SECTION_TITLES.get(key, key)
    return SECTION_TITLES.get(key, key)


def disclaimer(lang: str) -> str:
    return DISCLAIMER_HI if lang == "hi" else DISCLAIMER_EN


HINDI_TITLES: Dict[str, str] = {
    "cleartext_mail_session": "स्पष्ट-पाठ (unencrypted) मेल सत्र देखा गया",
    "starttls_capability_suppressed": "STARTTLS क्षमता ट्रांज़िट में दबाई गई",
    "starttls_refused": "सर्वर ने STARTTLS अपग्रेड अस्वीकार किया",
    "starttls_not_offered": "सर्वर ने STARTTLS प्रस्ताव नहीं किया",
    "starttls_downgrade": "STARTTLS डाउनग्रेड संकेत उपस्थित",
    "starttls_plaintext_after_upgrade": "STARTTLS अपग्रेड के बाद स्पष्ट-पाठ देखा गया",
    "starttls_cross_flow_inconsistency": "STARTTLS व्यवहार फ्लो के बीच भिन्न है",
    "tampered_token": "ट्रांज़िट में STARTTLS टोकन में हेरफेर",
    "weak_tls_version": "कमज़ोर TLS संस्करण नेगोशिएट",
    "broken_tls_version": "अप्रचलित TLS संस्करण नेगोशिएट",
    "weak_cipher_suite": "कमज़ोर साइफ़र स्यूट नेगोशिएट",
    "broken_cipher_suite": "टूटा हुआ साइफ़र स्यूट नेगोशिएट",
    "no_forward_secrecy": "फ़ॉरवर्ड सीक्रेसी नहीं है",
    "weak_key_exchange_group": "कमज़ोर की एक्सचेंज ग्रुप",
    "weak_public_key": "कमज़ोर पब्लिक की",
    "weak_signature_algorithm": "कमज़ोर सिग्नेचर एल्गोरिदम",
    "certificate_expired": "कैप्चर के समय प्रमाणपत्र की वैधता समाप्त",
    "certificate_not_yet_valid": "कैप्चर के समय प्रमाणपत्र अभी वैध नहीं था",
    "certificate_expiring_soon": "प्रमाणपत्र शीघ्र समाप्त हो रहा है",
    "hostname_mismatch": "प्रमाणपत्र अनुरोधित होस्ट से मेल नहीं खाता",
    "incomplete_chain": "अपूर्ण प्रमाणपत्र शृंखला",
    "chain_signature_invalid": "प्रमाणपत्र शृंखला का सिग्नेचर सत्यापित नहीं हुआ",
    "self_signed_leaf": "स्व-हस्ताक्षरित लीफ़ प्रमाणपत्र",
    "unknown_critical_extension": "अज्ञात महत्वपूर्ण TLS एक्सटेंशन",
    "insufficient_reassembly": "TCP स्ट्रीम पूर्ण रूप से पुनर्निर्मित नहीं हो सकी",
    "passive_tls13_certificate_not_visible": "TLS 1.3 प्रमाणपत्र निष्क्रिय विश्लेषण को अदृश्य",
    "non_mail_cleartext": "मेल-गैर-मेल पोर्ट पर स्पष्ट-पाठ संवाद",
    "known_malicious_indicator": "आपूर्तित खतरे के संकेत से मेल",
    "A1_tamper_signature": "कैप्चर-स्थानीय आधाररेखा के विरुद्ध हेरफेर संकेत",
    "A2_partial_upgrade": "पीयर अपने केवल कुछ सत्रों में अपग्रेड करता है",
    "A3_plaintext_on_implicit_port": "implicit-TLS पोर्ट पर स्पष्ट-पाठ",
    "A4_certificate_inconsistency": "पीयर ने एक ही कैप्चर में कई प्रमाणपत्र दिखाए",
    "A5_evidence_gap": "साक्ष्य अंतराल इस निष्कर्ष को सीमित करता है",
    "A6_session_size_outlier": "सत्र का आकार कैप्चर औसत से बहुत भिन्न",
}

HINDI_SECTIONS: Dict[str, str] = {
    "executive_summary": "कार्यकारी सारांश",
    "posture": "एन्क्रिप्शन स्थिति",
    "sessions": "सत्र विश्लेषण",
    "findings": "निष्कर्ष",
    "compliance": "DPDP अनुपालन मानचित्रण",
    "anomalies": "विषमताएँ",
    "limitations": "इस विश्लेषण की सीमाएँ",
    "evidence": "साक्ष्य शृंखला",
    "ioc": "खतरा बुद्धिमत्ता कवरेज",
    "remediation": "उपचार",
}


def safe_stdout(text: str) -> None:
    """Print text that may contain Devanagari on a cp1252 console.

    Windows consoles frequently raise UnicodeEncodeError on Devanagari. Rather
    than let a report crash the CLI, unencodable characters are replaced and a
    note is emitted so the operator knows output was degraded.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(encoding, "replace").decode(encoding, "replace"))
        print(f"[kryxai] note: console encoding {encoding} cannot render all "
              "characters; some text was replaced. Set PYTHONIOENCODING=utf-8.")
