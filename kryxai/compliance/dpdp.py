"""India-specific compliance mapping for observed mail-security findings.

The statutory text here is quoted from the Digital Personal Data Protection Act,
2023 as published on the India Code portal. Section 8(5) and the Second
Schedule penalty are kept deliberately distinct, because the Second Schedule
does not list section 8 among the contraventions it penalises: claiming a
Rs. 250 crore exposure for a section 8(5) breach would be wrong.

Nothing in this module is legal advice. It maps observed technical evidence to
statutory sections so that a reviewer can see the reasoning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

SOURCES_PATH = Path(__file__).with_name("sources.json")


@dataclass
class LegalProvision:
    key: str
    act: str
    section: str
    heading: str
    text: str
    url: str
    relevance: str
    penalty: Optional[str] = None
    penalty_schedule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "act": self.act,
            "section": self.section,
            "heading": self.heading,
            "text": self.text,
            "url": self.url,
            "relevance": self.relevance,
            "penalty": self.penalty,
            "penalty_schedule": self.penalty_schedule,
        }


@dataclass
class ComplianceMapping:
    provision: LegalProvision
    finding_codes: List[str]
    observation: str
    exposure: str
    not_a_legal_opinion: bool = True
    caveats: List[str] = field(default_factory=list)


_PROVISIONS: Dict[str, LegalProvision] = {}
# The source file's own declaration of how far the quoted text has been checked.
# Surfaced in the report rather than kept in the data file, so a reader of a
# signed report sees the same caveat the source carries.
_VERIFICATION: Dict[str, Any] = {
    "status": "UNVERIFIED_IN_THIS_BUILD",
    "checked": False,
    "authoritative_sources": [],
}


def _load() -> None:
    if _PROVISIONS:
        return
    if not SOURCES_PATH.exists():
        return
    data = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    for item in data["provisions"]:
        _PROVISIONS[item["key"]] = LegalProvision(**item)
    verification = data.get("verification") or {}
    _VERIFICATION.update(verification)


def provisions() -> Dict[str, LegalProvision]:
    _load()
    return dict(_PROVISIONS)


def get(key: str) -> Optional[LegalProvision]:
    _load()
    return _PROVISIONS.get(key)


# ── finding code → provisions ────────────────────────────────────────────────

CODE_TO_PROVISIONS: Dict[str, List[str]] = {
    "cleartext_mail_session": ["dpdp_s8_4"],
    "starttls_capability_suppressed": ["dpdp_s8_4", "dpdp_s8_5"],
    "starttls_refused": ["dpdp_s8_4"],
    "starttls_not_offered": ["dpdp_s8_4"],
    "cross_flow_inconsistency": ["dpdp_s8_4", "dpdp_s8_5"],
    "weak_tls_version": ["dpdp_s8_4"],
    "broken_tls_version": ["dpdp_s8_4"],
    "weak_cipher_suite": ["dpdp_s8_4"],
    "broken_cipher_suite": ["dpdp_s8_4"],
    "no_forward_secrecy": ["dpdp_s8_4"],
    "weak_key_exchange_group": ["dpdp_s8_4"],
    "certificate_expired": ["dpdp_s8_4"],
    "certificate_not_yet_valid": ["dpdp_s8_4"],
    "certificate_expiring_soon": ["dpdp_s8_4"],
    "weak_public_key": ["dpdp_s8_4"],
    "weak_signature_algorithm": ["dpdp_s8_4"],
    "hostname_mismatch": ["dpdp_s8_4", "dpdp_s8_5"],
    "incomplete_chain": ["dpdp_s8_4"],
    "chain_signature_invalid": ["dpdp_s8_4", "dpdp_s8_5"],
    "self_signed_leaf": ["dpdp_s8_4"],
    "unknown_critical_extension": ["dpdp_s8_4"],
    "insufficient_reassembly": ["cert_in_6h"],
    "passive_tls13_certificate_not_visible": [],
    "non_mail_cleartext": [],
}

# Second Schedule contraventions, quoted so the mapping never overstates exposure.
#
# "on conviction" is retained deliberately. The Board's penalty follows a
# criminal conviction, so the amount below is the maximum a court may impose on
# conviction, not a figure that attaches automatically to a technical finding.
# Note also that section 8 is NOT in the Second Schedule: the observations this
# tool makes map to section 8(4)/(5) for the sake of relevance, not exposure.
#
# VERIFICATION: this text has not been re-checked against the Gazette or India
# Code in this build. Treat it as a drafting aid and have a lawyer confirm it
# before any filing or external communication.
SECOND_SCHEDULE = (
    "If any of the provisions of section 4, section 6(2), (3), (4), (5) or (6), "
    "section 7 or section 9(4) or (5) or both, is contravened and the contravention "
    "is proved, the Board may impose a penalty of up to two hundred and fifty crore "
    "rupees for each contravention on conviction."
)

DPDP_URL = "https://www.indiacode.nic.in/handle/123456789/20563"
CERT_IN_URL = "https://www.cert-in.org.in/Directions70B.jsp"


def map_finding(finding: Dict[str, Any]) -> List[ComplianceMapping]:
    out: List[ComplianceMapping] = []
    code = finding.get("code", "")
    for key in CODE_TO_PROVISIONS.get(code, []):
        prov = get(key)
        if prov is None:
            continue
        caveats: List[str] = []
        exposure = prov.penalty or "No monetary penalty is prescribed for this section."
        if prov.penalty_schedule:
            caveats.append(
                "The Second Schedule does not list section 8; the Rs. 250 crore "
                "ceiling applies to sections 4, 6(2)-(6), 7 and 9(4)-(5)."
            )
        caveats.append(
            "Passive observation of an exposed session does not by itself establish "
            "a contravention; the adequacy of the controller's safeguards is a "
            "factual question."
        )
        out.append(
            ComplianceMapping(
                provision=prov,
                finding_codes=[code],
                observation=finding.get("detail", ""),
                exposure=exposure,
                caveats=caveats,
            )
        )
    return out


def map_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        for mapping in map_finding(f):
            out.append(
                {
                    "finding_code": f.get("code"),
                    "severity": f.get("severity"),
                    "endpoint": f.get("endpoint"),
                    "provision": mapping.provision.to_dict(),
                    "observation": mapping.observation,
                    "exposure": mapping.exposure,
                    "caveats": mapping.caveats,
                    "disclaimer": "Not legal advice.",
                }
            )
    return out


def compliance_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    mapped = map_findings(findings)
    by_section: Dict[str, int] = {}
    for m in mapped:
        by_section[m["provision"]["section"]] = by_section.get(m["provision"]["section"], 0) + 1
    _load()
    return {
        "framework": "Digital Personal Data Protection Act, 2023",
        "source": DPDP_URL,
        "mapped_findings": len(mapped),
        "by_section": by_section,
        "second_schedule": SECOND_SCHEDULE,
        "second_schedule_note": (
            "The Rs. 250 crore ceiling in the Second Schedule applies to "
            "contraventions of sections 4, 6(2)-(6), 7 and 9(4)-(5) of the DPDP "
            "Act. Section 8 is not among the penalised provisions, so a finding "
            "mapped to section 8 is reported as a safeguard gap, not as a "
            "quantified penalty exposure."
        ),
        # Carried into the signed report so a reader sees the same status the
        # source file declares. The statutory text is quoted, not paraphrased,
        # and it has not been checked against the Gazette by a lawyer.
        "verification_status": _VERIFICATION.get("status", "UNVERIFIED_IN_THIS_BUILD"),
        "verification_note": _VERIFICATION.get("note", ""),
        "authoritative_sources": list(_VERIFICATION.get("authoritative_sources") or []),
        "provisions": [p.to_dict() for p in _PROVISIONS.values()],
        "items": mapped,
        "disclaimer": (
            "KryxAI is a technical tool. This mapping is informational and is not "
            "legal advice or a compliance determination."
        ),
    }
