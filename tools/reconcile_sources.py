"""Reconcile the penalty wording in sources.json with dpdp.SECOND_SCHEDULE.

Kept as a script rather than a manual edit so the two cannot drift again.
"""

import json
import pathlib

P = pathlib.Path("kryxai/compliance/sources.json")
data = json.loads(P.read_text(encoding="utf-8"))

data["verification"] = {
    "status": "UNVERIFIED_IN_THIS_BUILD",
    "checked": False,
    "note": (
        "The statutory text below was transcribed from the India Code portal in an "
        "earlier pass and has not been re-checked against the Gazette in this build "
        "(network retrieval failed). It is a drafting aid, not legal advice. Have a "
        "qualified lawyer verify every quote and amount before relying on it in a "
        "filing, notice or external communication."
    ),
    "authoritative_sources": [
        "https://www.indiacode.nic.in/handle/123456789/20563",
        "https://www.egazette.nic.in/",
    ],
}

OLD = "carry a penalty of up to two hundred and fifty crore rupees for each contravention."
NEW = (
    "carry a penalty of up to two hundred and fifty crore rupees for each "
    "contravention, on conviction. The maximum attaches only on a proved "
    "contravention; it is not a figure that follows automatically from a "
    "technical finding."
)
# Section 4 is itself penalised, so its own `penalty` field quotes the bare
# maximum and needs the same qualification.
OLD_DIRECT = "Up to two hundred and fifty crore rupees for each contravention."
NEW_DIRECT = (
    "Up to two hundred and fifty crore rupees for each contravention, on "
    "conviction. This is the statutory maximum a court may impose on a proved "
    "contravention; it is not an automatic consequence of a technical finding."
)

changed = 0
for prov in data.get("provisions", []):
    for key in ("penalty", "penalty_schedule"):
        val = prov.get(key)
        if not isinstance(val, str):
            continue
        if OLD in val:
            prov[key] = val.replace(OLD, NEW)
            changed += 1
        elif OLD_DIRECT in val:
            prov[key] = val.replace(OLD_DIRECT, NEW_DIRECT)
            changed += 1

P.write_text(
    json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
)
print(f"updated {changed} penalty field(s); verification block added")
