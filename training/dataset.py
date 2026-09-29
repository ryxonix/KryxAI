"""Labelled synthetic corpus generation for training.

The point of this module is ground truth. Every capture is built with a known,
independently-declared weakness profile, and the label attached to it is that
profile, not anything KryxAI's rule engine concludes.

That distinction is the whole reason the model is worth training. If the label
were, say, "does the engine emit a high finding", the model would only be
learning to imitate `policy/kb.py`, it would score the rules as near-perfect on
data derived from those same rules, and that number would mean nothing. The
label here is what a reviewer would say looking at the handshake: this server
ran a 1024-bit key, so it is weak, whatever the tool concludes.

Import from the notebook. Not part of the installed package.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from kryxai.pcap import mailflows, tlssynth as ts  # noqa: E402
from kryxai.pcap.synth import ConversationBuilder, write_pcap  # noqa: E402

# The synthetic builder stamps packets at this epoch, and the scanner judges
# certificate validity against capture time, so labels about expiry are decided
# by moving not_after/not_before across this line.
CAPTURE_EPOCH = 1_700_000_000.0

CLIENT_HELLO = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com"))

# Ordered from acceptable to unacceptable. Used for the ordinal target and to
# describe each profile. A session's true band is the worst injected weakness.
BANDS = ("ok", "weak_crypto", "exposure")

# Number of distinct identities per weakness. Group-aware splitting needs many
# groups; a model that memorised a handful of certificates would look excellent
# on a random split and generalise to nothing.
IDENTITIES_PER_PROFILE = 8


@dataclass
class Profile:
    """A weakness profile, i.e. the ground truth for one generated identity."""

    name: str
    band: str
    description: str
    chain: List[bytes]
    turns: Sequence[Any]
    port: int = 25
    # Extra facts a reviewer would know but the feature vector may not encode.
    notes: str = ""
    expect_weak_tls: bool = False
    expect_starttls: bool = True


@dataclass
class Sample:
    path: Path
    profile: str
    band: str
    group: str
    label: int
    description: str


def _chain(
    index: int,
    *,
    key_size: int = 2048,
    relabel_sha1: bool = False,
    days_valid: Optional[int] = None,
    expired: bool = False,
) -> List[bytes]:
    """A distinct certificate identity per index.

    Identity is varied on purpose. Reusing one certificate across all training
    rows would let the model key on the certificate rather than on the
    cryptographic properties it is meant to learn.

    `relabel_sha1` swaps the signature OID rather than genuinely signing with
    SHA-1, because modern toolchains refuse SHA-1 signatures. The bytes are
    then not truly SHA-1-signed, so a profile that uses it is labelled on its
    1024-bit key and the OID is described as relabelled, not as a SHA-1
    signature the model is being asked to detect.
    """
    common: Dict[str, Any] = dict(
        leaf_cn=f"mx{index}.mail.example.com",
        ca_cn=f"Example Mail Root Root CA {index}",
        leaf_key_size=key_size,
    )
    if days_valid is not None or expired:
        if expired:
            common["not_before"] = int(CAPTURE_EPOCH) - 400 * 86400
            common["not_after"] = int(CAPTURE_EPOCH) - 30 * 86400
        else:
            common["not_before"] = int(CAPTURE_EPOCH) - 10 * 86400
            common["not_after"] = int(CAPTURE_EPOCH) + days_valid * 86400
    chain = ts.make_chain(**common)
    if relabel_sha1:
        chain = [ts.relabel_rsa_signature_to_sha1(leaf) for leaf in chain]
    return chain


def _profiles() -> List[Profile]:
    """One profile per ground-truth category, across SMTP, IMAP and POP3.

    Categories are chosen to match what a mail-security reviewer actually
    judges: a working modern handshake, a working but outdated one, a
    certificate that was already expired when the capture was taken, and a
    plaintext exposure. `weak_crypto` and `exposure` are both unacceptable, but
    they are not the same complaint, so the model gets an ordinal target rather
    than a binary one.
    """
    out: List[Profile] = []

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(i)
        out.append(
            Profile(
                name=f"smtp_modern_{i}",
                band="ok",
                description="SMTP, TLS 1.2 modern cipher, PFS, 2048-bit RSA, valid cert",
                chain=chain,
                turns=mailflows.smtp_upgraded(
                    CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=chain)
                ),
                port=587,
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(100 + i, key_size=1024, relabel_sha1=True)
        out.append(
            Profile(
                name=f"smtp_weak_rsa_{i}",
                band="weak_crypto",
                description="SMTP, TLS 1.2 with a 1024-bit RSA leaf key",
                chain=chain,
                turns=mailflows.smtp_upgraded(
                    CLIENT_HELLO, ts.tls12_session(cipher=0xC013, certs=chain)
                ),
                port=587,
                expect_weak_tls=True,
                notes=(
                    "1024-bit RSA is factorable. The signature OID is relabelled to "
                    "SHA-1 to exercise that parser path, so the label rests on the "
                    "key size, not on the OID."
                ),
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(200 + i, expired=True)
        out.append(
            Profile(
                name=f"smtp_expired_{i}",
                band="weak_crypto",
                description="SMTP, modern cipher but certificate expired before capture",
                chain=chain,
                turns=mailflows.smtp_upgraded(
                    CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=chain)
                ),
                port=587,
                notes="Strong algorithm, unusable certificate at capture time",
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(300 + i)
        out.append(
            Profile(
                name=f"smtp_plaintext_{i}",
                band="exposure",
                description="SMTP with no upgrade offered; mail content in cleartext",
                chain=chain,
                turns=mailflows.smtp_no_upgrade(),
                port=25,
                expect_starttls=False,
                notes="Credentials and message bodies observable on the wire",
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(400 + i)
        out.append(
            Profile(
                name=f"imap_suppressed_{i}",
                band="exposure",
                description="IMAP capability line with the STARTTLS keyword altered",
                chain=chain,
                turns=mailflows.imap_starttls_suppressed(
                    replacement=f"XXXXXXX{i:02d}"
                ),
                port=143,
                expect_starttls=False,
                notes="Starvation, not a broken server: a filtering middlebox",
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(500 + i)
        out.append(
            Profile(
                name=f"pop3_suppressed_{i}",
                band="exposure",
                description="POP3 CAPA response with STLS altered",
                chain=chain,
                turns=mailflows.pop3_stls_suppressed(replacement=f"XXXXXXX{i:02d}"),
                port=110,
                expect_starttls=False,
            )
        )

    for i in range(IDENTITIES_PER_PROFILE):
        chain = _chain(600 + i, key_size=1024)
        out.append(
            Profile(
                name=f"smtp_no_pfs_{i}",
                band="weak_crypto",
                description="SMTP, TLS 1.2 RSA key exchange: no forward secrecy",
                chain=chain,
                turns=mailflows.smtp_upgraded(
                    CLIENT_HELLO, ts.tls12_session(cipher=0x009C, certs=chain)
                ),
                port=587,
                expect_weak_tls=True,
                notes=(
                    "One server key compromise would expose every past session; "
                    "the certificate itself is also 1024-bit"
                ),
            )
        )

    return out


def write_corpus(out_dir: Path) -> List[Sample]:
    """Generate the labelled corpus to disk and return its index."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples: List[Sample] = []
    for profile in _profiles():
        label = BANDS.index(profile.band)
        path = out_dir / f"{profile.name}.pcap"
        builder = ConversationBuilder(server_port=profile.port)
        mailflows.replay(builder, profile.turns)
        write_pcap(path, builder.packets)
        samples.append(
            Sample(
                path=path,
                profile=profile.name,
                band=profile.band,
                # The group is the certificate identity, so no identity spans
                # the train/test split. Note it is deliberately *not* the
                # profile: grouping by profile would let a held-out group be an
                # entire weakness category, and the model would then be asked to
                # classify a category it had never seen.
                group=profile.name,
                label=label,
                description=profile.description,
            )
        )
    return samples


if __name__ == "__main__":  # pragma: no cover - manual use
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "training" / "data"
    index = write_corpus(target)
    counts: Dict[str, int] = {}
    for s in index:
        counts[s.band] = counts.get(s.band, 0) + 1
    print(f"wrote {len(index)} captures to {target}")
    print(f"  {len({s.group for s in index})} distinct identities (split groups)")
    for band in BANDS:
        print(f"  {band:12} {counts.get(band, 0)}")
