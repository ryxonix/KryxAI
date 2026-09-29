"""KryxAI command line interface.

Console output goes through the i18n safe printer, because Devanagari cannot
be encoded on a default Windows console (cp1252) and an unhandled
UnicodeEncodeError would turn a successful scan into a crash.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .config import Settings
from .engine import run_scan
from .i18n import disclaimer, safe_stdout, section_title
from .store import Store

SEVERITY_MARK = {
    "critical": "[!!]",
    "high": "[ !]",
    "medium": "[ ~]",
    "low": "[ .]",
    "info": "[  ]",
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kryxai",
        description=(
            "Passive SMTP/IMAP/POP3 mail-security forensics. Observes an existing "
            "capture; it does not probe, scan or modify anything."
        ),
    )
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="analyse a pcap/pcapng file")
    scan.add_argument("capture", help="path to the capture file")
    scan.add_argument("--lang", default="en,hi", help="report languages (en,hi)")
    scan.add_argument("--no-sign", action="store_true", help="do not sign the report")
    scan.add_argument("--no-chain", action="store_true", help="do not append to the evidence chain")
    scan.add_argument("--db", default=None, help="evidence database path")
    scan.add_argument("--out", default=None, help="report output directory")
    scan.add_argument("--json", action="store_true", help="print the full report JSON to stdout")
    scan.add_argument("--quiet", action="store_true", help="only print the summary line")

    corpus = sub.add_parser("corpus", help="generate the synthetic demo corpus")
    corpus.add_argument("out", nargs="?", default="corpus", help="output directory")

    chain = sub.add_parser("chain", help="verify the evidence chain")
    chain.add_argument("--db", default=None, help="evidence database path")

    report = sub.add_parser("report", help="re-render a report from a saved JSON file")
    report.add_argument("json_path")
    report.add_argument("--out", default="reports", help="output directory")
    report.add_argument("--lang", default="en,hi")

    sub.add_parser("capabilities", help="describe what this build can and cannot see")
    return p


def _settings(args: argparse.Namespace) -> Settings:
    overrides = {}
    if getattr(args, "db", None):
        overrides["database_path"] = args.db
    if getattr(args, "out", None):
        overrides["reports_dir"] = args.out
    return Settings(**overrides) if overrides else Settings()


def _print_report_paths(paths) -> None:
    """List written artefacts, and say so when a format was skipped.

    A missing PDF must never look like a successful run, so the omission is
    reported explicitly rather than inferred from the absence of a line.
    """
    from .reports import builder as report_builder

    for name, p in paths.items():
        safe_stdout(f"  {name}: {p}")
    if "pdf" not in paths and not report_builder.pdf_available():
        safe_stdout(f"  note: {report_builder.PDF_UNAVAILABLE_HINT}")


def _print_summary(report, lang: str) -> None:
    posture = report["posture"]
    counts = report["counts"]
    safe_stdout(
        f"KryxAI {report['version']}  posture {posture['grade']} "
        f"({posture['score']}/100, {posture['label']})"
    )
    safe_stdout(
        f"  {counts['sessions']} sessions | {counts['mail_sessions']} mail | "
        f"{counts['tls_upgraded']} upgraded to TLS | {counts['findings']} findings"
    )
    if posture.get("not_assessed"):
        safe_stdout(f"  not assessed: {', '.join(posture['not_assessed'])}")

    for f in report["findings"]:
        risk = f.get("risk") or {}
        title = (
            f.get("title_hi")
            if lang == "hi" and f.get("title_hi")
            else f.get("title")
        )
        safe_stdout(
            f"  {SEVERITY_MARK.get(f['severity'], '[  ]')} "
            f"{risk.get('priority', '?')}  {f['severity']:<8} "
            f"{f.get('endpoint') or '-':<22} {title}"
        )

    if report["findings"]:
        safe_stdout("")
        safe_stdout(f"  {section_title('limitations', lang)}:")
        for note in report["limitations"]:
            safe_stdout(f"    - {note}")

    evidence = report.get("evidence", {})
    safe_stdout("")
    safe_stdout(
        f"  evidence: scan {evidence.get('scan_id') or '-'}  "
        f"block {evidence.get('block_index') if evidence.get('block_index') is not None else '-'}  "
        f"state {evidence.get('chain_state', '-')}"
    )
    safe_stdout(f"  {disclaimer(lang)}")


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.capture)
    if not path.is_file():
        safe_stdout(f"error: capture not found: {path}")
        return 2

    settings = _settings(args)
    store = None if args.no_chain else Store(settings.database_path)
    try:
        result = run_scan(
            path,
            settings,
            store=store,
            persist=not args.no_chain,
        )
    except ValueError as exc:
        safe_stdout(f"error: could not read capture: {exc}")
        return 3

    report = result.report
    langs: List[str] = [x.strip() for x in args.lang.split(",") if x.strip()] or ["en"]

    if args.json:
        safe_stdout(json.dumps(report, indent=2, default=str, ensure_ascii=False))
        return 0

    from .reports import builder as report_builder

    paths = report_builder.write(
        report,
        Path(settings.reports_dir),
        settings,
        langs=langs,
        sign_reports=not args.no_sign,
    )
    if not args.quiet:
        _print_summary(report, langs[0])
    safe_stdout("")
    _print_report_paths(paths)
    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    from .pcap import corpus

    manifest = corpus.generate(Path(args.out))
    safe_stdout(f"generated {len(manifest['cases'])} synthetic captures in {args.out}")
    for case in manifest["cases"]:
        safe_stdout(f"  {case['filename']:<44} {case['size_bytes']:>8} B")
    safe_stdout(f"  index: {Path(args.out) / 'index.json'}")
    safe_stdout("")
    safe_stdout(f"  {manifest['warning']}")
    return 0


def cmd_chain(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = Store(settings.database_path)
    try:
        result = store.verify_chain()
        blocks = store.chain()
    finally:
        store.close()
    safe_stdout(
        f"chain {settings.chain_id}: {'VALID' if result['ok'] else 'BROKEN'} "
        f"({result['blocks']} block(s))"
    )
    if not result["ok"]:
        safe_stdout(f"  first broken block: {result['broken_at']}")
    for b in blocks:
        anchor = (
            f"anchored via {b.anchor_provider} tx={b.anchor_tx}"
            if b.anchored
            else "not anchored"
        )
        safe_stdout(
            f"  #{b.index} diff={b.difficulty} {b.block_hash[:16]}... {anchor}"
        )
    return 0 if result["ok"] else 1


def cmd_report(args: argparse.Namespace) -> int:
    from .config import Settings as S
    from .reports import builder as report_builder

    report = json.loads(Path(args.json_path).read_text(encoding="utf-8"))
    settings = S(reports_dir=args.out)
    langs = [x.strip() for x in args.lang.split(",") if x.strip()] or ["en"]
    paths = report_builder.write(report, Path(args.out), settings, langs=langs)
    _print_report_paths(paths)
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    from .feeds import ioc

    settings = Settings()
    feed = ioc.load_feed_dir(settings.ioc_feed_dir)
    payload = {
        "version": __import__("kryxai").__version__,
        "chain_id": settings.chain_id,
        "report_aad": settings.report_aad.decode(),
        "passive_only": True,
        "protocols": ["SMTP", "IMAP", "POP3"],
        "starttls_signatures": [
            "K1_capability_suppression",
            "K2_cross_flow_inconsistency",
            "K3_refused_upgrade",
            "K4_plaintext_after_upgrade",
        ],
        "tls_visibility": {
            "TLS 1.0-1.2": "version, cipher, group, signature, certificate, chain",
            "TLS 1.3": "version and cipher only (certificate is encrypted)",
        },
        "ioc": feed.to_dict(),
        "anchor_required": settings.blockchain_anchor_required,
        "alert_channels": settings.active_alert_channels(),
        "disclaimer": disclaimer("en"),
    }
    safe_stdout(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        safe_stdout(f"kryxai {__import__('kryxai').__version__}")
        return 0

    handlers = {
        "scan": cmd_scan,
        "corpus": cmd_corpus,
        "chain": cmd_chain,
        "report": cmd_report,
        "capabilities": cmd_capabilities,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
