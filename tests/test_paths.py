"""Tests for path resolution and packaging hygiene.

These guard the rule that an installed wheel never writes into site-packages,
which is where the database, the reports and the RSA-3072 report-signing key
would otherwise land.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from kryxai import config


def test_writable_state_is_never_inside_the_package():
    """Nothing KryxAI writes may land inside the package directory itself."""
    package = Path(config.PACKAGE_DIR).resolve()
    for path in (
        config.DATA_ROOT / "kryxai.db",
        config.DATA_ROOT / "reports",
        config.DATA_ROOT / "reports" / "keys",
    ):
        assert package not in Path(path).resolve().parents, (
            f"{path} would be written inside the installed package directory"
        )


def test_installed_wheel_does_not_write_into_site_packages():
    """The regression this guards: DB/reports/keys landing in site-packages.

    Only meaningful once installed, so it no-ops in a source checkout. The
    signing key in particular must not sit somewhere world-readable.
    """
    package = Path(config.PACKAGE_DIR).resolve()
    site = next(
        (
            p
            for p in package.parents
            if p.name in ("site-packages", "dist-packages")
        ),
        None,
    )
    if site is None:
        pytest.skip("running from a source checkout, not an installed wheel")

    for path in (
        config.DATA_ROOT / "kryxai.db",
        config.DATA_ROOT / "reports",
        config.DATA_ROOT / "reports" / "keys",
    ):
        assert site not in Path(path).resolve().parents, (
            f"{path} would be written inside {site}"
        )


def test_package_resources_resolve_from_the_package_dir():
    """Read-only bundled resources must follow the wheel, not the data root."""
    assert Path(config.PACKAGE_DIR).resolve() in Path(
        config.Settings().statute_sources_path
    ).resolve().parents
    assert Path(config.PACKAGE_DIR).resolve() in Path(
        config.Settings().ioc_feed_dir
    ).resolve().parents


def test_bundled_statute_sources_ship_and_load():
    src = Path(config.Settings().statute_sources_path)
    assert src.is_file(), f"statutory sources missing from the package: {src}"
    import json

    data = json.loads(src.read_text(encoding="utf-8"))
    assert data["provisions"]


def test_kryxai_home_overrides_the_data_root(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYXAI_HOME", str(tmp_path / "home"))
    assert config._default_data_root() == tmp_path / "home"


def test_source_checkout_keeps_state_beside_the_code():
    """A development checkout should not scatter state into the user profile."""
    if not (Path(config.PACKAGE_DIR).parent / "pyproject.toml").is_file():
        pytest.skip("not running from a source checkout")
    assert config._default_data_root() == Path(config.PACKAGE_DIR).resolve().parent


def test_ensure_writable_dirs_creates_missing_directories(tmp_path):
    s = config.Settings(
        database_path=str(tmp_path / "nested" / "kryxai.db"),
        reports_dir=str(tmp_path / "nested" / "out"),
        report_keys_dir=str(tmp_path / "nested" / "out" / "keys"),
    )
    config.ensure_writable_dirs(s)
    assert (tmp_path / "nested" / "out").is_dir()
    assert (tmp_path / "nested" / "out" / "keys").is_dir()
    assert (tmp_path / "nested").is_dir()


def test_ensure_writable_dirs_tolerates_an_unwritable_root(tmp_path):
    """A read-only data root must warn, not crash the import."""
    s = config.Settings(
        database_path="/nonexistent-root/should-not-appear/kryxai.db",
        reports_dir="/nonexistent-root/should-not-appear/out",
        report_keys_dir="/nonexistent-root/should-not-appear/out/keys",
    )
    if os.name == "nt" or sys.platform == "win32":
        pytest.skip("root is writable when not elevated on Windows")
    config.ensure_writable_dirs(s)  # must not raise
