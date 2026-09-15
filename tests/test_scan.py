"""Smoke tests for AXguard scanner."""

from pathlib import Path

from engines.scanner import ScanOptions, run_scan

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "vuln_app"
RULES = ROOT / "rules"


def test_scan_finds_pickle_and_shell():
    result = run_scan(ScanOptions(target=FIXTURES, rules_dir=RULES))
    ids = {f["id"] for f in result["findings"]}
    assert "injection.python-pickle-loads" in ids
    assert "injection.python-subprocess-shell" in ids
    assert "secrets.generic-api-key-assign" in ids


def test_scan_finds_xss_sink():
    result = run_scan(ScanOptions(target=FIXTURES, rules_dir=RULES))
    ids = {f["id"] for f in result["findings"]}
    assert "xss.innerhtml-assign" in ids


def test_scan_finds_new_domain_rules():
    result = run_scan(ScanOptions(target=FIXTURES, rules_dir=RULES))
    ids = {f["id"] for f in result["findings"]}
    assert "sql.python-format-query" in ids
    assert "ssti.flask-render-template-string" in ids
    assert "path.send-file-user" in ids
    assert "debug.django-debug-true" in ids
    assert "crypto.verify-false" in ids
    assert "graphql.disable-auth-introspection" in ids
    assert "upload.no-extension-check" in ids
    assert "nosql.mongo-where-operator" in ids
