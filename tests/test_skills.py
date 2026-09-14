"""Skill registry and validator smoke tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_validate_skills_script_ok():
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_skills.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK" in r.stdout


def test_core_skill_count():
    skills = list((ROOT / "skills" / "security").rglob("SKILL.md"))
    assert len(skills) >= 30


def test_index_lists_thirty_domain_skills():
    text = (ROOT / "skills" / "index.yaml").read_text(encoding="utf-8")
    # Count domain skill path entries under skills/security/
    n = text.count("path: skills/security/")
    assert n == 30
