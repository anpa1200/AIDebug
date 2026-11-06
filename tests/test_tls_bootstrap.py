import importlib.metadata
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import audit_dependencies, bootstrap_pip

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("version", ["24.1.3", "25.0.1", "26.2", "26.2.1"])
def test_old_pip_requires_bootstrap(version):
    assert not bootstrap_pip.pip_is_safe(version)


@pytest.mark.parametrize("version", ["26.2.2", "26.3", "27.0.0", "26.2.2.post1", "26.3+vendor.1"])
def test_fixed_pip_versions_are_accepted(version):
    assert bootstrap_pip.pip_is_safe(version)


@pytest.mark.parametrize("version", ["26.2.2rc1", "26.4.dev1", "unknown", "26.2.2\n--index-url evil"])
def test_unknown_pip_versions_fail_closed(version):
    with pytest.raises(RuntimeError, match="Cannot verify"):
        bootstrap_pip.pip_is_safe(version)


def test_bootstrap_verifies_wheel_and_installed_version(monkeypatch):
    versions = iter(["25.0.1", "26.2.2"])
    monkeypatch.setattr(importlib.metadata, "version", lambda _: next(versions))
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    bootstrap_pip.bootstrap()
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:3] == [sys.executable, "-m", "pip"]
    for flag in ("--isolated", "--disable-pip-version-check", "--no-index", "--no-deps", "--no-cache-dir"):
        assert flag in command
    assert command[-1] == bootstrap_pip.PIP_WHEEL
    assert "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" in command[-1]
    assert kwargs == {"check": True}


def test_bootstrap_preserves_newer_pip(monkeypatch):
    monkeypatch.setattr(importlib.metadata, "version", lambda _: "26.3")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("must not downgrade pip"))
    bootstrap_pip.bootstrap()


def test_failed_bootstrap_stops_before_more_downloads(monkeypatch):
    monkeypatch.setattr(importlib.metadata, "version", lambda _: "25.0.1")

    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        bootstrap_pip.bootstrap()


def test_bootstrap_rejects_unchanged_old_pip(monkeypatch):
    monkeypatch.setattr(importlib.metadata, "version", lambda _: "25.0.1")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="did not install"):
        bootstrap_pip.bootstrap()


def test_bootstrap_missing_pip_fails_without_network(monkeypatch):
    def missing(_):
        raise importlib.metadata.PackageNotFoundError("pip")

    monkeypatch.setattr(importlib.metadata, "version", missing)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("no pip available"))
    with pytest.raises(RuntimeError, match="pip is missing"):
        bootstrap_pip.bootstrap()


def test_audit_uses_complete_installed_pins_without_pip_resolver(monkeypatch):
    versions = {"pip": "26.3", "certifi": "2026.10.23"}
    monkeypatch.setattr(importlib.metadata, "version", versions.__getitem__)
    frozen = "certifi==2026.10.23\nfrida==17.26.1\n"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] is True
        if "freeze" in command:
            assert command[-5:] == ["--all", "--exclude", "1200km-aidebug", "--exclude", "pip"]
            return SimpleNamespace(stdout=frozen)
        assert {"--strict", "--disable-pip", "--no-deps"} <= set(command)
        assert Path(command[-1]).read_text() == "pip==26.3\n" + frozen
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    audit_dependencies.audit()
    assert len(calls) == 2
    assert not Path(calls[1][-1]).exists()


@pytest.mark.parametrize("versions", [
    {"pip": "26.2.1", "certifi": "2026.10.23"},
    {"pip": "26.3", "certifi": "2026.7.22"},
])
def test_audit_rejects_unpatched_transport_before_network(monkeypatch, versions):
    monkeypatch.setattr(importlib.metadata, "version", versions.__getitem__)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("unsafe network access"))
    with pytest.raises(RuntimeError, match="below the patched TLS floor"):
        audit_dependencies.audit()


def test_audit_rejects_empty_snapshot(monkeypatch):
    versions = {"pip": "26.3", "certifi": "2026.10.23"}
    monkeypatch.setattr(importlib.metadata, "version", versions.__getitem__)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=""))
    with pytest.raises(RuntimeError, match="empty dependency snapshot"):
        audit_dependencies.audit()


def test_ci_bootstraps_every_python_job_and_smoke_environment():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert workflow.count("uses: actions/setup-python@") == 6
    assert workflow.count("run: python scripts/bootstrap_pip.py") == 6
    assert "/tmp/aidebug-wheel-smoke/bin/python scripts/bootstrap_pip.py" in workflow
    assert 'pip install ".[all]"' in workflow
    assert "python scripts/audit_dependencies.py" in workflow
    assert "pip_audit --strict --requirement" not in workflow


def test_publish_retry_security_tools_come_from_workflow_not_old_tag():
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "ref: ${{ github.workflow_sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "python .release-tools/scripts/bootstrap_pip.py" in workflow
    assert "/tmp/aidebug-wheel-smoke/bin/python .release-tools/scripts/bootstrap_pip.py" in workflow
    assert "python .release-tools/scripts/audit_dependencies.py" in workflow
    assert 'pip install ".[dev,dynamic]" "certifi>=2026.10.19"' in workflow
    assert workflow.index("run: python .release-tools/scripts/bootstrap_pip.py") < workflow.index('pip install "packaging>=24"')
    assert "pip_audit --strict --requirement" not in workflow


def test_local_gate_bootstraps_both_environments():
    script = (ROOT / "scripts/release-readiness.sh").read_text()
    assert '"$gate_python" scripts/bootstrap_pip.py' in script
    assert '"$work_dir/venv/bin/python" scripts/bootstrap_pip.py' in script
    assert '"$gate_python" scripts/audit_dependencies.py' in script
    assert "pip_audit --strict --requirement" not in script
