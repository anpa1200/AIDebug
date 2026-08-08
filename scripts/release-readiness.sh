#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON:-python3}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

"$python_bin" -m venv "$work_dir/gate-venv"
gate_python="$work_dir/gate-venv/bin/python"
"$gate_python" -m pip install -e ".[dev,dynamic]"

"$gate_python" scripts/check_release_metadata.py
"$gate_python" scripts/check_evidence_assets.py
"$gate_python" scripts/check_docs.py
"$gate_python" -m ruff check .
"$gate_python" -m pytest -q
"$gate_python" -c \
  "import frida; from debugger.engine import DebugEngine; assert DebugEngine().is_available"
"$gate_python" -m bandit -q -r analysis debugger learning reporting storage ui main.py config.py \
  --severity-level medium --confidence-level medium
"$gate_python" -m pip check
"$gate_python" -m pip_audit --strict --requirement requirements.txt
"$gate_python" -m pip_audit --strict --requirement requirements-ai.txt
"$gate_python" -m pip_audit --strict --requirement requirements-dynamic.txt
"$gate_python" -c "import yara; yara.compile(filepath='examples/mock-output/aidebug-candidate.yar')"
command -v node >/dev/null || {
  echo "release readiness error: Node.js is required to syntax-check Frida scripts" >&2
  exit 1
}
for script in debugger/scripts/*.js; do
  node --check "$script"
done

"$gate_python" -m build --outdir "$work_dir/dist"
"$gate_python" -m twine check --strict "$work_dir"/dist/*
"$gate_python" scripts/check_distribution.py "$work_dir"/dist/*
"$python_bin" -m venv "$work_dir/venv"
"$work_dir/venv/bin/python" -m pip install "$work_dir"/dist/*.whl
"$work_dir/venv/bin/python" -m pip check
"$work_dir/venv/bin/aidebug" --help >/dev/null
"$work_dir/venv/bin/aidebug" --version
"$work_dir/venv/bin/aidebug" --learn mov-load >/dev/null
"$work_dir/venv/bin/python" -c \
  "from importlib.resources import files; assert files('analysis').joinpath('data/flirt_sigs.json').is_file()"
"$work_dir/venv/bin/python" -c \
  "from learning import catalog; assert len(catalog()) >= 30"
"$work_dir/venv/bin/python" -c \
  "from analysis.static_analyzer import StaticAnalyzer; info = StaticAnalyzer().analyze('/bin/true'); assert info.file_format == 'ELF'"
"$work_dir/venv/bin/aidebug" --binary /bin/true --offline --no-tui --json-export --yara \
  --max-functions 5 --out-dir "$work_dir/smoke-output" --db "$work_dir/smoke.db"
test -s "$work_dir/smoke-output/true_session_1_export.json"
test -s "$work_dir/smoke-output/true_session_1.yar"
"$gate_python" -c \
  "import yara; yara.compile(filepath='$work_dir/smoke-output/true_session_1.yar')"

echo "AIDebug release-readiness checks passed."
