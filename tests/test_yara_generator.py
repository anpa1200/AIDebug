import json
import re
import sys
from types import SimpleNamespace

import pytest
import yara

import config
from reporting.yara_generator import (
    YaraGenerationError,
    YaraGenerator,
    _sanitize_rule_name,
)


class FakeMessages:
    def __init__(self, response_text):
        self.response_text = response_text
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return SimpleNamespace(content=[SimpleNamespace(text=self.response_text)])


class FakeClient:
    def __init__(self, response_text):
        self.messages = FakeMessages(response_text)


def _trace(address=0x401000, name="danger", strings=None):
    return {
        "address": address,
        "name": name,
        "risk_level": "HIGH",
        "strings_referenced": json.dumps(strings or []),
        "disassembly": "0x401000: xor eax, 0x41\n0x401004: ret",
        "ai_analysis_json": json.dumps(
            {
                "suggested_name": name,
                "summary": "Suspicious decoder",
                "behaviors": ["XOR decode"],
                "mitre_technique": "T1027",
            }
        ),
    }


def test_yara_accepts_only_exact_single_compiled_rule(monkeypatch, tmp_path):
    expected = _sanitize_rule_name("danger", 0x401000)
    source = f'rule {expected} {{ strings: $a = "indicator" condition: $a }}'
    compiled = []
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(
            compile=lambda **kwargs: (
                compiled.append(kwargs["source"]),
                SimpleNamespace(match=lambda **_kwargs: []),
            )[1]
        ),
    )
    client = FakeClient(source)
    output = tmp_path / "candidate.yar"

    _, count = YaraGenerator(client=client).generate({}, [_trace()], output)

    content = output.read_text(encoding="utf-8")
    assert count == 1
    assert source in content
    assert compiled == [source]
    prompt = client.messages.requests[0]["messages"][0]["content"]
    assert "UNTRUSTED_FUNCTION_EVIDENCE" in prompt
    assert expected in prompt


def test_yara_remote_rejects_includes_and_multiple_rules_without_fallback(
    monkeypatch,
    tmp_path,
):
    expected = _sanitize_rule_name("rule", 0x401000)
    malicious = (
        'include "/etc/passwd"\n'
        f"rule {expected} {{ condition: true }}\n"
        "rule injected { condition: true }"
    )
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(compile=lambda **kwargs: object()),
    )
    output = tmp_path / "fallback.yar"

    with pytest.raises(YaraGenerationError, match="failed safety or syntax validation"):
        YaraGenerator(client=FakeClient(malicious)).generate(
            {"filename": "sample\ninclude \"other.yar\"", "sha256": "abc\nrule evil"},
            [_trace(name="rule", strings=[])],
            output,
        )

    assert not output.exists()


def test_yara_remote_rejects_obvious_match_all_condition(monkeypatch, tmp_path):
    expected = _sanitize_rule_name("danger", 0x401000)
    match_all = f"rule {expected} {{ condition: filesize >= 0 }}"
    compiled = []
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(compile=lambda **kwargs: compiled.append(kwargs["source"])),
    )
    output = tmp_path / "match-all.yar"

    with pytest.raises(YaraGenerationError, match="failed safety or syntax validation"):
        YaraGenerator(client=FakeClient(match_all)).generate({}, [_trace()], output)

    assert compiled == []
    assert not output.exists()


def test_yara_remote_request_failure_is_explicit_and_does_not_write(tmp_path):
    class FailingMessages:
        def create(self, **kwargs):
            del kwargs
            raise TimeoutError("provider timeout")

    output = tmp_path / "remote-failure.yar"
    client = SimpleNamespace(messages=FailingMessages())

    with pytest.raises(YaraGenerationError, match=r"request failed.*TimeoutError"):
        YaraGenerator(client=client).generate({}, [_trace()], output)

    assert not output.exists()


def test_yara_remote_rejects_semantic_match_all_not_covered_by_text_filter(tmp_path):
    expected = _sanitize_rule_name("danger", 0x401000)
    match_all = f"rule {expected} {{ condition: filesize < 1GB }}"
    output = tmp_path / "semantic-match-all.yar"

    with pytest.raises(YaraGenerationError, match="failed safety or syntax validation"):
        YaraGenerator(client=FakeClient(match_all)).generate({}, [_trace()], output)

    assert not output.exists()


def test_yara_remote_rule_limit_caps_provider_requests(monkeypatch, tmp_path):
    expected = _sanitize_rule_name("first", 0x401000)
    source = f'rule {expected} {{ strings: $a = "indicator" condition: $a }}'
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(
            compile=lambda **kwargs: SimpleNamespace(match=lambda **_match_kwargs: [])
        ),
    )
    client = FakeClient(source)
    output = tmp_path / "capped.yar"

    _, count = YaraGenerator(client=client).generate(
        {},
        [_trace(name="first"), _trace(0x402000, "second")],
        output,
        max_rules=1,
    )

    assert count == 1
    assert len(client.messages.requests) == 1
    assert "aidebug_first_401000" in output.read_text(encoding="utf-8")
    assert "aidebug_second_402000" not in output.read_text(encoding="utf-8")


def test_yara_offline_fallback_is_deliberate_safe_and_compilable(tmp_path):
    output = tmp_path / "fallback.yar"
    YaraGenerator(allow_remote=False).generate(
        {"filename": "sample\ninclude \"other.yar\"", "sha256": "abc\nrule evil"},
        [_trace(name="rule", strings=[])],
        output,
    )
    content = output.read_text(encoding="utf-8")

    assert not re.search(r"(?m)^(?:include|import)\b", content)
    assert "condition:\n        false" in content
    assert content.count("\nrule ") == 1
    yara.compile(filepath=str(output))


def test_yara_fallback_escapes_control_chars_and_rule_names_are_unique(tmp_path):
    output = tmp_path / "escaped.yar"
    traces = [
        _trace(0x401000, '9 bad\nname"', ['c2"\n\\path\x00']),
        _trace(0x402000, '9 bad\nname"', ["second-indicator"]),
    ]

    _, count = YaraGenerator(allow_remote=False).generate(
        {"filename": "bad\nrule injected", "sha256": "x\r\ninclude y"},
        traces,
        output,
    )
    content = output.read_text(encoding="utf-8")
    rule_names = re.findall(r"(?m)^rule ([A-Za-z_][A-Za-z0-9_]*)", content)

    assert count == 2
    assert len(rule_names) == len(set(rule_names)) == 2
    assert all(name.startswith("aidebug_") for name in rule_names)
    assert not re.search(r"(?m)^(?:include|import)\b", content)
    assert '\\n' in content
    assert '\\x00' in content


def test_yara_offline_rule_limit_bounds_output(tmp_path):
    output = tmp_path / "offline-capped.yar"
    _, count = YaraGenerator(allow_remote=False).generate(
        {},
        [_trace(name="first", strings=["one"]), _trace(0x402000, "second", ["two"])],
        output,
        max_rules=1,
    )

    content = output.read_text(encoding="utf-8")
    assert count == 1
    assert "aidebug_first_401000" in content
    assert "aidebug_second_402000" not in content


def test_yara_writes_an_empty_ruleset_without_api_or_targets(tmp_path):
    output = tmp_path / "empty.yar"
    path, count = YaraGenerator(allow_remote=False).generate({}, [], output)

    assert path == str(output)
    assert count == 0
    assert output.exists()
    assert "No HIGH/CRITICAL functions" in output.read_text(encoding="utf-8")


def test_yara_client_uses_the_configured_request_timeout(monkeypatch):
    constructor_arguments = {}

    def build_client(**kwargs):
        constructor_arguments.update(kwargs)
        return object()

    monkeypatch.setitem(
        sys.modules,
        "anthropic",
        SimpleNamespace(Anthropic=build_client),
    )

    client = YaraGenerator(api_key="test-key").client

    assert client is not None
    assert constructor_arguments == {
        "api_key": "test-key",
        "timeout": config.AI_TIMEOUT_SECONDS,
    }
