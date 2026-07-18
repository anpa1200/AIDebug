from types import SimpleNamespace

import config
import debugger
import main


class FakeStore:
    db_path = "/tmp/custom-aidebug.db"

    def __init__(self):
        self.api_calls = []
        self.network_events = []
        self.runtime_events = []

    def save_api_call(self, session_id, module, function, args, retval):
        self.api_calls.append((session_id, module, function, args, retval))

    def save_network_event(self, session_id, event):
        self.network_events.append((session_id, event))

    def save_runtime_event(self, session_id, event):
        self.runtime_events.append((session_id, event))


class FakeDebugEngine:
    instance = None

    def __init__(self, **kwargs):
        type(self).instance = self
        self.kwargs = kwargs
        self.is_available = True
        self.is_attached = False
        self.hooks = []
        self.resume_called = False
        self.detached = False
        self.status = {}

    def attach(self, pid):
        self.pid = pid
        return True

    def spawn(self, binary_path):
        self.binary_path = binary_path
        return 777

    def hook_function(self, address, on_entry=None, on_exit=None):
        self.hooks.append(address)

    def load_api_tracer(self, on_call=None):
        on_call(
            {
                "module": "kernel32.dll",
                "function": "CreateFileA",
                "args": ["sample"],
                "retval": "0x1",
            }
        )
        self.status["api"] = {"ready": True, "installed_count": 1, "errors": []}
        return self.status["api"]

    def load_network_tracer(self, on_event=None):
        on_event(
            {
                "event": "connect",
                "function": "connect",
                "ip": "203.0.113.4",
                "port": 443,
                "size": 0,
            }
        )
        self.status["network"] = {"ready": True, "installed_count": 1, "errors": []}
        return self.status["network"]

    def load_unpack_detector(self, on_unpack=None):
        on_unpack(
            {
                "event": "executable_protection_transition",
                "address": "0x700000",
                "size": 4096,
                "old_protect": 4,
                "new_protect": 32,
                "entry_point_candidate": "0x700010",
                "confidence": "heuristic",
            }
        )
        self.status["protection"] = {"ready": True, "installed_count": 1, "errors": []}
        return self.status["protection"]

    def get_instrumentation_status(self):
        return self.status

    def resume(self):
        self.resume_called = True
        return True

    def detach(self):
        self.detached = True


class PartialTracerDebugEngine(FakeDebugEngine):
    instance = None

    def load_api_tracer(self, on_call=None):
        raise RuntimeError("API tracer unavailable")


class RepeatedTracerDebugEngine(FakeDebugEngine):
    instance = None

    def load_api_tracer(self, on_call=None):
        super().load_api_tracer(on_call=on_call)
        return super().load_api_tracer(on_call=on_call)

    def load_network_tracer(self, on_event=None):
        super().load_network_tracer(on_event=on_event)
        return super().load_network_tracer(on_event=on_event)

    def load_unpack_detector(self, on_unpack=None):
        super().load_unpack_detector(on_unpack=on_unpack)
        return super().load_unpack_detector(on_unpack=on_unpack)


class ZeroHookDebugEngine(FakeDebugEngine):
    instance = None

    def _zero_status(self, key):
        self.status[key] = {"ready": True, "installed_count": 0, "errors": []}
        return self.status[key]

    def load_api_tracer(self, on_call=None):
        return self._zero_status("api")

    def load_network_tracer(self, on_event=None):
        return self._zero_status("network")

    def load_unpack_detector(self, on_unpack=None):
        return self._zero_status("protection")


class UnreadyDebugEngine(FakeDebugEngine):
    instance = None

    def load_api_tracer(self, on_call=None):
        return {"ready": False, "installed_count": 0, "errors": []}


class DegradedDebugEngine(FakeDebugEngine):
    instance = None

    def load_network_tracer(self, on_event=None):
        status = super().load_network_tracer(on_event=on_event)
        status["errors"] = [{"hook": "send", "error": "attach failed"}]
        return status


class CappedStore(FakeStore):
    def save_api_call(self, *args):
        super().save_api_call(*args)
        return False

    def save_network_event(self, *args):
        super().save_network_event(*args)
        return False

    def save_runtime_event(self, *args):
        super().save_runtime_event(*args)
        return False


def test_dynamic_attach_wires_rebased_hooks_and_persists_all_event_types(monkeypatch):
    monkeypatch.setattr(debugger, "DebugEngine", FakeDebugEngine)
    store = FakeStore()
    binary_info = SimpleNamespace(
        image_base=0x400000,
        filename="sample.exe",
    )

    completed = main.run_dynamic(
        binary_info,
        SimpleNamespace(get_function=lambda address: None),
        [0x401000, 0x402000],
        store,
        9,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
        frida_host="192.0.2.1:27042",
    )

    engine = FakeDebugEngine.instance
    assert completed
    assert engine.kwargs == {
        "remote_host": "192.0.2.1:27042",
        "static_image_base": 0x400000,
        "module_name": "sample.exe",
    }
    assert engine.hooks == [0x401000, 0x402000]
    assert not engine.resume_called  # An already-running attached process is not resumed.
    assert engine.detached
    assert store.api_calls[0][2] == "CreateFileA"
    assert store.network_events[0][1]["event"] == "connect"
    assert store.runtime_events[0][1]["confidence"] == "heuristic"


def test_dynamic_tracers_load_independently_after_one_setup_failure(monkeypatch):
    monkeypatch.setattr(debugger, "DebugEngine", PartialTracerDebugEngine)
    store = FakeStore()
    binary_info = SimpleNamespace(image_base=0x400000, filename="sample.exe")

    completed = main.run_dynamic(
        binary_info,
        SimpleNamespace(get_function=lambda address: None),
        [0x401000],
        store,
        10,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    engine = PartialTracerDebugEngine.instance
    assert not completed
    assert engine.detached
    assert store.api_calls == []
    assert store.network_events[0][1]["event"] == "connect"
    assert store.runtime_events[0][1]["confidence"] == "heuristic"


def test_dynamic_function_hooks_are_bounded(monkeypatch):
    monkeypatch.setattr(debugger, "DebugEngine", FakeDebugEngine)
    addresses = [0x401000 + index * 0x10 for index in range(75)]

    completed = main.run_dynamic(
        SimpleNamespace(image_base=0x400000, filename="sample.exe"),
        SimpleNamespace(get_function=lambda address: None),
        addresses,
        FakeStore(),
        12,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    assert completed
    assert FakeDebugEngine.instance.hooks == addresses[:config.MAX_DYNAMIC_FUNCTION_HOOKS]


def test_dynamic_persistence_cap_notices_are_emitted_once(monkeypatch, capsys):
    monkeypatch.setattr(debugger, "DebugEngine", RepeatedTracerDebugEngine)

    completed = main.run_dynamic(
        SimpleNamespace(image_base=0x400000, filename="sample.exe"),
        SimpleNamespace(get_function=lambda address: None),
        [0x401000],
        CappedStore(),
        11,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    stderr = capsys.readouterr().err
    assert completed
    assert stderr.count("API event persistence cap reached") == 1
    assert stderr.count("network event persistence cap reached") == 1
    assert stderr.count("runtime event persistence cap reached") == 1


def test_dynamic_zero_hook_observers_are_reported_truthfully(monkeypatch, capsys):
    monkeypatch.setattr(debugger, "DebugEngine", ZeroHookDebugEngine)

    completed = main.run_dynamic(
        SimpleNamespace(image_base=0x400000, filename="sample.exe"),
        SimpleNamespace(get_function=lambda address: None),
        [],
        FakeStore(),
        13,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    output = capsys.readouterr()
    assert completed
    assert output.out.count("observer active; 0 hooks are currently installed") == 3
    assert "Loaded dynamic tracer" not in output.out


def test_dynamic_unready_tracer_is_a_failure(monkeypatch, capsys):
    monkeypatch.setattr(debugger, "DebugEngine", UnreadyDebugEngine)

    completed = main.run_dynamic(
        SimpleNamespace(image_base=0x400000, filename="sample.exe"),
        SimpleNamespace(get_function=lambda address: None),
        [],
        FakeStore(),
        14,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    assert not completed
    assert "API tracer setup failed: script did not confirm readiness" in capsys.readouterr().err


def test_dynamic_late_instrumentation_error_degrades_result(monkeypatch, capsys):
    monkeypatch.setattr(debugger, "DebugEngine", DegradedDebugEngine)

    completed = main.run_dynamic(
        SimpleNamespace(image_base=0x400000, filename="sample.exe"),
        SimpleNamespace(get_function=lambda address: None),
        [],
        FakeStore(),
        15,
        SimpleNamespace(),
        pid=123,
        binary_path="sample.exe",
    )

    assert not completed
    assert "network instrumentation reported 1 error" in capsys.readouterr().err
