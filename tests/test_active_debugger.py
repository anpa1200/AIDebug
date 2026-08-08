from debugger.active import GDBMIDebugger, _decode_mi_string, _fields


def test_mi_field_parsing_decodes_strings():
    record = '*stopped,reason="breakpoint-hit",frame={addr="0x401000",func="main",file="x.c"}'
    fields = _fields(record)
    assert fields["reason"] == "breakpoint-hit"
    assert fields["addr"] == "0x401000"
    assert fields["func"] == "main"
    assert _decode_mi_string(r"line\nvalue") == "line\nvalue"


def test_debug_stop_tracks_register_changes_inputs_and_output(monkeypatch):
    debugger = object.__new__(GDBMIDebugger)
    debugger.arch = "x86-64"
    debugger.bits = 64
    debugger.os_target = "linux"
    debugger._previous_registers = {"rax": "0x1", "rdi": "0x2"}
    debugger._active_function = "sum"
    debugger._active_inputs = {"rdi": "0x2", "rsi": "0x3"}
    monkeypatch.setattr(
        debugger,
        "registers",
        lambda: {"rax": "0x5", "rdi": "0x2", "rsi": "0x3"},
    )

    stop = debugger._build_stop(
        '*stopped,reason="function-finished",return-value="5",'
        'frame={addr="0x401010",func="sum",file="sample.c",line="7"}'
    )

    assert stop.function == "sum"
    assert stop.address == 0x401010
    assert stop.function_inputs == {"rdi": "0x2", "rsi": "0x3"}
    assert stop.function_output == "GDB return=5"
    assert stop.changed_registers["rax"] == ("0x1", "0x5")
