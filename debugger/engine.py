"""
Frida-based dynamic instrumentation engine.

Usage:
    engine = DebugEngine()
    if engine.is_available:
        pid = engine.spawn('/path/to/binary')
        engine.hook_function(0x401234, on_entry=my_callback)
        engine.resume()
    ...
    engine.detach()
"""
import threading
from typing import Optional, Callable

from .snapshot import FunctionSnapshot


class DebugEngine:

    def __init__(self):
        self._session = None
        self._pid: Optional[int] = None
        self._hooks: dict = {}          # address -> {entry_cb, exit_cb, script}
        self._snapshots: dict = {}      # address -> FunctionSnapshot
        self._api_calls: list = []      # [{module, function, args, retval}]
        self._api_script = None
        self._on_api_call: Optional[Callable] = None
        self._lock = threading.Lock()
        self._available = self._probe_frida()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._available

    def spawn(self, binary_path: str, args: list = None) -> Optional[int]:
        """Spawn a new process and attach. Returns PID or None."""
        if not self._available:
            return None
        import frida
        try:
            args = args or []
            pid = frida.spawn([binary_path] + args)
            self._pid = pid
            self._do_attach(pid)
            return pid
        except Exception as e:
            print(f"[DebugEngine] spawn failed: {e}")
            return None

    def attach(self, pid: int) -> bool:
        """Attach to an already-running process."""
        if not self._available:
            return False
        self._pid = pid
        return self._do_attach(pid)

    def resume(self):
        """Resume a spawned (paused) process."""
        if self._pid and self._available:
            import frida
            try:
                frida.resume(self._pid)
            except Exception as e:
                print(f"[DebugEngine] resume failed: {e}")

    def hook_function(
        self,
        address: int,
        on_entry: Callable = None,
        on_exit: Callable = None,
    ):
        """
        Install entry/exit hooks at `address`.
        Callbacks receive a FunctionSnapshot argument.
        """
        if not self._session:
            return
        js = self._hook_js(address)
        script = self._session.create_script(js)
        script.on('message', lambda msg, data: self._on_hook_msg(msg, data, address))
        script.load()
        with self._lock:
            self._hooks[address] = {
                'entry_cb': on_entry,
                'exit_cb':  on_exit,
                'script':   script,
            }

    def load_api_tracer(self, on_call: Callable = None):
        """
        Load the Windows API tracer script (tracer.js).
        `on_call` is invoked with dict {module, function, args, retval} per event.
        """
        if not self._session:
            return
        import os
        js_path = os.path.join(os.path.dirname(__file__), 'scripts', 'tracer.js')
        with open(js_path, 'r') as f:
            js = f.read()
        self._on_api_call = on_call
        self._api_script = self._session.create_script(js)
        self._api_script.on('message', self._on_api_msg)
        self._api_script.load()

    def get_snapshot(self, address: int) -> Optional[FunctionSnapshot]:
        return self._snapshots.get(address)

    def get_api_calls(self) -> list:
        with self._lock:
            return list(self._api_calls)

    def detach(self):
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _probe_frida(self) -> bool:
        try:
            import frida  # noqa: F401
            return True
        except ImportError:
            return False

    def _do_attach(self, pid: int) -> bool:
        import frida
        try:
            self._session = frida.attach(pid)
            self._session.on('detached', self._on_detached)
            return True
        except Exception as e:
            print(f"[DebugEngine] attach to PID {pid} failed: {e}")
            return False

    def _on_detached(self, reason, crash):
        print(f"[DebugEngine] detached — reason: {reason}")

    def _on_hook_msg(self, message, data, address: int):
        if message['type'] != 'send':
            return
        payload = message['payload']
        snapshot = self._snapshots.setdefault(address, FunctionSnapshot(function_address=address))

        if payload.get('type') == 'entry':
            snapshot.entry_registers = payload.get('registers', {})
            if data:
                snapshot.entry_stack = bytes(data)
            hook = self._hooks.get(address, {})
            if hook.get('entry_cb'):
                hook['entry_cb'](snapshot)

        elif payload.get('type') == 'exit':
            snapshot.exit_registers = payload.get('registers', {})
            try:
                snapshot.return_value = int(payload.get('retval', '0'), 0)
            except (ValueError, TypeError):
                snapshot.return_value = 0
            hook = self._hooks.get(address, {})
            if hook.get('exit_cb'):
                hook['exit_cb'](snapshot)

    def _on_api_msg(self, message, data):
        if message['type'] != 'send':
            return
        payload = message['payload']
        if payload.get('type') == 'api_call':
            entry = {
                'module':   payload.get('module', ''),
                'function': payload.get('function', ''),
                'args':     payload.get('args', []),
                'retval':   '',
            }
            with self._lock:
                self._api_calls.append(entry)
            if self._on_api_call:
                self._on_api_call(entry)

        elif payload.get('type') == 'api_return':
            fn = payload.get('function', '')
            retval = payload.get('retval', '')
            with self._lock:
                # Back-fill retval into the last matching call
                for rec in reversed(self._api_calls):
                    if rec['function'] == fn and rec['retval'] == '':
                        rec['retval'] = retval
                        break

    # ------------------------------------------------------------------
    # Hook JavaScript (x86/x86-64, works on Wine too)
    # ------------------------------------------------------------------

    def _hook_js(self, address: int) -> str:
        addr_str = hex(address)
        return f"""\
'use strict';
var addr = ptr('{addr_str}');
Interceptor.attach(addr, {{
    onEnter: function(args) {{
        var ctx = this.context;
        var regs = {{}};
        var names = ['eax','ebx','ecx','edx','esi','edi','esp','ebp',
                     'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip'];
        names.forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});
        var stackBytes = null;
        try {{ stackBytes = Memory.readByteArray(ctx.esp || ctx.rsp, 64); }} catch(e) {{}}
        send({{type:'entry', address:'{addr_str}', registers:regs}}, stackBytes);
        this._addr = '{addr_str}';
    }},
    onLeave: function(retval) {{
        var ctx = this.context;
        var regs = {{}};
        ['eax','rax'].forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});
        send({{type:'exit', address:this._addr, retval:retval.toString(), registers:regs}});
    }}
}});
"""
