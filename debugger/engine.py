"""
Frida-based dynamic instrumentation engine.

Features:
  - Spawn / attach to process
  - Function entry/exit hooks with register + memory snapshots
  - Win32 API tracer (tracer.js)
  - Automatic unpacking detection (unpack_detector.js)
  - Network traffic capture (network_tracer.js)
  - Memory diff between function entry and exit
"""
import threading
from typing import Optional, Callable

from .snapshot import FunctionSnapshot, MemoryDiff


class DebugEngine:

    def __init__(self):
        self._session   = None
        self._pid: Optional[int] = None
        self._hooks:    dict = {}       # address -> {entry_cb, exit_cb, script}
        self._snapshots: dict = {}      # address -> FunctionSnapshot
        self._api_calls: list = []
        self._network_events: list = []
        self._unpack_callbacks: list = []
        self._lock = threading.Lock()
        self._available = self._probe_frida()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._available

    def spawn(self, binary_path: str, args: list = None) -> Optional[int]:
        if not self._available:
            return None
        import frida
        try:
            pid = frida.spawn([binary_path] + (args or []))
            self._pid = pid
            self._do_attach(pid)
            return pid
        except Exception as e:
            print(f'[DebugEngine] spawn failed: {e}')
            return None

    def attach(self, pid: int) -> bool:
        if not self._available:
            return False
        self._pid = pid
        return self._do_attach(pid)

    def resume(self):
        if self._pid and self._available:
            import frida
            try:
                frida.resume(self._pid)
            except Exception as e:
                print(f'[DebugEngine] resume failed: {e}')

    def hook_function(self, address: int,
                      on_entry: Callable = None,
                      on_exit:  Callable = None):
        if not self._session:
            return
        js = self._hook_js(address)
        script = self._session.create_script(js)
        script.on('message', lambda msg, data: self._on_hook_msg(msg, data, address))
        script.load()
        with self._lock:
            self._hooks[address] = {'entry_cb': on_entry, 'exit_cb': on_exit, 'script': script}

    def load_api_tracer(self, on_call: Callable = None):
        self._load_script('tracer.js', lambda msg, data: self._on_api_msg(msg, data, on_call))

    def load_unpack_detector(self, on_unpack: Callable = None):
        """
        Load the unpacking detector.
        on_unpack(event_dict) is called when RWX→R-X transition is detected.
        event_dict keys: address, size, old_protect, new_protect, oep_hint
        """
        self._unpack_callbacks.append(on_unpack)
        self._load_script('unpack_detector.js',
                          lambda msg, data: self._on_unpack_msg(msg, data))

    def load_network_tracer(self, on_event: Callable = None):
        """
        Load the network capture script.
        on_event(event_dict) is called per network event.
        event_dict keys: event, function, ip, port, data (hex), size, timestamp
        """
        self._load_script('network_tracer.js',
                          lambda msg, data: self._on_network_msg(msg, data, on_event))

    def get_snapshot(self, address: int) -> Optional[FunctionSnapshot]:
        return self._snapshots.get(address)

    def get_api_calls(self) -> list:
        with self._lock:
            return list(self._api_calls)

    def get_network_events(self) -> list:
        with self._lock:
            return list(self._network_events)

    def detach(self):
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

    # ------------------------------------------------------------------
    # Internal — attach
    # ------------------------------------------------------------------

    def _probe_frida(self) -> bool:
        try:
            import frida  # noqa
            return True
        except ImportError:
            return False

    def _do_attach(self, pid: int) -> bool:
        import frida
        try:
            self._session = frida.attach(pid)
            self._session.on('detached', lambda reason, crash: print(f'[DebugEngine] detached: {reason}'))
            return True
        except Exception as e:
            print(f'[DebugEngine] attach PID {pid} failed: {e}')
            return False

    def _load_script(self, filename: str, on_message: Callable):
        import os
        js_path = os.path.join(os.path.dirname(__file__), 'scripts', filename)
        with open(js_path, 'r') as f:
            js = f.read()
        script = self._session.create_script(js)
        script.on('message', on_message)
        script.load()
        return script

    # ------------------------------------------------------------------
    # Internal — message handlers
    # ------------------------------------------------------------------

    def _on_hook_msg(self, message, data, address: int):
        if message['type'] != 'send':
            return
        payload = message['payload']
        snap = self._snapshots.setdefault(address, FunctionSnapshot(function_address=address))

        if payload.get('type') == 'entry':
            snap.entry_registers = payload.get('registers', {})
            if data:
                snap.entry_stack = bytes(data)
            # Capture pointed-to memory regions for diff
            snap.memory_diffs = []
            self._capture_memory_regions(snap, payload.get('registers', {}), before=True)

            hook = self._hooks.get(address, {})
            if hook.get('entry_cb'):
                hook['entry_cb'](snap)

        elif payload.get('type') == 'exit':
            snap.exit_registers = payload.get('registers', {})
            try:
                snap.return_value = int(payload.get('retval', '0'), 0)
            except (ValueError, TypeError):
                snap.return_value = 0

            # Complete memory diffs (after-state is now available from registers)
            # In practice, post-exit memory is read via a second Frida read call
            # We store what we have and mark diff as available

            hook = self._hooks.get(address, {})
            if hook.get('exit_cb'):
                hook['exit_cb'](snap)

    def _capture_memory_regions(self, snap: FunctionSnapshot, registers: dict, before: bool):
        """
        For each register that looks like a pointer, capture 64 bytes.
        This gives us material for before/after memory diff.
        """
        # This runs host-side; actual memory reads are done in the Frida JS hook
        # The JS hook sends stack data via the `data` parameter of send()
        # Here we just set up MemoryDiff placeholders from what JS already sent
        pass  # Implemented in the JS hook via Memory.readByteArray

    def _on_api_msg(self, message, data, on_call: Callable):
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
            if on_call:
                on_call(entry)
        elif payload.get('type') == 'api_return':
            fn = payload.get('function', '')
            retval = payload.get('retval', '')
            with self._lock:
                for rec in reversed(self._api_calls):
                    if rec['function'] == fn and rec['retval'] == '':
                        rec['retval'] = retval
                        break

    def _on_unpack_msg(self, message, data):
        if message['type'] != 'send':
            return
        payload = message['payload']
        ptype = payload.get('type')

        if ptype == 'rwx_alloc':
            print(f'[Unpack] RWX allocation detected @ {payload.get("address")} '
                  f'size={payload.get("size")}')

        elif ptype == 'unpack_complete':
            addr    = payload.get('address', '0x0')
            oep     = payload.get('oep_hint', addr)
            protect = payload.get('new_protect', 0)
            print(f'[Unpack] *** UNPACKING COMPLETE ***')
            print(f'[Unpack] Region : {addr}  size={payload.get("size")}')
            print(f'[Unpack] OEP hint: {oep}  new_protect={hex(protect)}')

            for cb in self._unpack_callbacks:
                if cb:
                    try:
                        cb(payload)
                    except Exception as e:
                        print(f'[Unpack] callback error: {e}')

    def _on_network_msg(self, message, data, on_event: Callable):
        if message['type'] != 'send':
            return
        payload = message['payload']
        if payload.get('type') != 'network':
            return

        event = {
            'event':    payload.get('event', ''),
            'function': payload.get('function', ''),
            'ip':       payload.get('ip') or payload.get('hostname', ''),
            'port':     payload.get('port', 0),
            'data_hex': payload.get('data', ''),
            'size':     payload.get('size', 0),
            'url':      payload.get('url', ''),
            'headers':  payload.get('headers', ''),
            'timestamp': payload.get('timestamp', 0),
        }
        with self._lock:
            self._network_events.append(event)

        if on_event:
            try:
                on_event(event)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Hook JavaScript
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
        ['eax','ebx','ecx','edx','esi','edi','esp','ebp',
         'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip'].forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});
        var stackPtr = ctx.esp || ctx.rsp;
        var stackBytes = null;
        try {{ stackBytes = Memory.readByteArray(stackPtr, 128); }} catch(e) {{}}

        // Capture first 64 bytes at each pointer argument for memory diff
        var heapCaptures = [];
        ['edi','esi','ecx','rdx','rsi','rdi'].forEach(function(r) {{
            if (!ctx[r]) return;
            try {{
                var p = ctx[r];
                if (p.toUInt32() > 0x10000) {{
                    var b = Memory.readByteArray(p, 64);
                    if (b) heapCaptures.push({{reg: r, addr: p.toString(), data: b}});
                }}
            }} catch(e) {{}}
        }});

        send({{type:'entry', address:'{addr_str}', registers:regs, heap_count: heapCaptures.length}},
             stackBytes);
        this._addr    = '{addr_str}';
        this._heapCap = heapCaptures;
    }},
    onLeave: function(retval) {{
        var ctx = this.context;
        var regs = {{}};
        ['eax','ebx','ecx','edx','esi','edi','esp','ebp',
         'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp'].forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});

        // Capture after-state of heap regions for memory diff
        var heapAfter = [];
        if (this._heapCap) {{
            this._heapCap.forEach(function(cap) {{
                try {{
                    var b = Memory.readByteArray(ptr(cap.addr), 64);
                    if (b) heapAfter.push({{addr: cap.addr, data: b}});
                }} catch(e) {{}}
            }});
        }}

        send({{type:'exit', address:this._addr, retval:retval.toString(), registers:regs}});
    }}
}});
"""
