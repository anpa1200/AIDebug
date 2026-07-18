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
import json
import logging
import re
import threading
from collections import deque
from collections.abc import Callable

import config

from .snapshot import FunctionSnapshot, MemoryDiff

logger = logging.getLogger(__name__)


class DebugEngine:

    def __init__(
        self,
        remote_host: str = None,
        static_image_base: int = None,
        module_name: str = None,
    ):
        """
        remote_host: 'host:port' of a remote frida-server (e.g. '192.168.56.101:27042').
                     Leave None to use the local Frida device.
        """
        if static_image_base is not None and (
            isinstance(static_image_base, bool)
            or not isinstance(static_image_base, int)
            or static_image_base < 0
        ):
            raise ValueError('Static image base must be a non-negative integer')

        self._session   = None
        self._device = None
        self._pid: int | None = None
        self._hooks:    dict = {}       # address -> {entry_cb, exit_cb, script}
        self._snapshots: dict = {}      # address -> FunctionSnapshot
        self._active_snapshots: dict = {}
        self._memory_before: dict = {}
        self._api_calls = deque(maxlen=config.MAX_RUNTIME_EVENTS)
        self._pending_api_calls: dict = {}
        self._api_callback = None
        self._network_events = deque(maxlen=config.MAX_RUNTIME_EVENTS)
        self._instrumentation_status: dict = {}
        self._instrumentation_events: dict[str, threading.Event] = {}
        self._unpack_callbacks: list = []
        self._scripts: list = []
        self._lock = threading.Lock()
        self._remote_host = self._normalize_remote_endpoint(remote_host) if remote_host else None
        self._static_image_base = static_image_base
        self._module_name = module_name
        self._dropped_api_calls = 0
        self._dropped_network_events = 0
        self._dropped_snapshots = 0
        self._available = self._probe_frida()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def is_attached(self) -> bool:
        with self._lock:
            return self._session is not None and self._pid is not None

    def spawn(self, binary_path: str, args: list = None) -> int | None:
        if not self._available:
            return None
        try:
            device = self._get_device()
            pid = device.spawn([binary_path] + (args or []))
            if not self._do_attach(pid, device=device):
                try:
                    device.kill(pid)
                except Exception as cleanup_exc:
                    logger.debug('Unable to terminate failed spawned PID %s: %s', pid, cleanup_exc)
                return None
            return pid
        except Exception as e:
            print(f'[DebugEngine] spawn failed: {e}')
            return None

    def attach(self, pid: int) -> bool:
        if not self._available:
            return False
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError('PID must be a positive integer')
        return self._do_attach(pid)

    def resume(self):
        if self._pid and self._available and self._device:
            try:
                self._device.resume(self._pid)
                return True
            except Exception as e:
                print(f'[DebugEngine] resume failed: {e}')
        return False

    def hook_function(self, address: int,
                      on_entry: Callable = None,
                      on_exit:  Callable = None):
        if not self._session:
            raise RuntimeError('Attach to a process before installing function hooks')
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError('Function address must be a non-negative integer')
        if self._static_image_base is None:
            raise RuntimeError(
                'A static image base is required to translate analysis addresses for ASLR/PIE'
            )
        offset = address - self._static_image_base
        if not 0 <= offset <= 0xFFFFFFFF:
            raise ValueError('Function address is outside the supported target module range')
        js = self._hook_js(address, offset)
        tracer = f'function:{address:x}'
        self._prepare_instrumentation(tracer)
        script = None
        with self._lock:
            self._hooks[address] = {'entry_cb': on_entry, 'exit_cb': on_exit, 'script': None}
        try:
            script = self._session.create_script(js)
            script.on('message', lambda msg, data: self._on_hook_msg(msg, data, address))
            script.load()
            status = self._await_instrumentation(tracer)
            if status['installed_count'] < 1:
                raise RuntimeError(f'Function hook at {address:#x} installed no interceptor')
        except Exception:
            if script is not None:
                try:
                    script.unload()
                except Exception as cleanup_exc:
                    logger.debug('Unable to unload failed %s hook: %s', tracer, cleanup_exc)
            with self._lock:
                self._hooks.pop(address, None)
            raise
        with self._lock:
            self._hooks[address]['script'] = script
            self._scripts.append(script)

    def load_api_tracer(self, on_call: Callable = None):
        self._api_callback = on_call
        return self._load_script(
            'tracer.js',
            lambda msg, data: self._on_api_msg(msg, data, on_call),
            'api',
        )

    def load_unpack_detector(self, on_unpack: Callable = None):
        """
        Load the unpacking detector.
        on_unpack(event_dict) is called for a writable-to-executable protection heuristic.
        The event contains an entry-point candidate, not a verified OEP.
        """
        if on_unpack:
            self._unpack_callbacks.append(on_unpack)
        return self._load_script(
            'unpack_detector.js',
            lambda msg, data: self._on_unpack_msg(msg, data),
            'protection',
        )

    def load_network_tracer(self, on_event: Callable = None):
        """
        Load the network capture script.
        on_event(event_dict) is called per network event.
        event_dict keys: event, function, ip, port, data (hex), size, timestamp
        """
        return self._load_script(
            'network_tracer.js',
            lambda msg, data: self._on_network_msg(msg, data, on_event),
            'network',
        )

    def get_snapshot(self, address: int) -> FunctionSnapshot | None:
        with self._lock:
            return self._snapshots.get(address)

    def get_api_calls(self) -> list:
        with self._lock:
            return [
                {**entry, 'args': [dict(arg) if isinstance(arg, dict) else arg
                                   for arg in entry.get('args', [])]}
                for entry in self._api_calls
            ]

    def get_network_events(self) -> list:
        with self._lock:
            return [dict(event) for event in self._network_events]

    def get_instrumentation_status(self) -> dict:
        with self._lock:
            return {
                name: {
                    **status,
                    'errors': [dict(error) for error in status.get('errors', [])],
                }
                for name, status in self._instrumentation_status.items()
            }

    def get_dropped_event_counts(self) -> dict:
        with self._lock:
            return {
                'api_calls': self._dropped_api_calls,
                'network_events': self._dropped_network_events,
                'snapshots': self._dropped_snapshots,
            }

    def detach(self):
        if self._session:
            self._flush_pending_api_calls()
            try:
                self._session.detach()
            except Exception as exc:
                logger.debug('Frida session detach raised: %s', exc)
        with self._lock:
            self._session = None
            self._pid = None
            self._hooks.clear()
            self._scripts.clear()
            self._instrumentation_events.clear()
            self._active_snapshots.clear()
            self._memory_before.clear()

    # ------------------------------------------------------------------
    # Internal — attach
    # ------------------------------------------------------------------

    def _probe_frida(self) -> bool:
        try:
            import frida  # noqa
            return True
        except ImportError:
            return False

    @staticmethod
    def _normalize_remote_endpoint(endpoint: str) -> str:
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError('Remote Frida endpoint must be non-empty text')
        endpoint = endpoint.strip()
        if any(ch.isspace() or ord(ch) < 32 for ch in endpoint):
            raise ValueError('Remote Frida endpoint cannot contain whitespace or control characters')
        if any(ch in endpoint for ch in '/?#@'):
            raise ValueError('Remote Frida endpoint must be host[:port], not a URL')

        if endpoint.startswith('['):
            match = re.fullmatch(r'\[([^\]]+)\](?::(\d+))?', endpoint)
            if not match:
                raise ValueError('Invalid bracketed IPv6 Frida endpoint')
            host, port_text = match.group(1), match.group(2) or '27042'
            normalized_host = f'[{host}]'
        elif endpoint.count(':') == 0:
            normalized_host, port_text = endpoint, '27042'
        elif endpoint.count(':') == 1:
            normalized_host, port_text = endpoint.rsplit(':', 1)
        else:
            # An unbracketed IPv6 literal gets the default port.
            normalized_host, port_text = f'[{endpoint}]', '27042'

        if not normalized_host or not port_text.isdigit():
            raise ValueError('Invalid remote Frida host or port')
        port = int(port_text)
        if not 1 <= port <= 65_535:
            raise ValueError('Remote Frida port must be between 1 and 65535')
        return f'{normalized_host}:{port}'

    def _get_device(self):
        """Return the Frida device to use (local or remote)."""
        if self._device is not None:
            return self._device
        import frida
        if self._remote_host:
            self._device = frida.get_device_manager().add_remote_device(self._remote_host)
        else:
            self._device = frida.get_local_device()
        return self._device

    def _do_attach(self, pid: int, device=None) -> bool:
        try:
            device = device or self._get_device()
            session = device.attach(pid)
            session.on('detached', self._on_detached)
            self._device = device
            self._session = session
            self._pid = pid
            return True
        except Exception as e:
            self._session = None
            self._pid = None
            print(f'[DebugEngine] attach PID {pid} failed: {e}')
            return False

    def _on_detached(self, reason, crash=None):
        del crash
        self._flush_pending_api_calls()
        with self._lock:
            self._session = None
            self._pid = None
            self._active_snapshots.clear()
            self._memory_before.clear()
        print(f'[DebugEngine] detached: {reason}')

    def _load_script(self, filename: str, on_message: Callable, tracer: str):
        import os
        if not self._session:
            raise RuntimeError('Attach to a process before loading instrumentation scripts')
        if filename not in {'tracer.js', 'unpack_detector.js', 'network_tracer.js'}:
            raise ValueError('Unsupported instrumentation script')
        js_path = os.path.join(os.path.dirname(__file__), 'scripts', filename)
        with open(js_path, encoding='utf-8') as f:
            js = f.read()
        self._prepare_instrumentation(tracer)
        script = self._session.create_script(js)
        script.on('message', on_message)
        try:
            script.load()
            status = self._await_instrumentation(tracer)
        except Exception:
            try:
                script.unload()
            except Exception as cleanup_exc:
                logger.debug('Unable to unload failed %s script: %s', tracer, cleanup_exc)
            raise
        with self._lock:
            self._scripts.append(script)
        return status

    # ------------------------------------------------------------------
    # Internal — message handlers
    # ------------------------------------------------------------------

    def _on_hook_msg(self, message, data, address: int):
        tracer = f'function:{address:x}'
        if self._handle_script_error(message, tracer):
            return
        payload = self._payload_from_message(message)
        if payload is None:
            return
        if self._handle_instrumentation_status(payload, tracer):
            return
        invocation_id = self._bounded_int(payload.get('invocation_id'), 1, 2**63 - 1)
        if invocation_id is None:
            return
        key = (address, invocation_id)

        if payload.get('type') == 'entry':
            snap = FunctionSnapshot(function_address=address)
            snap.entry_registers = self._bounded_mapping(payload.get('registers'))
            snap.entry_stack = bytes(data[:128]) if data else b''
            before = self._decode_memory_regions(payload.get('heap_before'))
            with self._lock:
                if len(self._active_snapshots) >= config.MAX_ACTIVE_INVOCATIONS:
                    oldest = next(iter(self._active_snapshots))
                    self._active_snapshots.pop(oldest, None)
                    self._memory_before.pop(oldest, None)
                    self._dropped_snapshots += 1
                self._active_snapshots[key] = snap
                self._memory_before[key] = before
                self._snapshots[address] = snap
                hook = self._hooks.get(address, {})
            self._invoke_callback(hook.get('entry_cb'), snap, 'entry')

        elif payload.get('type') == 'exit':
            with self._lock:
                snap = self._active_snapshots.pop(key, None)
                before = self._memory_before.pop(key, {})
                hook = self._hooks.get(address, {})
            if snap is None:
                return
            snap.exit_registers = self._bounded_mapping(payload.get('registers'))
            snap.exit_stack = bytes(data[:128]) if data else b''
            try:
                snap.return_value = int(payload.get('retval', '0'), 0)
            except (ValueError, TypeError):
                snap.return_value = 0
            after = self._decode_memory_regions(payload.get('heap_after'))
            snap.memory_diffs = [
                MemoryDiff(address=region_address, data_before=before_bytes, data_after=after[region_address])
                for region_address, before_bytes in before.items()
                if region_address in after
            ]
            with self._lock:
                self._snapshots[address] = snap
            self._invoke_callback(hook.get('exit_cb'), snap, 'exit')

    def _on_api_msg(self, message, data, on_call: Callable):
        del data
        if self._handle_script_error(message, 'api'):
            return
        payload = self._payload_from_message(message)
        if payload is None:
            return
        if self._handle_instrumentation_status(payload, 'api'):
            return
        if payload.get('type') == 'api_call':
            call_id = self._bounded_int(payload.get('call_id'), 1, 2**63 - 1)
            if call_id is None:
                return
            entry = {
                'call_id': call_id,
                'thread_id': self._bounded_int(payload.get('thread_id'), 0, 2**32 - 1) or 0,
                'module': self._bounded_text(payload.get('module'), 256),
                'function': self._bounded_text(payload.get('function'), 256),
                'args': self._bounded_list(payload.get('args')),
                'retval':   '',
            }
            with self._lock:
                if len(self._pending_api_calls) >= config.MAX_ACTIVE_INVOCATIONS:
                    oldest = next(iter(self._pending_api_calls))
                    self._pending_api_calls.pop(oldest, None)
                    self._dropped_api_calls += 1
                self._pending_api_calls[call_id] = entry
        elif payload.get('type') == 'api_return':
            call_id = self._bounded_int(payload.get('call_id'), 1, 2**63 - 1)
            if call_id is None:
                return
            with self._lock:
                entry = self._pending_api_calls.pop(call_id, None)
                if entry is None:
                    return
                entry['retval'] = self._bounded_text(payload.get('retval'), 1_024)
                if len(self._api_calls) == self._api_calls.maxlen:
                    self._dropped_api_calls += 1
                self._api_calls.append(entry)
            self._invoke_callback(on_call, dict(entry), 'API')

    def _on_unpack_msg(self, message, data):
        del data
        if self._handle_script_error(message, 'protection'):
            return
        payload = self._payload_from_message(message)
        if payload is None:
            return
        if self._handle_instrumentation_status(payload, 'protection'):
            return
        ptype = payload.get('type')

        if ptype == 'writable_alloc':
            print(f'[Unpack] Writable allocation tracked @ {payload.get("address")} '
                  f'size={payload.get("size")}')

        elif ptype == 'protection_transition':
            addr    = payload.get('address', '0x0')
            candidate = payload.get('entry_point_candidate', addr)
            protect = self._bounded_int(payload.get('new_protect'), 0, 0xFFFFFFFF) or 0
            event = {
                'event': 'executable_protection_transition',
                'address': self._bounded_text(addr, 128),
                'size': self._bounded_int(payload.get('size'), 0, 2**32 - 1) or 0,
                'old_protect': self._bounded_int(payload.get('old_protect'), 0, 0xFFFFFFFF) or 0,
                'new_protect': protect,
                'entry_point_candidate': self._bounded_text(candidate, 128),
                'confidence': 'heuristic',
            }
            print('[Unpack] Executable protection transition observed (heuristic)')
            print(f'[Unpack] Region : {event["address"]}  size={event["size"]}')
            print(f'[Unpack] Entry candidate: {event["entry_point_candidate"]}  '
                  f'new_protect={hex(protect)}')

            for cb in list(self._unpack_callbacks):
                self._invoke_callback(cb, dict(event), 'unpack')

    def _on_network_msg(self, message, data, on_event: Callable):
        del data
        if self._handle_script_error(message, 'network'):
            return
        payload = self._payload_from_message(message)
        if payload is None:
            return
        if self._handle_instrumentation_status(payload, 'network'):
            return
        if payload.get('type') != 'network':
            return

        event = {
            'event': self._bounded_text(payload.get('event'), 128),
            'function': self._bounded_text(payload.get('function'), 256),
            'ip': self._bounded_text(payload.get('ip') or payload.get('hostname'), 512),
            'port': self._bounded_int(payload.get('port'), 0, 65_535) or 0,
            'data_hex': self._bounded_hex(payload.get('data'), 1_024),
            'size': self._bounded_int(payload.get('size'), 0, 2**31 - 1) or 0,
            'url': self._bounded_text(payload.get('url'), 4_096),
            'headers': self._bounded_text(payload.get('headers'), 8_192),
            'timestamp': self._bounded_int(payload.get('timestamp'), 0, 2**63 - 1) or 0,
        }
        with self._lock:
            if len(self._network_events) == self._network_events.maxlen:
                self._dropped_network_events += 1
            self._network_events.append(event)

        self._invoke_callback(on_event, dict(event), 'network')

    @staticmethod
    def _payload_from_message(message) -> dict | None:
        if not isinstance(message, dict) or message.get('type') != 'send':
            return None
        payload = message.get('payload')
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _bounded_text(value, limit: int) -> str:
        if value is None:
            return ''
        if not isinstance(value, str):
            value = str(value)
        return ''.join(ch for ch in value if ch in '\n\t' or ord(ch) >= 32)[:limit]

    @staticmethod
    def _bounded_int(value, minimum: int, maximum: int) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if minimum <= result <= maximum else None

    @classmethod
    def _bounded_hex(cls, value, limit: int) -> str:
        value = cls._bounded_text(value, limit).lower()
        return value if re.fullmatch(r'[0-9a-f]*', value) else ''

    @classmethod
    def _bounded_mapping(cls, value) -> dict:
        if not isinstance(value, dict):
            return {}
        return {
            cls._bounded_text(key, 32): cls._bounded_text(item, 128)
            for key, item in list(value.items())[:32]
        }

    @classmethod
    def _bounded_list(cls, value) -> list:
        if not isinstance(value, list):
            return []
        result = []
        for item in value[:32]:
            if isinstance(item, dict):
                result.append({
                    cls._bounded_text(key, 64): cls._bounded_text(val, 1_024)
                    for key, val in list(item.items())[:16]
                })
            else:
                result.append(cls._bounded_text(item, 1_024))
        return result

    @classmethod
    def _decode_memory_regions(cls, value) -> dict[int, bytes]:
        if not isinstance(value, list):
            return {}
        result = {}
        for item in value[:12]:
            if not isinstance(item, dict):
                continue
            try:
                address = int(item.get('address', ''), 0)
            except (TypeError, ValueError):
                continue
            data_hex = cls._bounded_hex(item.get('data_hex'), 128)
            if address < 0 or len(data_hex) % 2:
                continue
            try:
                result[address] = bytes.fromhex(data_hex)
            except ValueError:
                continue
        return result

    @staticmethod
    def _invoke_callback(callback, value, label: str):
        if not callback:
            return
        try:
            callback(value)
        except Exception as exc:
            print(f'[DebugEngine] {label} callback failed: {exc}')

    def _flush_pending_api_calls(self):
        with self._lock:
            pending = list(self._pending_api_calls.values())
            self._pending_api_calls.clear()
            for entry in pending:
                entry['retval'] = '<call did not return before detach>'
                if len(self._api_calls) == self._api_calls.maxlen:
                    self._dropped_api_calls += 1
                self._api_calls.append(entry)
        for entry in pending:
            self._invoke_callback(self._api_callback, dict(entry), 'API')

    def _handle_instrumentation_status(self, payload: dict, default_tracer: str) -> bool:
        status_type = payload.get('type')
        if status_type not in {'ready', 'hook_status', 'hook_error'}:
            return False
        tracer = self._bounded_text(payload.get('tracer') or default_tracer, 64)
        with self._lock:
            status = self._instrumentation_status.setdefault(tracer, {
                'installed_count': 0,
                'message': '',
                'errors': [],
                'ready': False,
                'fatal': False,
            })
            count = self._bounded_int(payload.get('installed_count'), 0, 100_000)
            if count is not None:
                status['installed_count'] = count
            message = self._bounded_text(payload.get('message'), 512)
            if message:
                status['message'] = message
            if status_type == 'ready':
                status['ready'] = True
            if status_type == 'hook_error':
                error = {
                    'hook': self._bounded_text(payload.get('hook'), 256),
                    'error': self._bounded_text(payload.get('error'), 512),
                }
                status['errors'] = (status['errors'] + [error])[-32:]
                if payload.get('fatal') is True:
                    status['fatal'] = True
            snapshot = dict(status)
            event = self._instrumentation_events.get(tracer)
            if event and (status['ready'] or status['fatal']):
                event.set()
        if status_type in {'ready', 'hook_error'}:
            print(
                f'[DebugEngine] {tracer} instrumentation: '
                f'{snapshot["installed_count"]} hooks installed'
            )
        return True

    def _handle_script_error(self, message, tracer: str) -> bool:
        if not isinstance(message, dict) or message.get('type') != 'error':
            return False
        error = message.get('description') or message.get('stack') or 'unknown script error'
        self._handle_instrumentation_status({
            'type': 'hook_error',
            'tracer': tracer,
            'hook': 'script',
            'error': error,
            'fatal': True,
        }, tracer)
        return True

    def _prepare_instrumentation(self, tracer: str) -> None:
        with self._lock:
            self._instrumentation_status[tracer] = {
                'installed_count': 0,
                'message': 'waiting for script readiness',
                'errors': [],
                'ready': False,
                'fatal': False,
            }
            self._instrumentation_events[tracer] = threading.Event()

    def _await_instrumentation(self, tracer: str) -> dict:
        with self._lock:
            event = self._instrumentation_events.get(tracer)
        if event is None or not event.wait(config.INSTRUMENTATION_READY_TIMEOUT_SECONDS):
            raise RuntimeError(f'{tracer} instrumentation did not report readiness')
        with self._lock:
            status = dict(self._instrumentation_status.get(tracer, {}))
            status['errors'] = [dict(error) for error in status.get('errors', [])]
        if status.get('fatal'):
            detail = status['errors'][-1]['error'] if status.get('errors') else 'script error'
            raise RuntimeError(f'{tracer} instrumentation failed: {detail}')
        if not status.get('ready'):
            raise RuntimeError(f'{tracer} instrumentation did not become ready')
        return status

    # ------------------------------------------------------------------
    # Hook JavaScript
    # ------------------------------------------------------------------

    def _hook_js(self, address: int, module_offset: int) -> str:
        addr_str = hex(address)
        expected_module = json.dumps(self._module_name or '')
        return f"""\
'use strict';
var expectedModule = {expected_module};
var targetModule = Process.mainModule;
if (expectedModule && targetModule.name.toLowerCase() !== expectedModule.toLowerCase()) {{
    throw new Error('Main module mismatch: expected ' + expectedModule + ', got ' + targetModule.name);
}}
var addr = targetModule.base.add({module_offset});
var invocationCounter = 0;

function bytesToHex(buffer) {{
    if (!buffer) return '';
    var bytes = new Uint8Array(buffer);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {{
        hex += ('0' + bytes[i].toString(16)).slice(-2);
    }}
    return hex;
}}

Interceptor.attach(addr, {{
    onEnter: function(args) {{
        this._invocationId = ++invocationCounter;
        var ctx = this.context;
        var regs = {{}};
        ['eax','ebx','ecx','edx','esi','edi','esp','ebp',
         'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','rsp','rbp','rip',
         'r0','r1','r2','r3','sp','lr','pc',
         'x0','x1','x2','x3','x4','x5','x6','x7','x8'].forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});
        var stackPtr = ctx.esp || ctx.rsp || ctx.sp;
        var stackBytes = null;
        try {{ stackBytes = stackPtr.readByteArray(128); }} catch(e) {{}}

        // Capture first 64 bytes at each pointer argument for memory diff
        var heapCaptures = [];
        ['edi','esi','ecx','rdx','rsi','rdi','r8','r9',
         'r0','r1','r2','r3','x0','x1','x2','x3','x4','x5','x6','x7'].forEach(function(r) {{
            if (!ctx[r]) return;
            try {{
                var p = ctx[r];
                if (p.compare(ptr('0x10000')) > 0) {{
                    var b = p.readByteArray(64);
                    if (b) heapCaptures.push({{
                        address: p.toString(),
                        data_hex: bytesToHex(b)
                    }});
                }}
            }} catch(e) {{}}
        }});

        send({{
            type: 'entry',
            invocation_id: this._invocationId,
            address: '{addr_str}',
            registers: regs,
            heap_before: heapCaptures
        }}, stackBytes);
        this._addr    = '{addr_str}';
        this._heapCap = heapCaptures;
    }},
    onLeave: function(retval) {{
        var ctx = this.context;
        var regs = {{}};
        ['eax','ebx','ecx','edx','esi','edi','esp','ebp',
         'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','rsp','rbp',
         'r0','r1','r2','r3','sp','lr','pc',
         'x0','x1','x2','x3','x4','x5','x6','x7','x8'].forEach(function(r) {{
            if (ctx[r] !== undefined) regs[r] = ctx[r].toString();
        }});
        var exitStack = null;
        var exitStackPtr = ctx.esp || ctx.rsp || ctx.sp;
        try {{ exitStack = exitStackPtr.readByteArray(128); }} catch(e) {{}}

        // Capture after-state of heap regions for memory diff
        var heapAfter = [];
        if (this._heapCap) {{
            this._heapCap.forEach(function(cap) {{
                try {{
                    var b = ptr(cap.address).readByteArray(64);
                    if (b) heapAfter.push({{
                        address: cap.address,
                        data_hex: bytesToHex(b)
                    }});
                }} catch(e) {{}}
            }});
        }}

        send({{
            type: 'exit',
            invocation_id: this._invocationId,
            address: this._addr,
            retval: retval.toString(),
            registers: regs,
            heap_after: heapAfter
        }}, exitStack);
    }}
}});
send({{
    type: 'ready',
    tracer: 'function:{address:x}',
    installed_count: 1,
    message: 'Function interceptor installed'
}});
"""
