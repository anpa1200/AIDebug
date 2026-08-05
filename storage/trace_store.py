"""
SQLite-backed persistent store for analysis sessions, function traces, and API calls.
"""
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
import warnings

import config

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_path TEXT    NOT NULL,
    filename    TEXT    NOT NULL,
    sha256      TEXT,
    arch        TEXT,
    bits        INTEGER,
    os_target   TEXT,
    created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS function_traces (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        INTEGER NOT NULL,
    address           INTEGER NOT NULL,
    name              TEXT,
    disassembly       TEXT,
    calls_to          TEXT,    -- JSON array
    called_from       TEXT,    -- JSON array
    strings_referenced TEXT,   -- JSON array
    instruction_count INTEGER,
    snapshot_json     TEXT,
    ai_analysis_json  TEXT,
    risk_level        TEXT,
    mitre_technique   TEXT,
    analyzed_at       TEXT     DEFAULT CURRENT_TIMESTAMP,
    analysis_cache_key TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    UNIQUE(session_id, address)
);

CREATE TABLE IF NOT EXISTS api_calls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    module      TEXT,
    function    TEXT,
    args_json   TEXT,
    retval      TEXT,
    timestamp   TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS network_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    event_type  TEXT,
    function    TEXT,
    ip          TEXT,
    port        INTEGER,
    data_hex    TEXT,
    size        INTEGER,
    url         TEXT,
    headers     TEXT,
    timestamp   INTEGER,
    logged_at   TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detected_patterns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    address     INTEGER NOT NULL,
    name        TEXT,
    description TEXT,
    severity    TEXT,
    evidence    TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runtime_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    event_type  TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    logged_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_traces_session  ON function_traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_risk     ON function_traces(risk_level);
CREATE INDEX IF NOT EXISTS idx_api_session     ON api_calls(session_id);
CREATE INDEX IF NOT EXISTS idx_net_session     ON network_events(session_id);
CREATE INDEX IF NOT EXISTS idx_pat_session     ON detected_patterns(session_id);
CREATE INDEX IF NOT EXISTS idx_runtime_session ON runtime_events(session_id);
"""


class TraceStore:

    API_ARGS_JSON_LIMIT = 16_384
    EVENT_TEXT_LIMIT = 4_096

    def __init__(self, db_path: str):
        db_path = os.fspath(db_path)
        self.db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, mode=0o700, exist_ok=True)
        if db_path != ':memory:':
            try:
                fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            self._tighten_file_permissions(db_path)

        self._lock = threading.RLock()
        self._closed = False
        self._dropped_event_counts = {}
        self._drop_warnings = set()
        self.conn = sqlite3.connect(
            db_path,
            # Several TraceStore instances can legitimately open the same
            # fresh database at once (e.g. concurrent analysis sessions);
            # the first one to arrive runs schema DDL and a WAL-mode switch,
            # both of which take an exclusive lock the others must wait out.
            # 5s was tight enough to occasionally raise "database is locked"
            # under real contention/CI load even though every writer makes
            # progress; 15s stays comfortably below realistic caller
            # timeouts while giving that startup race enough room.
            timeout=15.0,
            check_same_thread=False,
        )
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute('PRAGMA foreign_keys=ON')
            self.conn.execute('PRAGMA busy_timeout=15000')
            self._initialize_schema_with_retry()
            if db_path != ':memory:':
                self.conn.execute('PRAGMA journal_mode=WAL')
                self.conn.execute('PRAGMA synchronous=NORMAL')
                for storage_path in (db_path, f'{db_path}-wal', f'{db_path}-shm'):
                    self._tighten_file_permissions(storage_path)
        except BaseException:
            self.conn.close()
            self._closed = True
            raise

    @staticmethod
    def _tighten_file_permissions(path: str):
        """Best-effort owner-only permissions without following symbolic links."""
        nofollow = getattr(os, 'O_NOFOLLOW', None)
        fchmod = getattr(os, 'fchmod', None)
        if nofollow is not None and fchmod is not None:
            flags = os.O_RDONLY | nofollow | getattr(os, 'O_CLOEXEC', 0)
            try:
                fd = os.open(path, flags)
            except (OSError, TypeError, NotImplementedError):
                return
            try:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    fchmod(fd, 0o600)
            except (OSError, TypeError, NotImplementedError):
                pass
            finally:
                os.close(fd)
            return

        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                return
            os.chmod(path, 0o600, follow_symlinks=False)
        except (OSError, TypeError, NotImplementedError):
            pass

    @staticmethod
    def _schema_statements():
        pending = []
        for line in SCHEMA.splitlines():
            pending.append(line)
            statement = '\n'.join(pending).strip()
            if statement and sqlite3.complete_statement(statement):
                yield statement
                pending.clear()

    def _initialize_schema_with_retry(self, attempts: int = 8) -> None:
        """_initialize_schema() takes an exclusive BEGIN IMMEDIATE lock, so when
        several TraceStore instances open the same fresh (or legacy-schema)
        database at once, only one proceeds at a time and the rest queue
        behind it, each doing a real disk-synced commit. Under CI-level disk
        contention that queue's tail can occasionally still exceed
        busy_timeout for the last connection in line even though every
        writer is making progress; retrying a few times with backoff
        survives that without masking a database that is genuinely stuck
        (which would keep failing on every attempt and still raise).
        """
        delay = 0.1
        for attempt in range(attempts):
            try:
                self._initialize_schema()
                return
            except sqlite3.OperationalError as exc:
                if 'locked' not in str(exc).lower() or attempt == attempts - 1:
                    raise
                time.sleep(delay)
                delay *= 2

    def _initialize_schema(self):
        """Serialize schema validation and additive migrations across connections."""
        self.conn.execute('BEGIN IMMEDIATE')
        try:
            current_version = self.conn.execute('PRAGMA user_version').fetchone()[0]
            if current_version > SCHEMA_VERSION:
                raise RuntimeError(
                    f'Trace database schema version {current_version} is newer than '
                    f'this AIDebug build supports ({SCHEMA_VERSION}); refusing to downgrade it'
                )
            for statement in self._schema_statements():
                self.conn.execute(statement)
            self._migrate_schema()
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def _migrate_schema(self):
        """Apply small additive migrations for databases created by v1.1.0."""
        columns = {
            row['name'] for row in self.conn.execute('PRAGMA table_info(function_traces)')
        }
        if 'analysis_cache_key' not in columns:
            self.conn.execute('ALTER TABLE function_traces ADD COLUMN analysis_cache_key TEXT')
        self.conn.execute(f'PRAGMA user_version={SCHEMA_VERSION}')

    def _record_event_drop(self, table: str, session_id: int):
        key = (table, session_id)
        self._dropped_event_counts[key] = self._dropped_event_counts.get(key, 0) + 1
        if key not in self._drop_warnings:
            self._drop_warnings.add(key)
            warnings.warn(
                f'Dropped additional {table} records for session {session_id}: '
                f'per-session limit is {config.MAX_PERSISTED_EVENTS_PER_TYPE}',
                RuntimeWarning,
                stacklevel=3,
            )

    def get_dropped_event_counts(self, session_id: int) -> dict:
        with self._lock:
            return {
                table: count
                for (table, stored_session_id), count in self._dropped_event_counts.items()
                if stored_session_id == session_id
            }

    def _ensure_open(self):
        if self._closed:
            raise RuntimeError('TraceStore is closed')

    @classmethod
    def _bounded_text(cls, value, limit=None) -> str:
        limit = limit or cls.EVENT_TEXT_LIMIT
        if value is None:
            return ''
        if not isinstance(value, str):
            value = str(value)
        return ''.join(ch for ch in value if ch in '\n\t' or ord(ch) >= 32)[:limit]

    @classmethod
    def _bounded_int(cls, value, minimum: int, maximum: int, default: int = 0) -> int:
        if isinstance(value, bool):
            return default
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return default
        return result if minimum <= result <= maximum else default

    @classmethod
    def _normalize_json(cls, value, depth=0):
        if depth > 6:
            return '<depth-limit>'
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            return cls._bounded_text(value)
        if isinstance(value, bytes):
            return value[:2_048].hex()
        if isinstance(value, (list, tuple)):
            return [cls._normalize_json(item, depth + 1) for item in value[:64]]
        if isinstance(value, dict):
            return {
                cls._bounded_text(key, 128): cls._normalize_json(item, depth + 1)
                for key, item in list(value.items())[:64]
            }
        return cls._bounded_text(value)

    @classmethod
    def _dump_json(cls, value, limit=100_000) -> str:
        encoded = json.dumps(cls._normalize_json(value), ensure_ascii=False, allow_nan=False)
        if len(encoded) <= limit:
            return encoded
        return json.dumps({
            'truncated': True,
            'preview': encoded[:max(0, limit - 40)],
        }, ensure_ascii=False, allow_nan=False)

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(self, binary_info) -> int:
        with self._lock, self.conn:
            self._ensure_open()
            cur = self.conn.execute(
                "INSERT INTO sessions (binary_path, filename, sha256, arch, bits, os_target) "
                "VALUES (?,?,?,?,?,?)",
                (
                    self._bounded_text(binary_info.path, 8_192),
                    self._bounded_text(binary_info.filename, 1_024),
                    self._bounded_text(binary_info.sha256, 128),
                    self._bounded_text(binary_info.arch, 128),
                    self._bounded_int(binary_info.bits, 0, 128),
                    self._bounded_text(binary_info.os_target, 128),
                ),
            )
            return cur.lastrowid

    def list_sessions(self) -> list:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC, id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_session(self, session_id: int) -> dict | None:
        with self._lock:
            self._ensure_open()
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # Function traces
    # ------------------------------------------------------------------

    def save_function_analysis(self, session_id: int, function, analysis, snapshot=None):
        snap_json = self._dump_json({
            'entry_registers': snapshot.entry_registers if snapshot else {},
            'exit_registers':  snapshot.exit_registers  if snapshot else {},
            'return_value':    snapshot.return_value     if snapshot else 0,
        })
        ai_json = self._dump_json({
            'suggested_name':  analysis.suggested_name,
            'summary':         analysis.summary,
            'parameters':      analysis.parameters,
            'return_value':    analysis.return_value,
            'behaviors':       analysis.behaviors,
            'mitre_technique': analysis.mitre_technique,
            'risk_level':      analysis.risk_level,
            'notes':           analysis.notes,
        })
        cache_key = getattr(analysis, 'cache_key', '') or config.AI_CACHE_KEY
        if analysis.suggested_name == 'parse_error':
            cache_key = None
        with self._lock, self.conn:
            self._ensure_open()
            self.conn.execute("""
                INSERT INTO function_traces
                    (session_id, address, name, disassembly, calls_to, called_from,
                     strings_referenced, instruction_count, snapshot_json,
                     ai_analysis_json, risk_level, mitre_technique, analysis_cache_key)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, address) DO UPDATE SET
                    name=excluded.name,
                    disassembly=excluded.disassembly,
                    calls_to=excluded.calls_to,
                    called_from=excluded.called_from,
                    strings_referenced=excluded.strings_referenced,
                    instruction_count=excluded.instruction_count,
                    snapshot_json=excluded.snapshot_json,
                    ai_analysis_json=excluded.ai_analysis_json,
                    risk_level=excluded.risk_level,
                    mitre_technique=excluded.mitre_technique,
                    analysis_cache_key=excluded.analysis_cache_key,
                    analyzed_at=CURRENT_TIMESTAMP
            """, (
                session_id,
                function.address,
                self._bounded_text(analysis.suggested_name, 256),
                self._bounded_text(function.disassembly_text, 8_000),
                self._dump_json(function.calls_to),
                self._dump_json(function.called_from),
                self._dump_json(function.strings_referenced),
                len(function.instructions),
                snap_json,
                ai_json,
                self._bounded_text(analysis.risk_level, 32),
                self._bounded_text(analysis.mitre_technique, 256),
                self._bounded_text(cache_key, 512) if cache_key else None,
            ))

    def get_cached_analysis(self, session_id: int, address: int, cache_key: str = None):
        """Return a cached AIAnalysis for this function, or None."""
        cache_key = cache_key or config.AI_CACHE_KEY
        with self._lock:
            self._ensure_open()
            row = self.conn.execute("""
                SELECT ft.ai_analysis_json
                FROM function_traces AS ft
                JOIN sessions AS source ON source.id = ft.session_id
                JOIN sessions AS current ON current.id = ?
                WHERE source.sha256 = current.sha256
                  AND current.sha256 IS NOT NULL
                  AND ft.address = ?
                  AND ft.analysis_cache_key = ?
                  AND ft.ai_analysis_json IS NOT NULL
                ORDER BY ft.analyzed_at DESC, ft.id DESC
                LIMIT 1
            """, (session_id, address, cache_key)).fetchone()
        if not row:
            return None
        from analysis.ai_analyzer import AIAnalyzer
        try:
            data = json.loads(row['ai_analysis_json'])
            if not isinstance(data, dict):
                return None
            result = object.__new__(AIAnalyzer)._parse(json.dumps(data, ensure_ascii=False))
            if result.suggested_name == 'parse_error':
                return None
            result.cache_key = cache_key
            return result
        except (json.JSONDecodeError, TypeError, ValueError):
            return None

    def get_all_traces(self, session_id: int) -> list:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT * FROM function_traces WHERE session_id=? "
                "ORDER BY CASE risk_level "
                "  WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
                "  WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END, address",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_risk_summary(self, session_id: int) -> dict:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM function_traces "
                "WHERE session_id=? GROUP BY risk_level",
                (session_id,),
            ).fetchall()
            return {r['risk_level']: r['cnt'] for r in rows}

    def search(self, session_id: int, query: str) -> list:
        query = self._bounded_text(query, 1_024)
        escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        q = f'%{escaped}%'
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute("""
                SELECT * FROM function_traces
                WHERE session_id=? AND (
                    name LIKE ? ESCAPE '\\' OR strings_referenced LIKE ? ESCAPE '\\'
                    OR ai_analysis_json LIKE ? ESCAPE '\\'
                )
                ORDER BY CASE risk_level
                  WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                  WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END, address
            """, (session_id, q, q, q)).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # API call log (dynamic mode)
    # ------------------------------------------------------------------

    def save_api_call(self, session_id: int, module: str, function: str,
                      args: list, retval: str):
        with self._lock, self.conn:
            self._ensure_open()
            cursor = self.conn.execute(
                "INSERT INTO api_calls (session_id, module, function, args_json, retval) "
                "SELECT ?,?,?,?,? WHERE ("
                "SELECT COUNT(*) FROM api_calls WHERE session_id=?"
                ") < ?",
                (
                    session_id,
                    self._bounded_text(module, 256),
                    self._bounded_text(function, 256),
                    self._dump_json(args, self.API_ARGS_JSON_LIMIT),
                    self._bounded_text(retval, 1_024),
                    session_id,
                    config.MAX_PERSISTED_EVENTS_PER_TYPE,
                ),
            )
            if cursor.rowcount == 1:
                return True
            self._record_event_drop('api_calls', session_id)
            return False

    def get_api_calls(self, session_id: int) -> list:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT * FROM api_calls WHERE session_id=? ORDER BY id",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Network events (dynamic mode)
    # ------------------------------------------------------------------

    def save_network_event(self, session_id: int, event: dict):
        if not isinstance(event, dict):
            raise TypeError('Network event must be a dictionary')
        data_hex = self._bounded_text(event.get('data_hex', ''), 1_024).lower()
        if not re.fullmatch(r'[0-9a-f]*', data_hex):
            data_hex = ''
        with self._lock, self.conn:
            self._ensure_open()
            cursor = self.conn.execute(
                "INSERT INTO network_events "
                "(session_id, event_type, function, ip, port, data_hex, size, url, headers, timestamp) "
                "SELECT ?,?,?,?,?,?,?,?,?,? WHERE ("
                "SELECT COUNT(*) FROM network_events WHERE session_id=?"
                ") < ?",
                (
                    session_id,
                    self._bounded_text(event.get('event', ''), 128),
                    self._bounded_text(event.get('function', ''), 256),
                    self._bounded_text(event.get('ip', ''), 512),
                    self._bounded_int(event.get('port', 0), 0, 65_535),
                    data_hex,
                    self._bounded_int(event.get('size', 0), 0, 2**31 - 1),
                    self._bounded_text(event.get('url', ''), 4_096),
                    self._bounded_text(event.get('headers', ''), 8_192),
                    self._bounded_int(event.get('timestamp', 0), 0, 2**63 - 1),
                    session_id,
                    config.MAX_PERSISTED_EVENTS_PER_TYPE,
                ),
            )
            if cursor.rowcount == 1:
                return True
            self._record_event_drop('network_events', session_id)
            return False

    def get_network_events(self, session_id: int) -> list:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT * FROM network_events WHERE session_id=? ORDER BY id",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def save_runtime_event(self, session_id: int, event: dict):
        if not isinstance(event, dict):
            raise TypeError('Runtime event must be a dictionary')
        event_type = self._bounded_text(event.get('event'), 128)
        if not event_type:
            raise ValueError('Runtime event requires a non-empty event name')
        with self._lock, self.conn:
            self._ensure_open()
            cursor = self.conn.execute(
                "INSERT INTO runtime_events (session_id, event_type, payload_json) "
                "SELECT ?,?,? WHERE ("
                "SELECT COUNT(*) FROM runtime_events WHERE session_id=?"
                ") < ?",
                (
                    session_id,
                    event_type,
                    self._dump_json(event, 32_768),
                    session_id,
                    config.MAX_PERSISTED_EVENTS_PER_TYPE,
                ),
            )
            if cursor.rowcount == 1:
                return True
            self._record_event_drop('runtime_events', session_id)
            return False

    def get_runtime_events(self, session_id: int) -> list:
        with self._lock:
            self._ensure_open()
            rows = self.conn.execute(
                "SELECT * FROM runtime_events WHERE session_id=? ORDER BY id",
                (session_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Detected patterns
    # ------------------------------------------------------------------

    def save_patterns(self, session_id: int, address: int, patterns: list):
        """Save detected MalwarePattern objects for a function."""
        with self._lock, self.conn:
            self._ensure_open()
            self.conn.execute(
                "DELETE FROM detected_patterns WHERE session_id=? AND address=?",
                (session_id, address),
            )
            for p in list(patterns)[:256]:
                self.conn.execute(
                    "INSERT INTO detected_patterns "
                    "(session_id, address, name, description, severity, evidence) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        session_id,
                        address,
                        self._bounded_text(p.name, 256),
                        self._bounded_text(p.description, 4_096),
                        self._bounded_text(p.severity, 32),
                        self._bounded_text(p.evidence, 4_096),
                    ),
                )

    def get_patterns(self, session_id: int, address: int = None) -> list:
        with self._lock:
            self._ensure_open()
            if address is not None:
                rows = self.conn.execute(
                    "SELECT * FROM detected_patterns WHERE session_id=? AND address=? ORDER BY id",
                    (session_id, address),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM detected_patterns WHERE session_id=? ORDER BY address, id",
                    (session_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------

    def close(self):
        with self._lock:
            if not self._closed:
                self.conn.close()
                self._closed = True

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
