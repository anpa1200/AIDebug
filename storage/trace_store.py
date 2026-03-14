"""
SQLite-backed persistent store for analysis sessions, function traces, and API calls.
"""
import sqlite3
import json
import os
from typing import Optional


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
    FOREIGN KEY (session_id) REFERENCES sessions(id),
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
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_traces_session  ON function_traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_risk     ON function_traces(risk_level);
CREATE INDEX IF NOT EXISTS idx_api_session     ON api_calls(session_id);
"""


class TraceStore:

    def __init__(self, db_path: str):
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(self, binary_info) -> int:
        cur = self.conn.execute(
            "INSERT INTO sessions (binary_path, filename, sha256, arch, bits, os_target) "
            "VALUES (?,?,?,?,?,?)",
            (binary_info.path, binary_info.filename, binary_info.sha256,
             binary_info.arch, binary_info.bits, binary_info.os_target),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_sessions(self) -> list:
        rows = self.conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Function traces
    # ------------------------------------------------------------------

    def save_function_analysis(self, session_id: int, function, analysis, snapshot=None):
        snap_json = json.dumps({
            'entry_registers': snapshot.entry_registers if snapshot else {},
            'exit_registers':  snapshot.exit_registers  if snapshot else {},
            'return_value':    snapshot.return_value     if snapshot else 0,
        })
        ai_json = json.dumps({
            'suggested_name':  analysis.suggested_name,
            'summary':         analysis.summary,
            'parameters':      analysis.parameters,
            'return_value':    analysis.return_value,
            'behaviors':       analysis.behaviors,
            'mitre_technique': analysis.mitre_technique,
            'risk_level':      analysis.risk_level,
            'notes':           analysis.notes,
        })
        self.conn.execute("""
            INSERT INTO function_traces
                (session_id, address, name, disassembly, calls_to, called_from,
                 strings_referenced, instruction_count, snapshot_json,
                 ai_analysis_json, risk_level, mitre_technique)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(session_id, address) DO UPDATE SET
                name=excluded.name,
                ai_analysis_json=excluded.ai_analysis_json,
                risk_level=excluded.risk_level,
                mitre_technique=excluded.mitre_technique,
                analyzed_at=CURRENT_TIMESTAMP
        """, (
            session_id,
            function.address,
            analysis.suggested_name,
            function.disassembly_text[:8000],
            json.dumps(function.calls_to),
            json.dumps(function.called_from),
            json.dumps(function.strings_referenced),
            len(function.instructions),
            snap_json,
            ai_json,
            analysis.risk_level,
            analysis.mitre_technique,
        ))
        self.conn.commit()

    def get_cached_analysis(self, session_id: int, address: int):
        """Return a cached AIAnalysis for this function, or None."""
        row = self.conn.execute(
            "SELECT ai_analysis_json FROM function_traces "
            "WHERE session_id=? AND address=? AND ai_analysis_json IS NOT NULL",
            (session_id, address),
        ).fetchone()
        if not row:
            return None
        from analysis.ai_analyzer import AIAnalysis
        data = json.loads(row['ai_analysis_json'])
        return AIAnalysis(**data)

    def get_all_traces(self, session_id: int) -> list:
        rows = self.conn.execute(
            "SELECT * FROM function_traces WHERE session_id=? "
            "ORDER BY CASE risk_level "
            "  WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "  WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END, address",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_risk_summary(self, session_id: int) -> dict:
        rows = self.conn.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM function_traces "
            "WHERE session_id=? GROUP BY risk_level",
            (session_id,),
        ).fetchall()
        return {r['risk_level']: r['cnt'] for r in rows}

    def search(self, session_id: int, query: str) -> list:
        q = f'%{query}%'
        rows = self.conn.execute("""
            SELECT * FROM function_traces
            WHERE session_id=? AND (
                name LIKE ? OR strings_referenced LIKE ? OR ai_analysis_json LIKE ?
            )
            ORDER BY CASE risk_level
              WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
              WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END
        """, (session_id, q, q, q)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # API call log (dynamic mode)
    # ------------------------------------------------------------------

    def save_api_call(self, session_id: int, module: str, function: str,
                      args: list, retval: str):
        self.conn.execute(
            "INSERT INTO api_calls (session_id, module, function, args_json, retval) "
            "VALUES (?,?,?,?,?)",
            (session_id, module, function, json.dumps(args), retval),
        )
        self.conn.commit()

    def get_api_calls(self, session_id: int) -> list:
        rows = self.conn.execute(
            "SELECT * FROM api_calls WHERE session_id=? ORDER BY id",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------

    def close(self):
        self.conn.close()
