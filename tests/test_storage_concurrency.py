import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from types import SimpleNamespace

import pytest

import config
from storage import TraceStore


def make_binary():
    return SimpleNamespace(
        path='/tmp/sample',
        filename='sample.exe',
        sha256='a' * 64,
        arch='x86-64',
        bits=64,
        os_target='Linux',
    )


def create_legacy_database(db_path):
    connection = sqlite3.connect(db_path)
    connection.executescript("""
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_path TEXT NOT NULL,
            filename TEXT NOT NULL, sha256 TEXT, arch TEXT, bits INTEGER,
            os_target TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE function_traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL,
            address INTEGER NOT NULL, name TEXT, disassembly TEXT, calls_to TEXT,
            called_from TEXT, strings_referenced TEXT, instruction_count INTEGER,
            snapshot_json TEXT, ai_analysis_json TEXT, risk_level TEXT,
            mitre_technique TEXT, analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(session_id, address)
        );
        PRAGMA user_version=1;
    """)
    connection.close()


@pytest.mark.parametrize('legacy', [False, True], ids=['new', 'legacy'])
def test_concurrent_database_open_serializes_schema_setup(tmp_path, legacy):
    db_path = tmp_path / 'traces.db'
    if legacy:
        create_legacy_database(db_path)

    worker_count = 8
    barrier = threading.Barrier(worker_count)

    def inspect_schema():
        barrier.wait(timeout=10)
        with TraceStore(db_path) as store:
            columns = {
                row['name']
                for row in store.conn.execute('PRAGMA table_info(function_traces)')
            }
            session_columns = {
                row['name'] for row in store.conn.execute('PRAGMA table_info(sessions)')
            }
            version = store.conn.execute('PRAGMA user_version').fetchone()[0]
            runtime_table = store.conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='runtime_events'"
            ).fetchone()
            return (
                version,
                'analysis_cache_key' in columns,
                {
                    'decompiled_code', 'decompile_language',
                    'decompile_backend', 'decompile_warning'
                } <= columns,
                {'file_format', 'analysis_origin', 'compiled_sha256'} <= session_columns,
                runtime_table is not None,
            )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(inspect_schema) for _ in range(worker_count)]
        results = [future.result(timeout=20) for future in futures]

    assert results == [(6, True, True, True, True)] * worker_count


def save_event(store, event_kind, session_id, sequence):
    if event_kind == 'api_calls':
        return store.save_api_call(session_id, 'sample', 'call', [sequence], str(sequence))
    if event_kind == 'network_events':
        return store.save_network_event(
            session_id,
            {'event': 'send', 'function': 'send', 'size': sequence},
        )
    return store.save_runtime_event(
        session_id,
        {'event': 'transition', 'sequence': sequence},
    )


@pytest.mark.parametrize('event_kind', ['api_calls', 'network_events', 'runtime_events'])
def test_event_cap_is_authoritative_across_open_connections(tmp_path, monkeypatch, event_kind):
    monkeypatch.setattr(config, 'MAX_PERSISTED_EVENTS_PER_TYPE', 2)
    db_path = tmp_path / 'events.db'

    with TraceStore(db_path) as first, TraceStore(db_path) as second:
        session_id = first.create_session(make_binary())
        assert save_event(first, event_kind, session_id, 1) is True
        assert save_event(second, event_kind, session_id, 2) is True
        with pytest.warns(RuntimeWarning, match='per-session limit'):
            assert save_event(first, event_kind, session_id, 3) is False

        count = first.conn.execute(
            f'SELECT COUNT(*) FROM {event_kind} WHERE session_id=?',
            (session_id,),
        ).fetchone()[0]
        assert count == 2
        assert first.get_dropped_event_counts(session_id) == {event_kind: 1}


@pytest.mark.parametrize('event_kind', ['api_calls', 'network_events', 'runtime_events'])
def test_event_cap_remains_atomic_during_simultaneous_writes(
    tmp_path, monkeypatch, event_kind
):
    limit = 3
    worker_count = 8
    monkeypatch.setattr(config, 'MAX_PERSISTED_EVENTS_PER_TYPE', limit)
    monkeypatch.setattr('storage.trace_store.warnings.warn', lambda *args, **kwargs: None)
    db_path = tmp_path / 'simultaneous.db'

    with ExitStack() as stack:
        stores = [stack.enter_context(TraceStore(db_path)) for _ in range(worker_count)]
        session_id = stores[0].create_session(make_binary())
        barrier = threading.Barrier(worker_count)

        def write(index):
            barrier.wait(timeout=10)
            return save_event(stores[index], event_kind, session_id, index)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(write, range(worker_count)))

        count = stores[0].conn.execute(
            f'SELECT COUNT(*) FROM {event_kind} WHERE session_id=?',
            (session_id,),
        ).fetchone()[0]

    assert results.count(True) == limit
    assert results.count(False) == worker_count - limit
    assert count == limit


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permission bits are required')
def test_existing_database_permissions_are_tightened(tmp_path):
    db_path = tmp_path / 'existing.db'
    connection = sqlite3.connect(db_path)
    connection.execute('PRAGMA user_version=1')
    connection.close()
    os.chmod(db_path, 0o666)

    with TraceStore(db_path):
        assert db_path.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(
    not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'fchmod'),
    reason='File-descriptor permission hardening is unavailable',
)
def test_permission_hardening_failure_does_not_block_database_open(tmp_path, monkeypatch):
    db_path = tmp_path / 'readonly-metadata.db'
    sqlite3.connect(db_path).close()

    def deny_fchmod(_fd, _mode):
        raise PermissionError('permission changes are unavailable')

    monkeypatch.setattr(os, 'fchmod', deny_fchmod)
    with TraceStore(db_path) as store:
        session_id = store.create_session(make_binary())
        assert store.get_session(session_id)['filename'] == 'sample.exe'
