"""Refresh the frozen knowledge index with one final history verification.

Inputs must remain stable during the operation, as in the original builder.
This adapter does not cache digests or claim an atomic snapshot of the inputs.
Only a private database is modified before the publication guards succeed.
"""
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time


PRODUCER = 'knowledge-index-refresh-v2'
_SIDECARS = ('-wal', '-shm', '-journal')


def _plain_destination(output):
    """Reject redirected destinations, including existing parent reparse points."""
    for path in (output, *output.parents):
        try:
            value = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(value.st_mode)
                or getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('Index destination is a symlink or reparse point: ' + str(path))
    for suffix in _SIDECARS:
        if os.path.lexists(str(output) + suffix):
            raise ValueError('Index destination has SQLite sidecar: ' + str(output) + suffix)


def _identity(index, output):
    _plain_destination(output)
    try:
        before = output.stat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('Index destination must be a regular file without hard-link aliases')
    value = index.digest(output)
    after = output.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError('Index destination changed during refresh')
    _plain_destination(output)
    return before.st_dev, before.st_ino, value


def _destination_guard(index, output, expected):
    if _identity(index, output) != expected:
        raise ValueError('Index destination changed during refresh')


def _inputs_guard(index, context, root, knowledge, expected_context, reports, tools,
                  unfinished_receipts=()):
    if context.inventory(index, root, knowledge) != expected_context:
        raise ValueError('Knowledge inputs changed during refresh')
    if ({str(path) for path in index.discover(root)} != reports
            or index.tool_inputs() != tools
            or any(Path(path).is_file() for path in unfinished_receipts)):
        raise ValueError('Index inputs changed during refresh')


def _hash_scope(db):
    """Count the full, non-memoized digest calls made by frozen verify_index."""
    return dict(
        artifacts=db.execute('SELECT count(*) FROM artifacts').fetchone()[0],
        receipt_references=db.execute('''SELECT count(*) FROM artifacts
            WHERE receipt IS NOT NULL AND receipt != '' ''').fetchone()[0],
        pseudocode_pairs=db.execute('''SELECT count(*) FROM (
            SELECT DISTINCT o.pseudocode,v.pseudocode_sha FROM observations o
            JOIN variants v ON o.variant=v.id WHERE o.pseudocode IS NOT NULL)''').fetchone()[0],
        releases=db.execute('SELECT count(*) FROM releases').fetchone()[0])


def _verify(index, db, metrics):
    scope = _hash_scope(db)
    started = time.perf_counter()
    index.verify_index(db, include_context=False)
    metrics['history_verification_passes'] += 1
    metrics['history_hash_scope'] = scope
    metrics['expected_history_digest_calls'] = sum(scope.values())
    metrics['durations']['history_verification_seconds'] = time.perf_counter() - started


def _result(value, output, metrics, started):
    metrics['durations']['total_seconds'] = time.perf_counter() - started
    return dict(value, database=str(output), producer=PRODUCER,
                full_history_verified=True, metrics=metrics)


def build(index, root, output, on_progress=None, knowledge=None, *, before_publish=None):
    """Build or refresh using a fresh private frozen module/API supplied by caller.

    ``before_publish`` is an optional read-only external-input validation barrier.
    It runs after the complete history check, before the destination guard and
    publication (also on an unchanged return). No SHA result is memoized here.
    """
    started = time.perf_counter()
    root = Path(root)
    output = Path(os.path.abspath(output))
    knowledge = Path(knowledge) if knowledge is not None else index.KNOWLEDGE
    _plain_destination(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    destination = _identity(index, output)
    context = index.extension('knowledge-context')
    inventory_started = time.perf_counter()
    context_inputs = context.inventory(index, root, knowledge)
    tools = index.tool_inputs()
    reports = {str(path) for path in index.discover(root)}
    metrics = dict(mode=None, history_verification_passes=0,
                   digest_memoization=False, history_hash_scope={},
                   expected_history_digest_calls=0,
                   durations=dict(initial_inventory_seconds=time.perf_counter() - inventory_started))
    previous = None
    try:
        if destination is not None:
            previous = index.open_index(output)
            builder = previous.execute("SELECT value FROM metadata WHERE key='tool_inputs'").fetchone()
            old_reports = {row['path'] for row in previous.execute('SELECT path FROM artifacts')}
            unfinished_receipts = {str(index.receipt_for(Path(row['path'])))
                                   for row in previous.execute('SELECT path,receipt FROM artifacts')
                                   if not row['receipt']}
            newly_finished = any(Path(path).is_file() for path in unfinished_receipts)
            version = previous.execute('PRAGMA user_version').fetchone()[0]
            old_context = ({row['path']: row['sha'] for row in previous.execute('SELECT * FROM context_inputs')}
                           if version == 2 else None)
            eligible = (version == 2 and builder and json.loads(builder['value']) == tools
                        and old_reports <= reports and not newly_finished)
            if eligible and old_reports == reports and old_context == context_inputs:
                metrics['mode'] = 'reused'
                _verify(index, previous, metrics)
                _inputs_guard(index, context, root, knowledge, context_inputs, reports, tools,
                              unfinished_receipts)
                counts = index.index_counts(previous)
                previous.close()
                previous = None
                if before_publish:
                    before_publish()
                _destination_guard(index, output, destination)
                return _result(dict(counts=counts, reused=True, roles_transferred=False,
                                    game_or_ghidra_started=False), output, metrics, started)
        else:
            eligible = False

        with tempfile.TemporaryDirectory(prefix='knowledge-refresh-v2-', dir=output.parent) as folder:
            temporary = Path(folder) / 'search.sqlite3'
            if eligible:
                metrics['mode'] = 'incremental'
                revised = sqlite3.connect(temporary)
                revised.row_factory = sqlite3.Row
                try:
                    previous.backup(revised)
                    previous.close()
                    previous = None
                    added = sorted(reports - old_reports)
                    if added:
                        sources = index.Sources(root)
                        for number, name in enumerate(added, 1):
                            try:
                                index.import_report(revised, sources, Path(name))
                            except (ValueError, OSError, KeyError, TypeError) as error:
                                raise ValueError(f'Export rejected: {name}: {error}') from error
                            if on_progress:
                                on_progress(number, len(added))
                    if old_context != context_inputs:
                        revised.execute('DELETE FROM search WHERE variant IN (SELECT id FROM context)')
                        revised.executescript('DROP TABLE context; DROP TABLE context_inputs;')
                        context.import_context(index, revised, root, knowledge, context_inputs)
                    # The inherited history is still untrusted until this final,
                    # complete pass. No private database is published before it.
                    _verify(index, revised, metrics)
                    _inputs_guard(index, context, root, knowledge, context_inputs, reports, tools,
                                  unfinished_receipts)
                    revised.commit()
                    if revised.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        raise ValueError('Index integrity failed')
                    value = dict(counts=index.index_counts(revised), reused=False,
                                 code_reused=True, imported_reports=len(added),
                                 roles_transferred=False, game_or_ghidra_started=False)
                finally:
                    revised.close()
            else:
                metrics['mode'] = 'rebuild'
                if previous is not None:
                    previous.close()
                    previous = None
                # The old builder receives a nonexistent, private destination;
                # its internal replace can never publish the canonical database.
                value = index.build(root, temporary, on_progress=on_progress, knowledge=knowledge)
                revised = index.open_index(temporary)
                try:
                    _verify(index, revised, metrics)
                    _inputs_guard(index, context, root, knowledge, context_inputs, reports, tools)
                finally:
                    revised.close()
            if before_publish:
                before_publish()
            _destination_guard(index, output, destination)
            _plain_destination(temporary)
            temporary.replace(output)
            return _result(value, output, metrics, started)
    finally:
        if previous is not None:
            previous.close()
