"""Offline SQLite snapshots; credentials stay protected by the original Windows user."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
DATABASES = ('console.sqlite3', 'accounts.sqlite3')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_database(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Повреждена база: ' + path.name)


def verify(folder):
    folder = Path(folder).resolve()
    manifest = json.loads((folder / 'manifest.json').read_text('utf-8'))
    if (manifest.get('schema') != 1 or manifest.get('credential_protection') != 'Windows DPAPI CurrentUser'
            or type(manifest.get('databases')) is not list or not manifest['databases']):
        raise ValueError('Неподдерживаемый manifest резервной копии')
    names = [row['name'] for row in manifest['databases']]
    if len(names) != len(set(names)) or set(names) - set(DATABASES):
        raise ValueError('Неверный состав резервной копии')
    for row in manifest['databases']:
        path = folder / row['name']
        if path.is_symlink() or path.stat().st_size != row['size'] or digest(path) != row['sha256']:
            raise ValueError('SHA или размер резервной копии изменился: ' + row['name'])
        check_database(path)
    return manifest


def create(local, destination, *, timeout=15):
    """Never overwrite sources or prior snapshots; backup() includes committed WAL data.

    Each database is individually consistent. Stop workers for an application-wide
    restore point: separate SQLite databases have no shared transaction.
    """
    local, destination = Path(local).resolve(), Path(destination).resolve()
    if destination == local or local in destination.parents:
        raise ValueError('Резервную копию нужно хранить вне .local')
    sources = [local / name for name in DATABASES if (local / name).is_file()]
    if not sources or not (local / 'console.sqlite3').is_file():
        raise ValueError('Не найдена существующая console.sqlite3')
    if any(path.is_symlink() for path in sources):
        raise ValueError('Символические ссылки баз не поддерживаются')
    destination.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.incomplete-', dir=destination))
    try:
        rows = []
        for source in sources:
            target = temporary / source.name
            deadline = time.monotonic() + timeout

            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise TimeoutError('Истёк срок создания SQLite snapshot')

            with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
                with closing(sqlite3.connect(target)) as output:
                    db.backup(output, pages=256, progress=progress, sleep=0.05)
            check_database(target)
            rows.append(dict(name=source.name, size=target.stat().st_size, sha256=digest(target)))
        manifest = dict(schema=1, created_utc=datetime.now(timezone.utc).isoformat(),
            credential_protection='Windows DPAPI CurrentUser', databases=rows,
            missing_databases=[name for name in DATABASES if name not in {p.name for p in sources}],
            consistency='per_database', portable_credentials=False,
            includes_research_resources=False, network_used=False)
        (temporary / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', 'utf-8')
        verify(temporary)
        final = destination / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12])
        temporary.rename(final)
        return final
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('create')
    make.add_argument('--local', type=Path, default=HERE / '.local')
    make.add_argument('--destination', type=Path, required=True)
    check = commands.add_parser('verify')
    check.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'create':
        path = create(args.local, args.destination)
        print(json.dumps(dict(backup=str(path), verified=True, portable_credentials=False)))
    else:
        report = verify(args.backup)
        print(json.dumps(dict(verified=True, databases=len(report['databases']), portable_credentials=False)))
