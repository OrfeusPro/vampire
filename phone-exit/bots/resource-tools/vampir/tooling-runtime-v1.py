"""Полные входы установленного Python и runtime групповых fixture-проверок."""
import hashlib
import importlib.metadata
import importlib.util
import locale
import os
from pathlib import Path
import platform
import sys
import sysconfig


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(workspace):
    local = Path(workspace) / 'phone-exit/.tools/vampir-analysis'
    files = {Path(sys.executable).resolve()}
    stdlib = Path(sysconfig.get_path('stdlib'))
    excluded = {'site-packages', '__pycache__', 'test', 'tests', 'idlelib', 'tkinter'}
    for folder, directories, names in os.walk(stdlib):
        directories[:] = [name for name in directories if name not in excluded]
        files.update(Path(folder) / name for name in names if name.endswith('.py'))
    for folder in {Path(sys.executable).resolve().parent, Path(sys.base_prefix)}:
        files.update(folder.glob('python*.dll'))
        files.update((folder / 'DLLs').glob('*.pyd'))
        files.update((folder / 'DLLs').glob('*.dll'))
    distributions = {}
    for name in ('capstone', 'unicorn', 'cryptography'):
        if name == 'cryptography':
            selected = [importlib.metadata.distribution(name)]
        else:
            selected = [item for item in importlib.metadata.distributions(path=[str(local)])
                        if str(item.metadata['Name']).lower() == name]
        if len(selected) != 1:
            raise ValueError('Missing or ambiguous tooling runtime: ' + name)
        distribution = selected[0]
        if distribution.files is None:
            raise ValueError('Runtime lacks a complete file inventory: ' + name)
        package_files = set()
        for entry in distribution.files:
            if '__pycache__' in entry.parts or entry.suffix.lower() in ('.pyc', '.pyo'):
                continue
            path = Path(distribution.locate_file(entry)).resolve()
            if not path.is_file():
                raise ValueError('Runtime file missing: ' + str(path))
            files.add(path)
            package_files.add(str(path))
        package = Path(distribution.locate_file(name))
        for path in package.rglob('*'):
            if (path.is_file() and '__pycache__' not in path.parts
                    and path.suffix.lower() not in ('.pyc', '.pyo')):
                resolved = path.resolve()
                files.add(resolved)
                package_files.add(str(resolved))
        if name == 'cryptography':
            origin = importlib.util.find_spec(name)
            expected = Path(distribution.locate_file(name + '/__init__.py')).resolve()
            if origin is None or Path(origin.origin).resolve() != expected:
                raise ValueError('Cryptography distribution differs from the import target')
        distributions[name] = dict(version=distribution.version, files=sorted(package_files))
    environment = {}
    for name in ('PATH', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONHASHSEED', 'PYTHONUTF8',
                 'PYTHONIOENCODING', 'SystemRoot', 'TEMP', 'TMP', 'TZ', 'LANG', 'LC_ALL'):
        value = os.environ.get(name)
        environment[name] = None if value is None else hashlib.sha256(value.encode('utf-8')).hexdigest()
    return dict(python_version=platform.python_version(), implementation=platform.python_implementation(),
                executable=str(Path(sys.executable).resolve()), platform=platform.platform(),
                locale=locale.setlocale(locale.LC_ALL), distributions=distributions,
                environment_sha256=environment,
                files={str(path.resolve()): digest(path) for path in sorted(files)})
