"""Полная проверка знаний с однократным завершающим аудитом истории."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import unquote


HERE = Path(__file__).resolve().parent
PRODUCER = 'knowledge-check-v2'
TOOL_NAMES = ('knowledge-check-v2.py', 'knowledge-index-refresh-v2.py',
              'knowledge-index.py', 'research-workflow.py', 'knowledge-context.py',
              'check-knowledge.py', 'extract-native-enums.py',
              'build-headless-sdk-config.py', 'build-native-entry-code.py')


def load(name):
    spec = importlib.util.spec_from_file_location('_knowledge_check_v2_' + name.replace('-', '_'),
                                                HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tool_snapshot():
    return {str((HERE / name).resolve()): digest(HERE / name) for name in TOOL_NAMES}


def staged_snapshot(workspace):
    def git(*arguments):
        return subprocess.run(['git', *arguments], cwd=workspace, capture_output=True,
                              check=True).stdout
    # Include modes, blob identities and conflict stages, not just changed names.
    return dict(entries=git('ls-files', '--stage', '-z'),
                checked_names=git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'))


def knowledge_snapshot(index, knowledge):
    knowledge = Path(knowledge)
    paths = set(knowledge.rglob('*.md')) | set(knowledge.glob('*.json'))
    facts = set((knowledge / 'releases').glob('*/facts.json'))
    paths |= facts
    exists = {}
    for question in index.read_json(knowledge / 'questions.json')['questions']:
        for name in question.get('evidence', []):
            selected = index.child(knowledge, name)
            exists[str(selected.resolve())] = selected.is_file()
    for path in facts:
        for fact in index.read_json(path)['facts']:
            paths |= {Path(row['path']) for row in fact.get('evidence', [])}
            paths |= {Path(row['report']) for row in fact.get('checks', [])}
    if knowledge == index.KNOWLEDGE:
        links = index.extension('check-knowledge')
        documents = links.documents()
        paths |= set(documents)
        # Match the legacy link check's scope, including targets outside its tree.
        for path in documents:
            for match in links.LINK.finditer(path.read_text('utf-8-sig')):
                target = match.group(1).strip('<>')
                if re.match(r'^(?:https?|app|plugin|mailto|codex|data):', target, re.I):
                    continue
                name = unquote(target.split('#', 1)[0].split('?', 1)[0])
                if name.lower().endswith('.md'):
                    selected = Path(name) if re.match(r'^[A-Za-z]:[/\\]', name) else path.parent / name
                    exists[str(selected.resolve())] = selected.is_file()
    return dict(files={str(path.resolve()): index.digest(path) for path in sorted(paths)},
                exists=exists)


class InputGuard:
    """Endpoint comparisons detect drift; they do not provide an atomic snapshot."""
    def __init__(self, index, knowledge, tools):
        self.index = index
        self.knowledge = knowledge
        self.workspace = index.HERE.parents[3]
        self.tools = tools
        started = time.monotonic()
        self.staged = staged_snapshot(self.workspace)
        self.inputs = knowledge_snapshot(index, knowledge)
        self.duration_seconds = time.monotonic() - started
        self.checks = 0

    def before_publish(self):
        started = time.monotonic()
        try:
            if tool_snapshot() != self.tools:
                raise ValueError('Инструменты проверки изменились во время прохода')
            if knowledge_snapshot(self.index, self.knowledge) != self.inputs:
                raise ValueError('Входы проверки знаний изменились во время прохода')
            if staged_snapshot(self.workspace) != self.staged:
                raise ValueError('Git index изменился во время проверки staged Markdown')
            self.checks += 1
        finally:
            self.duration_seconds += time.monotonic() - started


def validate_report_path(index, args, database, guard):
    report = getattr(args, 'output', None)
    if report is None:
        return
    output = Path(report).resolve()
    knowledge = args.knowledge.resolve()
    inputs = set(guard.inputs['files']) | set(guard.inputs['exists']) | set(guard.tools)
    if output == Path(database).resolve() or any(output == Path(name) for name in inputs):
        raise ValueError('Отчёт проверки не может перезаписать её вход или базу')
    # A newly created report must not itself change a checked input inventory.
    if (output.suffix.lower() in ('.py', '.md') or
            (output.parent == knowledge and output.suffix.lower() == '.json') or
            (output.name == 'facts.json' and output.parent.parent == knowledge / 'releases') or
            any(output.is_relative_to(args.root.resolve() / name)
                for name in ('client-code-snapshots', 'ghidra'))):
        raise ValueError('Отчёт проверки находится в области входных материалов')


def check(index, args, database, *, tools=None):
    """Run unchanged workflow checks with a private build adapter and supplied API."""
    started = time.monotonic()
    tools = tool_snapshot() if tools is None else tools
    workflow = load('research-workflow')
    builder = load('knowledge-index-refresh-v2')
    guard = InputGuard(index, args.knowledge, tools)
    validate_report_path(index, args, database, guard)
    builds = []

    def build(root, output, on_progress=None, knowledge=None):
        result = builder.build(index, root, output, on_progress=on_progress,
                               knowledge=knowledge, before_publish=guard.before_publish)
        if result.get('full_history_verified') is not True:
            raise ValueError('Builder не подтвердил полный завершающий аудит истории')
        builds.append(result)
        return result

    private_index = SimpleNamespace(**vars(index))
    private_index.build = build
    result = workflow.check(private_index, args, database)
    if len(builds) != 1 or guard.checks != 1:
        raise ValueError('Нарушен порядок единственной сборки и барьера публикации')
    result.update(producer=dict(id=PRODUCER, version=2,
                                sha256=tools[str(Path(__file__).resolve())]),
                  full_history_verified=True, index_build=builds[0],
                  metrics=dict(duration_seconds=time.monotonic() - started,
                               input_guard_seconds=guard.duration_seconds,
                               guarded_files=len(guard.inputs['files']),
                               staged_index_entries=len(guard.staged['entries'].split(b'\0')) - 1),
                  proves_client_compatibility=False, runtime_admitted=False,
                  stable_inputs='Full input hashes and Git index identities compared at endpoints; '
                                'no atomic filesystem snapshot or protection against change-and-restore.')
    return result


def run(args):
    started = time.monotonic()
    # Capture tools before loading them; no frozen module globals are modified.
    tools = tool_snapshot()
    legacy = load('knowledge-index')
    database = args.database or args.root / 'knowledge/search.sqlite3'
    result = check(legacy.api(), args, database, tools=tools)
    result['metrics']['duration_seconds'] = time.monotonic() - started
    return result


def write_report(path, result):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='knowledge-check-v2-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write('\n')
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path,
                        default=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES',
                                                    'F:/PhoneExit Resources/Vampir')))
    parser.add_argument('--database', type=Path)
    parser.add_argument('--knowledge', type=Path, default=HERE / 'knowledge')
    parser.add_argument('--output', type=Path, help='Дополнительный JSON-отчёт вне входных материалов')
    args = parser.parse_args(argv)
    result = run(args)
    if args.output is not None:
        write_report(args.output, result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
