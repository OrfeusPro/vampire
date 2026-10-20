"""One explicit documentation migration with link rebasing and an audited map."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
KNOWLEDGE = HERE / 'knowledge'
MAP = KNOWLEDGE / 'document-locations.json'
LINK = re.compile(r'(!?\[[^\]\n]*\]\()(<[^>\n]+>|[^)\n]+)(\))')


def topic(name):
    stem = name.removesuffix('.md').removeprefix('HEADLESS-')
    if stem.startswith(('GHIDRA', 'DUMPER')):
        return 'tools'
    if stem.startswith(('PATCH-', 'CLIENT-RELEASE', 'CDN-', 'GMC2-', 'PUBLIC-', 'PAK-CONFIG', 'CONFIG-STARTUP', 'MODULE-DESCRIPTORS')):
        return 'updates'
    if stem.startswith(('CHARACTER-', 'SELECTION-', 'SELECTED-PLAYER', 'WAITING-END', 'WORLD-')):
        return 'characters'
    if stem.startswith(('AUTH', 'NID-', 'SDK-', 'DEVICE-', 'CHANNEL-', 'SILENT-', 'GAME-AUTO', 'GAME-PGS', 'GAME-SUCCESS', 'TITLE-AUTH')):
        return 'auth'
    if stem == 'MAP-ATLAS':
        return 'maps'
    if stem.startswith(('UI-', 'ENTRY-', 'NATIVE-ENTRY', 'NATIVE-UI', 'FADER-', 'MESSAGE-', 'SYSTEM-MESSAGE')):
        return 'interface'
    if stem.startswith(('QUEST-', 'CONDITION-', 'CONTENTS-', 'UNLOCK-', 'RUNTIME-CHAIN', 'SHOP-', 'REWARDS-', 'PACKET-RESULT')):
        return 'scenarios'
    if stem in ('ATTRIBUTES', 'COLLECTIONS', 'NPC-LOOT', 'CATALOG-STRUCTURE', 'NATIVE-SEMANTICS'):
        return 'game-data'
    if name.startswith('HEADLESS-'):
        return 'network'
    if stem == 'CODE-CLUES':
        return 'tools'
    raise ValueError('Needs explicit topic: ' + name)


def plan():
    kept = {'README.md', 'RESOURCE-INDEX.md', 'ANALYSIS-TOOLS.md'}
    mapping = {p.resolve(): (KNOWLEDGE / 'evidence' / topic(p.name) / p.name).resolve()
               for p in HERE.glob('*.md') if p.name not in kept}
    bots = HERE.parents[1]
    archives = {
        bots / 'vampir/README.md': bots / 'vampir/RESEARCH-HISTORY.md',
        bots / 'vampir/FUNCTION-INDEX.md': bots / 'vampir/FUNCTION-HISTORY.md',
        bots / 'vampir-headless/README.md': bots / 'vampir-headless/RESEARCH-HISTORY.md',
        bots / 'vampir-headless/TASKS.md': bots / 'vampir-headless/TASKS-HISTORY.md',
        HERE / 'RESOURCE-INDEX.md': HERE / 'RESOURCE-HISTORY.md',
        HERE / 'README.md': HERE / 'RESEARCH-HISTORY.md',
    }
    return mapping, {p.resolve(): q.resolve() for p, q in archives.items()}


def rebase(text, old, new, mapping, archives):
    def replace(match):
        raw = match.group(2)
        angled = raw.startswith('<') and raw.endswith('>')
        target = raw[1:-1] if angled else raw
        if re.match(r'^(?:https?|app|plugin|mailto|codex|data):', target, re.I):
            return match.group(0)
        path, marker, fragment = target.partition('#')
        if not path:
            return match.group(0)
        if '?' in path or ' "' in path or " '" in path:
            return match.group(0)  # Do not reinterpret titles or dynamic URLs.
        absolute = bool(re.match(r'^[A-Za-z]:[/\\]', path))
        original = Path(unquote(path)) if absolute else old.parent / unquote(path)
        original = original.resolve()
        destination = archives.get(original, original) if marker else original
        destination = mapping.get(destination, destination)
        if absolute:
            revised = destination.as_posix()
        else:
            revised = Path(os.path.relpath(destination, new.parent)).as_posix()
        if marker:
            revised += '#' + fragment
        if angled or ' ' in revised:
            revised = '<' + revised + '>'
        return match.group(1) + revised + match.group(3)
    return LINK.sub(replace, text)


def apply():
    if MAP.exists():
        raise ValueError('Migration already recorded; refusing a second move')
    mapping, archives = plan()
    for old, new in {**mapping, **archives}.items():
        if not old.is_relative_to(WORKSPACE.resolve()) or not new.is_relative_to(WORKSPACE.resolve()):
            raise ValueError('Move outside workspace')
        if not old.is_file() or new.exists():
            raise ValueError('Missing source or existing destination: ' + str(old))
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=WORKSPACE).decode('utf-8').split('\0')
    files = {WORKSPACE / name for name in names if name.endswith('.md')}
    files.update(KNOWLEDGE.rglob('*.md'))
    updates = {}
    records = []
    for path in sorted(files):
        if not path.is_file():
            continue
        old = path.resolve()
        new = mapping.get(old, archives.get(old, old))
        text = path.read_text('utf-8-sig')
        revised = rebase(text, old, new, mapping, archives)
        if new != old or revised != text:
            updates[new] = revised
        if old in mapping or old in archives:
            records.append(dict(old=old.relative_to(WORKSPACE).as_posix(),
                current=new.relative_to(WORKSPACE).as_posix(),
                topic=topic(old.name) if old in mapping else 'history',
                old_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    # Compute all edits before mutating any path. No recursive moves or deletes.
    for old, new in mapping.items():
        new.parent.mkdir(parents=True, exist_ok=True)
        old.rename(new)
    for old, new in archives.items():
        old.rename(new)
    for path, text in updates.items():
        path.write_text(text, encoding='utf-8')
    for filename, key in (('function-roles.json', 'roles'), ('questions.json', 'questions')):
        path = KNOWLEDGE / filename
        data = json.loads(path.read_text('utf-8'))
        if key == 'roles':
            for row in data[key].values():
                target = (HERE / row['evidence']).resolve()
                row['evidence'] = Path(os.path.relpath(mapping.get(target, target), HERE)).as_posix()
        else:
            for row in data[key]:
                row['evidence'] = [Path(os.path.relpath(mapping.get((KNOWLEDGE / p).resolve(), (KNOWLEDGE / p).resolve()), KNOWLEDGE)).as_posix()
                                   for p in row['evidence']]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=WORKSPACE, text=True).strip()
    MAP.write_text(json.dumps(dict(version=1, source_commit=source_commit, documents=records), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(moved=len(mapping), archived=len(archives), rewritten_markdown=len(updates))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.apply:
        apply()
    elif MAP.exists():
        records = json.loads(MAP.read_text('utf-8'))['documents']
        print(json.dumps(dict(already_applied=True, documents=len(records), map=str(MAP))))
    else:
        mapping, archives = plan()
        print(json.dumps(dict(documents=len(mapping), archives=len(archives),
            topics={name: sum(p.parent.name == name for p in mapping.values()) for name in sorted({p.parent.name for p in mapping.values()})})))
