"""Validate relocated evidence, topic inventories and local Markdown document links."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
BOTS = HERE.parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\((<[^>\n]+>|[^)\n]+)\)')


def documents():
    return sorted(set(HERE.rglob('*.md')) | set((BOTS / 'vampir').rglob('*.md')) |
                  set((BOTS / 'vampir-headless').rglob('*.md')) |
                  set((BOTS / 'vampir-shared').rglob('*.md')))


def build_topic_lists():
    location = json.loads((HERE / 'knowledge/document-locations.json').read_text('utf-8'))
    workspace = HERE.parents[3]
    groups = {}
    for row in location['documents']:
        if row['topic'] == 'history':
            continue
        target = workspace / row['current']
        if not target.is_file() or (workspace / row['old']).exists():
            raise ValueError('Migration source/destination invariant failed')
        groups.setdefault(row['topic'], []).append(target)
    for topic, paths in groups.items():
        page = HERE / 'knowledge/topics' / (topic + '.md')
        if not page.is_file():
            raise ValueError('Topic summary missing: ' + topic)
        marker = '<!-- evidence-inventory -->'
        text = page.read_text('utf-8').split(marker)[0].rstrip()
        lines = ['', '', marker, '## Подробные разборы', '',
                 'Это источники и история проверок; наличие документа не означает завершённую live-функцию.', '']
        for target in sorted(paths):
            title = target.read_text('utf-8-sig').splitlines()[0].lstrip('# ').strip()
            title = title.replace('[', '(').replace(']', ')')
            lines.append(f'- [{title}](../evidence/{topic}/{target.name})')
        page.write_text(text + '\n'.join(lines) + '\n', encoding='utf-8')
    return {topic: len(paths) for topic, paths in sorted(groups.items())}


def check():
    broken = []
    checked = 0
    for path in documents():
        for number, line in enumerate(path.read_text('utf-8-sig').splitlines(), 1):
            for match in LINK.finditer(line):
                target = match.group(1).strip('<>')
                if re.match(r'^(?:https?|app|plugin|mailto|codex|data):', target, re.I):
                    continue
                name = unquote(target.split('#', 1)[0].split('?', 1)[0])
                if not name.lower().endswith('.md'):
                    continue
                resolved = Path(name) if re.match(r'^[A-Za-z]:[/\\]', name) else path.parent / name
                checked += 1
                if not resolved.is_file():
                    broken.append(dict(path=str(path), line=number, target=target))
    return dict(documents=len(documents()), markdown_links_checked=checked, broken=broken)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-topic-lists', action='store_true')
    args = parser.parse_args()
    if args.build_topic_lists:
        print(json.dumps(dict(topics=build_topic_lists())))
    result = check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(1 if result['broken'] else 0)
