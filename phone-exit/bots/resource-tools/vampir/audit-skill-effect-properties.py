"""Inventory every static Skill/Effect field before defining UI application rules."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

KINDS = ('Skill', 'SkillOperation', 'Effect', 'EffectOperation')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def profile(nodes):
    properties = {}
    for key, node in nodes.items():
        if node['kind'] not in KINDS:
            continue
        for field, value in node['fields'].items():
            if field == 'provenance':
                continue
            if not isinstance(value, str):
                raise ValueError('Статическое поле должно сохранять исходную CSV строку')
            identity = 'UI-23.K-' + hashlib.sha256((node['kind'] + '.' + field).encode()).hexdigest()[:12]
            prop = properties.setdefault(identity, dict(id=identity, owner=node['kind'], field=field,
                observations=0, blank=0, explicit_zero=0, values={}, occurrences=[],
                review='not_reviewed', unit=None, default=None, runtime_application_verified=False))
            prop['observations'] += 1
            prop['blank'] += value == ''
            prop['explicit_zero'] += value == '0'
            prop['values'][value] = prop['values'].get(value, 0) + 1
            prop['occurrences'].append(dict(node=key, field=field, provenance=node['fields']['provenance']))
    findings = []
    for key, node in nodes.items():
        if node['kind'] != 'Effect':
            continue
        row = node['fields']; values = [row.get(f, '') for f in ('Duration', 'MinDuration', 'MaxDuration')]
        if all(v.isascii() and v.isdecimal() for v in values):
            duration, low, high = map(int, values)
            if not low <= duration <= high:
                findings.append(dict(node=key, fields=dict(zip(('Duration', 'MinDuration', 'MaxDuration'), values)),
                    provenance=row['provenance'], status='numeric_comparison_not_runtime_error',
                    actual_duration=None, precedence_verified=False))
    return dict(properties=properties, duration_outside_numeric_bounds=findings)


def checklist(report):
    lines = ['# Характеристики навыков и эффектов', '', 'Аудит: `' + report['id'] + '`.', '',
        '[Источники и ограничения](UI-GAME-DATA.md). Пустое поле и явный ноль различаются.',
        'Каждый пункт требует проверки единиц, defaults / overrides, связей, применения и результата.', '']
    for prop in sorted(report['properties'].values(), key=lambda p: (KINDS.index(p['owner']), p['field'])):
        lines.append('- [ ] ' + prop['id'] + '. `' + prop['owner'] + '.' + prop['field'] +
            '` · наблюдений: ' + str(prop['observations']) + '; пустых: ' + str(prop['blank']) +
            '; явных нулей: ' + str(prop['explicit_zero']))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tasks', type=Path)
    args = parser.parse_args()
    if args.output.exists() or (args.tasks and args.tasks.exists()):
        parser.error('Прежние результаты и отметки не перезаписываются')
    source = args.folder / 'index.json'; source_sha = sha(source)
    dataset = json.loads(source.read_text('utf-8'))
    proofs = {}
    for name in ('effect-time-code.json', 'skill-time-code.json', 'skill-total-time-code.json', 'skill-level-mp-code.json'):
        path = args.root / 'code-clues' / name; raw = json.loads(path.read_text('utf-8'))
        proofs[name] = dict(file='code-clues/' + name, sha256=sha(path), native_sha256=raw['sha256'],
            status='historical_report_not_current_client_validation',
            limits=raw['limitations'])
    result = profile(dataset['nodes'])
    fingerprints = dict(dataset_index=source_sha, audit=sha(Path(__file__)),
                        evidence={k: v['sha256'] for k, v in proofs.items()})
    result.update(id=hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest(),
        dataset=dataset['dataset_id'], fingerprints=fingerprints, evidence=proofs,
        limits=['Наблюдения статических строк не определяют единицы, defaults или текущее состояние.',
            'Пустое поле не подменяется нулём. Время и значения не конвертируются.',
            'Численное сравнение Duration / Min / Max не определяет ошибку или runtime precedence.',
            'Native отчёты повторно не исполнялись; прежний SHA не подтверждает текущий клиент.'])
    if sha(source) != source_sha or any(sha(args.root / p['file']) != p['sha256'] for p in proofs.values()):
        raise ValueError('Источники изменились во время аудита')
    args.output.write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    if args.tasks:
        args.tasks.write_text(checklist(result), 'utf-8')
    print(json.dumps(dict(id=result['id'], properties=len(result['properties']),
        observations=sum(p['observations'] for p in result['properties'].values()),
        duration_outside_numeric_bounds=len(result['duration_outside_numeric_bounds'])), ensure_ascii=False))
