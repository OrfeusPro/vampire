"""Recover table reference declarations from intact Korean validation messages.

Extracts declared foreign-key relationships, never invents row IDs or values.
"""
import hashlib
import json
import mmap
import os
import re
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
INSTALL = Path(os.environ.get('PHONEEXIT_VAMPIR_INSTALL', 'C:/Program Files/Netmarble/Netmarble Game/VAMPIR'))


def main():
    source = INSTALL / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    out = ROOT / 'code-clues'
    out.mkdir(exist_ok=True)
    references, rejected = [], []
    marker = '[데이터 참조 오류]'.encode('utf-16le')
    # This explicit diagnostic names the source workbook/sheet/column and target.
    grammar = re.compile(r"'([^']+\.xlsx)' 엑셀의 '([^']+)' 시트 → '([^']+)' 컬럼 값.*?참조 대상인 '([^']+\.xlsx)' 엑셀의 '([^']+)' 시트", re.DOTALL)
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        digest = hashlib.sha256(data).hexdigest()
        for match in re.finditer(re.escape(marker), data):
            start, end = match.start(), match.end()
            while end + 2 <= len(data) and end < start + 16384 and data[end:end + 2] != b'\x00\x00':
                end += 2
            message = data[start:end].decode('utf-16le', errors='strict')
            fields = grammar.search(message)
            if not fields:
                rejected.append(dict(offset=start, text=message))
                continue
            workbook, sheet, column, target_book, target_sheet = fields.groups()
            references.append(dict(offset=start, encoding='utf-16le', evidence='reference_validation_diagnostic',
                                   source=dict(workbook=workbook, sheet=sheet), field=column,
                                   target=dict(workbook=target_book, sheet=target_sheet), text=message))
    report = dict(source=str(source), sha256=digest, references=references, rejected=rejected,
                  limitation='Declared table references only; row values, ordering and runtime state are not recovered')
    (out / 'table-dependencies.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    selected = [r for r in references if any(s in r['source']['workbook'] for s in ('Quest/', 'Tutorial/', 'World/WorldSpot', 'World/Area'))]
    lines = ['# Зависимости таблиц Vampir', '', 'Автоматически извлечено из полных диагностических строк проверки ссылок в EXE.',
             'Численные значения строк и выполнение квестов этим не восстановлены.', '',
             '| Источник (XLSX / лист) | Поле ссылки | Целевая таблица (XLSX / лист) | Смещение в EXE |', '|---|---|---|---|']
    for row in selected:
        src, dst = row['source'], row['target']
        lines.append(f"| {src['workbook']} / {src['sheet']} | {row['field']} | {dst['workbook']} / {dst['sheet']} | {row['offset']} |")
    (out / 'quest-dependencies.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(references=len(references), rejected=len(rejected), quest_world_tutorial=len(selected)), ensure_ascii=False))
    for row in selected:
        if row['source']['sheet'] in ('Quest', 'QuestTask', 'Tutorial', 'TutorialStep', 'TutorialUI'):
            print(row['source']['sheet'] + '.' + row['field'] + ' -> ' + row['target']['sheet'])


if __name__ == '__main__':
    main()
