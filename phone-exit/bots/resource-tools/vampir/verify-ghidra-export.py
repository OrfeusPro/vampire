"""Verify export provenance and make a human-readable batch index."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))


def verify(out):
    report=json.loads((out/'functions.json').read_text('utf-8'))
    provenance=json.loads((out/'provenance.json').read_text('utf-8'))
    manifest_path=ROOT/'ghidra/entry-manifest.json';manifest=json.loads(manifest_path.read_text('utf-8'))
    if report['source_sha256']!=manifest['source_sha256'] or provenance['source_sha256']!=manifest['source_sha256']:
        raise ValueError('Source mismatch')
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest()!=provenance['manifest_sha256']:raise ValueError('Manifest changed since export')
    for name,digest in provenance['files'].items():
        if Path(name).name!=name or hashlib.sha256((out/name).read_bytes()).hexdigest()!=digest:raise ValueError('Export file hash mismatch '+name)
    expected={f['name']:int(f['address'],16) for f in manifest['functions']}
    observed={f['name']:int(f['address'],16) for f in report['functions']}
    if expected!=observed:raise ValueError('Function inventory mismatch')
    lines=['# Vampir — пакетный экспорт Ghidra','',
        'Псевдокод и связи вызовов помогают исследованию; это не исходный C++ проект и не проверенный протокол.',
        'Имена функций заданы по общему справочнику; типы и выражения восстановлены декомпилятором.',
        '',f"Source SHA256: `{report['source_sha256']}`.",
        f"Ghidra {report['ghidra_version']}, Java {report['java_version']}.",'',
        '| Функция | Адрес | Инструкций | Calls | Результат |','| --- | --- | ---: | ---: | --- |']
    warnings=0
    for f in report['functions']:
        if not f['completed'] or not f.get('pseudocode_file'):raise ValueError('Incomplete decompilation '+f['name'])
        text=(out/f['pseudocode_file']).read_text('utf-8')
        if not text.strip():raise ValueError('Empty pseudocode '+f['name'])
        warnings+=text.count('WARNING')
        lines.append(f"| [{f['name']}]({f['pseudocode_file']}) | `{f['address']}` | {f['instruction_count']} | {len(f['calls'])} | completed |")
    lines+=['',f'Warnings в псевдокоде: {warnings}. Их требуется читать перед переносом логики.',
        'PE unwind ranges и SHA исходных участков — ['+manifest_path.name+']('+os.path.relpath(manifest_path,out).replace('\\','/')+').',
        'Декомпиляция не запускает игру и не доказывает корректность типов, сетевой обмен или авторизацию.','']
    (out/'INDEX.md').write_text('\n'.join(lines),encoding='utf-8')
    root=ROOT/'ghidra'
    relative=out.resolve().relative_to(root.resolve()).as_posix()
    overview=['# Vampir — анализ кода через Ghidra','',
        f"Клиент SHA256: `{report['source_sha256']}`.",
        f"Экспортировано функций: {len(expected)}. Предупреждений: {warnings}.",'',
        f'- [Полный индекс псевдокода]({relative}/INDEX.md)',
        f'- [Подготовка Login]({relative}/Login_Prepare.c)',
        f'- [Сериализатор Login]({relative}/PktLogin_Write.c)',
        f'- [Request handoff]({relative}/Request_Handoff.c)',
        f'- [Обработчик VersionResult]({relative}/VersionResult_Handler.c)',
        '- [Исходные адреса и SHA участков](entry-manifest.json)',
        '- [Указатель последнего экспорта](latest-export.json)','',
        'Это восстановленный псевдокод с аналитическими именами, не исходный C++ проект.',
        'Сетевой обмен и успешный вход не проверяются декомпиляцией.','']
    (root/'INDEX.md').write_text('\n'.join(overview),encoding='utf-8')
    return dict(functions=len(expected),warnings=warnings,index=str(out/'INDEX.md'))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path,nargs='?')
    args=parser.parse_args()
    out=args.output
    if out is None:
        latest=json.loads((ROOT/'ghidra/latest-export.json').read_text('utf-8'));out=Path(latest['output'])
        if hashlib.sha256((out/'functions.json').read_bytes()).hexdigest()!=latest['report_sha256']:raise ValueError('Latest report hash mismatch')
    result=verify(out)
    print(json.dumps(result,ensure_ascii=False))
