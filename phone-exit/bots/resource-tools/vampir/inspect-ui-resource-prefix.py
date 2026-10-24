"""Static prefix producer/calls and exact config observation; never claims active settings."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prefix_getter', HERE / 'inspect-nktileview-registration.py')
getter = importlib.util.module_from_spec(spec); spec.loader.exec_module(getter)
native = getter.native


def config_value(text):
    section = None; found = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1]
        elif section == 'NnCoreSetting' and '=' in stripped and not stripped.startswith((';', '#')):
            key, value = stripped.split('=', 1)
            if key.strip() == 'ContentSubName': found.append(dict(line=number, value=value.strip()))
    if len(found) != 1: raise ValueError('Нужна единственная точная запись ContentSubName в NnCoreSetting')
    return found[0]


def inspect(request, config_manifest):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    roots = (0x1445c6820, 0x141426b30, 0x1414277b0, 0x141429e10)
    if not {hex(a) for a in roots} <= {f['address'] for f in request['functions']}:
        raise ValueError('Не все явные prefix/string roots входят в задание')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for address in roots:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Изменилась unwind граница')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    rows = {row['address']: row for part in fragments for row in part['instructions']}
    expected = {0x1445c6865: ('call', '0x1445c2c30'),
                0x1445c6b4e: ('call', '0x1414277b0'),
                0x1445c6b53: ('cmp', 'dword ptr [rip + 0x6f9db2e], 1'),
                0x1445c6b60: ('jle', '0x1445c6ba8'),
                0x1445c6b75: ('call', '0x14142b760'),
                0x1445c6b94: ('call', '0x141429e10')}
    for at, pair in expected.items():
        if (rows[at]['mnemonic'], rows[at]['operands']) != pair:
            raise ValueError('Изменился prefix data flow')
    literals = {}
    for at, text in ((0x1445c684d, 'ContentSubName'), (0x1445c6857, 'NnCoreSetting'),
                     (0x1445c6b3a, '/Game'), (0x1445c6b69, '/')):
        address = rows[at]['rip_references'][0]; offset = image.offset(address - image.pe.base)
        encoded = (text + '\0').encode('utf-16le')
        if raw[offset:offset + len(encoded)] != encoded: raise ValueError('Изменился литерал')
        literals[text] = dict(address=hex(address), offset=offset, bytes=encoded.hex())
    meta_raw = config_manifest.read_bytes(); meta = json.loads(meta_raw)
    if meta['exe_sha256'] != getter.SHA: raise ValueError('Снимок конфигурации другой версии')
    configs = [c for c in meta['configs'] if c['path'] == 'ProjectRED/Config/DefaultGame.ini']
    if len(configs) != 1: raise ValueError('Нет однозначной DefaultGame.ini')
    path = (config_manifest.parent / configs[0]['snapshot_file']).resolve()
    if not path.is_relative_to(config_manifest.parent.resolve()): raise ValueError('Путь вне снимка')
    data = path.read_bytes(); observed = config_value(data.decode('utf-8-sig'))
    return dict(source_sha256=getter.SHA, fragments=fragments, literals=literals,
        flow=dict(config_section='NnCoreSetting', config_key='ContentSubName',
            config_target='0x14b564680', prefix_target='0x14b5646b0',
            initial_argument='/Game', condition='dword at14b564688 > 1',
            separator_argument='/', string_helpers=['0x1414277b0', '0x14142b760', '0x141429e10']),
        config_observation=dict(manifest=str(config_manifest), manifest_sha256=getter.sha(meta_raw),
            file=str(path), plaintext_snapshot_sha256=getter.sha(data), **observed,
            archive_sha256=meta['archive_sha256'],
            config_precedence_verified=meta['config_precedence_verified'],
            active_runtime_settings_verified=meta['active_runtime_settings_verified']),
        limits=['Static call/literal/data-flow proof; full config reader and string concatenation not executed.',
            'Config snapshot value is an observation, not active mounted precedence or runtime global value.',
            'No automatic /Game/RED path is emitted; helper semantics and successful resolution remain separate.',
            'Plaintext snapshot SHA is separate from stored ciphertext payload hash in config manifest.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--config-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = inspect(json.loads(args.request.read_text('utf-8')), args.config_manifest)
    result['inspector_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(fragments=len(result['fragments']), config_value=result['config_observation']['value'],
        active_runtime_settings_verified=result['config_observation']['active_runtime_settings_verified']), ensure_ascii=False))
