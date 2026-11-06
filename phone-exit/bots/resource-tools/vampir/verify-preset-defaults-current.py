"""Whole current preset/DataAsset/UObject constructors with explicit services."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/preset-defaults-11322.json'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path), Path(root)
    context = json.loads(context_path.read_bytes())
    sha = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
    if context.get('schema') != 1 or context.get('recipe') != 'preset-defaults-current-v1' or context['source_sha256'] != sha:
        raise ValueError('Current preset context/source differs')
    roles = {k: int(v, 16) for k, v in context['functions'].items()}
    if set(roles) != {'preset', 'data_asset', 'uobject'}:
        raise ValueError('Preset constructor roles differ')
    h = load('native-request-harness-11316').make_harness(context['exports'], set(roles.values()),
        root=root, source_sha256=sha, copy_thunk=None)
    uc, x = h.uc, h.x
    for row in context['descriptors']:
        off = h.image.offset(int(row['descriptor'], 16) - h.image.pe.base)
        data = h.raw[off:off + 56]
        if data.hex() != row['bytes']:
            raise ValueError('Current preset descriptor changed')
        name_offset = h.image.offset(struct.unpack_from('<Q', data)[0] - h.image.pe.base)
        if (h.raw[name_offset:name_offset + len(row['name']) + 1] != row['name'].encode('ascii') + b'\0'
                or struct.unpack_from('<I', data, 24)[0] != row['flags']
                or struct.unpack_from('<I', data, 50)[0] != row['offset']):
            raise ValueError('Current descriptor name/type/offset differs')
    fields = [d for d in context['descriptors'] if d['name'] != 'UnderlyingType']
    if len(fields) != 17 or [d['offset'] for d in fields] != list(range(0x30, 0x74, 4)):
        raise ValueError('Current preset field offsets differ')
    obj, init, cls = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    calls = []
    hooks = {k: int(v, 16) for k, v in context['fixtures'].items()}
    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        calls.append(at)
        if at == hooks['initializer']:
            h.finish(init)
        elif at == hooks['uobject_service']:
            h.finish()
        elif at == hooks['class_service']:
            if machine.reg_read(x.UC_X86_REG_RCX) != cls:
                raise ValueError('DataAsset class service argument differs')
            h.finish()
        else:
            raise ValueError('Unexpected invalid initializer branch')
    for at in hooks.values():
        h.add_fixture(at, fixture)
    cases = []
    for poison in (0, 0xa5, 0xff):
        for feature in (0, 1):
            for has_class in (False, True):
                for already_bound in (False, True):
                    calls.clear()
                    uc.mem_write(obj - 16, bytes([0x47]) * 16 + bytes([poison]) * 0x78 + bytes([0x83]) * 16)
                    uc.mem_write(obj + 16, struct.pack('<Q', cls if has_class else 0))
                    uc.mem_write(init, struct.pack('<Q', obj if already_bound else 0) + bytes([0xcd]) * 24)
                    uc.mem_write(init + 0x20, struct.pack('<Q', obj))
                    uc.mem_write(int(context['feature_global'], 16), bytes([feature]))
                    h.call(roles['preset'], init + 0x20)
                    result = bytes(uc.mem_read(obj, 0x78))
                    if result[:8] != struct.pack('<Q', int(context['vtable'], 16)):
                        raise ValueError('Current preset vtable differs')
                    if result[0x30:0x54] != bytes([poison]) * 36:
                        raise ValueError('Constructor unexpectedly initialized omitted integer fields')
                    if struct.unpack_from('<7f', result, 0x54) != (0.5,) * 7 or result[0x70] != 0:
                        raise ValueError('Current float/voice constructor values differ')
                    if result[0x28:0x30] != struct.pack('<Q', cls if has_class else 0):
                        raise ValueError('DataAsset class forwarding differs')
                    if bytes(uc.mem_read(init, 8)) != struct.pack('<Q', obj) or uc.mem_read(init + 0x12, 1) != b'\0':
                        raise ValueError('UObject initializer ownership differs')
                    if bytes(uc.mem_read(obj - 16, 16)) != bytes([0x47]) * 16 or bytes(uc.mem_read(obj + 0x78, 16)) != bytes([0x83]) * 16:
                        raise ValueError('Constructor wrote outside object')
                    if calls.count(hooks['initializer']) != 1 or calls.count(hooks['uobject_service']) != 1:
                        raise ValueError('Constructor service sequence differs')
                    if calls.count(hooks['class_service']) != int(bool(feature and has_class)):
                        raise ValueError('DataAsset feature/class branch differs')
                    cases.append(dict(poison=poison, feature=feature, has_class=has_class,
                        already_bound=already_bound, integer_defaults_written=False, floats=[0.5] * 7, voice=0))
    calls.clear()
    uc.mem_write(init + 0x20, bytes(8))
    h.call(roles['preset'], init + 0x20)
    if calls:
        raise ValueError('Null object called constructor services')
    inputs = {str(context_path.resolve()): digest(context_path), str(Path(__file__).resolve()): digest(__file__),
        str(h.source.resolve()): sha}
    for name in ('native-request-harness-11316.py', 'build-native-entry-code.py', 'audit-client-release.py'):
        p = HERE / name
        inputs[str(p)] = digest(p)
    for p in h.evidence:
        inputs[p['path']] = p['sha256']
    if any(digest(p) != expected for p, expected in inputs.items()):
        raise ValueError('Current preset inputs changed')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=sha, inputs=inputs,
        cases=cases, null_object_services=0, descriptors=fields, native_execution=True,
        network_used=False, runtime_admitted=False, complete_loaded_preset_verified=False,
        limits=['Whole preset, DataAsset and UObject constructors execute. Initializer lookup and external UObject/class services are fixtures.',
                'Omitted integers preserve poison. A current allocation/completion/CDO property-copy chain is still required.',
                'Descriptor bytes and fields are exact current data; registration and full ClassInfo/preset consumers are not executed.',
                'No Viper payload, Create packet or server acceptance is provided.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/preset-defaults-current-v1', report)
    return dict(report=str(path), sha256=digest(path), cases=len(cases) + 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(verify()))
