"""Recover two public module descriptors from verified base/patch PAK indexes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('descriptor_core', HERE / 'recover-pak-game-config.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
PROFILES = {
    'base': '393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db',
    'patch': 'fa7cf1b9ef8a76bab748ef8b63bd64463dba08eca5dcd261f3f164127f241a66',
}
DESCRIPTORS = {'ProjectRED/ProjectRED.uproject': 'ProjectRED.uproject',
               'ProjectRED/Plugins/NkPatch/NkPatch.uplugin': 'NkPatch.uplugin'}
OUTPUTS = {f'{role}.{label}' for role in PROFILES for label in DESCRIPTORS.values()}


def summarize(data):
    obj = json.loads(data.decode('utf-8-sig'))
    if not isinstance(obj, dict) or not isinstance(obj.get('Modules'), list) or len(obj['Modules']) > 128:
        raise ValueError('Unsupported module descriptor')
    modules = []
    for i, row in enumerate(obj['Modules']):
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) for k in ('Name', 'Type', 'LoadingPhase')):
            raise ValueError('Invalid module declaration')
        modules.append(dict(json_pointer=f'/Modules/{i}', declaration=row))
    return dict(modules=modules, nkpatch_plugin=[dict(json_pointer=f'/Plugins/{i}', declaration=row)
                for i, row in enumerate(obj.get('Plugins', [])) if isinstance(row, dict) and row.get('Name') == 'NkPatch'])


def recover():
    references = {}
    for role, identity in PROFILES.items():
        path = core.ROOT / 'resource-config-snapshots' / identity / 'manifest.json'
        if core.sha256(path) != identity:
            raise ValueError('Config reference snapshot changed')
        references[role] = json.loads(path.read_text('utf-8'))
    source = references['base']['source_exe']
    raw = Path(source).read_bytes()
    if hashlib.sha256(raw).hexdigest() != core.EXE_SHA256:
        raise ValueError('Compiled key source changed')
    flow = core.load('descriptor_flow', HERE / 'build-headless-cdn-json-flow.py')
    preparation = flow.body.head.headers.uri.http.preparation
    native = preparation.url.settings.config.native
    key, key_report = core.recover_key(raw, native.Image(raw), native, preparation)
    dependencies = references['base']['dependencies']
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    dll = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', 'F:/PhoneExit Resources/RF Online Next')) / 'tools/oodle-data-shared.dll'
    if core.sha256(reader_path) != dependencies['reader_sha256'] or core.sha256(dll) != dependencies['oodle_sha256']:
        raise ValueError('Descriptor decoder dependency changed')
    reader = core.load('descriptor_reader', reader_path)
    archives, files = [], {}
    for role, reference in references.items():
        archive = Path(reference['source_archive']['path'])
        before = archive.stat()
        if core.sha256(archive) != reference['archive_sha256']:
            raise ValueError('Descriptor archive changed')
        with archive.open('rb') as stream:
            limit = before.st_size - 221
            main = core.read_verified_index(stream, reference['main_index'], key, limit)
            metadata, encoded = core.parse_main(main)
            directory_info = metadata['side_indexes']['full_directory']
            directory_raw = core.read_verified_index(stream, directory_info, key, limit)
            directory = core.parse_directory(directory_raw, metadata['entry_count'])
            names = {e['path']: e for e in directory['entries']}
            entries = []
            for name, label in DESCRIPTORS.items():
                if name not in names:
                    entries.append(dict(path=name, present=False))
                    continue
                payload, info = core.extract_config(stream, names[name], encoded, key, reader, reference['main_index']['offset'])
                snapshot_file = f'{role}.{label}'
                files[snapshot_file] = payload
                entries.append(dict(**info, present=True, snapshot_file=snapshot_file, **summarize(payload)))
        after = archive.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('Archive changed during descriptor recovery')
        archives.append(dict(role=role, path=str(archive), size=before.st_size, modified_ns=before.st_mtime_ns,
            sha256=reference['archive_sha256'], config_snapshot_sha256=PROFILES[role],
            main_index=reference['main_index'], directory_index=directory_info, entries=entries))
    return dict(schema_version=1, source_exe=source, exe_sha256=core.EXE_SHA256,
        tool_sha256=core.sha256(Path(__file__)), recovery_tool_sha256=core.sha256(HERE / 'recover-pak-game-config.py'),
        dependencies=dependencies, key_callback=key_report, archives=archives,
        declared_loading_phases_only=True, runtime_module_order_verified=False,
        config_precedence_verified=False, active_runtime_settings_verified=False, network_ready=False), files


def save(report, files):
    if set(files) - OUTPUTS:
        raise ValueError('Unsupported descriptor output filename')
    manifest = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    identity = hashlib.sha256(manifest).hexdigest()
    folder = core.ROOT / 'module-config-snapshots' / identity
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in {**files, 'manifest.json': manifest}.items():
        target = folder / name
        try:
            with target.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            if target.read_bytes() != data:
                raise ValueError('Immutable descriptor snapshot differs') from None
    return folder / 'manifest.json', identity


if __name__ == '__main__':
    report, files = recover()
    manifest, identity = save(report, files)
    pointer = dict(manifest=str(manifest), sha256=identity, files=len(files), runtime_module_order_verified=False)
    (core.ROOT / 'code-clues/module-descriptor-recovery.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))
