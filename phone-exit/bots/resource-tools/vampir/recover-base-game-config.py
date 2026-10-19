"""Verify base-install Game INIs independently of patch configuration precedence."""
import json
import os
import struct
from pathlib import Path
import importlib.util

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('base_config_recovery', HERE / 'recover-pak-game-config.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
ARCHIVE = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Content/Paks/ProjectRED-Windows.pak')
ARCHIVE_SHA256 = 'c10228ece0e1252bdd3ccf99fd4936e52d7a144f96c634080947d24c429e525b'
PATCH_ID = 'fa7cf1b9ef8a76bab748ef8b63bd64463dba08eca5dcd261f3f164127f241a66'


def recover():
    prior_path = core.ROOT / 'resource-config-snapshots' / PATCH_ID / 'manifest.json'
    if core.sha256(prior_path) != PATCH_ID:
        raise ValueError('Patch reference snapshot changed')
    prior = json.loads(prior_path.read_text('utf-8'))
    before = ARCHIVE.stat()
    if core.sha256(ARCHIVE) != ARCHIVE_SHA256:
        raise ValueError('Base archive no longer matches supported release')
    raw = Path(prior['source_exe']).read_bytes()
    if core.hashlib.sha256(raw).hexdigest() != core.EXE_SHA256:
        raise ValueError('Unsupported compiled key source')
    flow = core.load('base_recovery_flow', HERE / 'build-headless-cdn-json-flow.py')
    preparation = flow.body.head.headers.uri.http.preparation
    native = preparation.url.settings.config.native
    key, key_report = core.recover_key(raw, native.Image(raw), native, preparation)
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    dll = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', 'F:/PhoneExit Resources/RF Online Next')) / 'tools/oodle-data-shared.dll'
    dependencies = prior['dependencies']
    if (core.sha256(reader_path) != dependencies['reader_sha256'] or
            core.sha256(dll) != dependencies['oodle_sha256']):
        raise ValueError('Reader or Oodle dependency changed')
    reader = core.load('base_recovery_reader', reader_path)
    with ARCHIVE.open('rb') as stream:
        stream.seek(-512, 2)
        tail = stream.read()
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if (marker < 17 or tail[marker - 17:marker - 1] != bytes(16) or
                tail[marker - 1] != 1 or struct.unpack_from('<i', tail, marker + 4)[0] != 11):
            raise ValueError('Unsupported encrypted PAK footer')
        offset, size = struct.unpack_from('<QQ', tail, marker + 8)
        limit = before.st_size - 512 + marker - 17
        main_info = dict(offset=offset, size=size, sha1=tail[marker + 24:marker + 44].hex())
        main = core.read_verified_index(stream, main_info, key, limit)
        metadata, encoded = core.parse_main(main)
        directory_info = metadata['side_indexes']['full_directory']
        directory_raw = core.read_verified_index(stream, directory_info, key, limit)
        directory = core.parse_directory(directory_raw, metadata['entry_count'])
        names = {entry['path']: entry for entry in directory['entries']}
        files, configs, comparisons = {}, [], []
        patch_configs = {c['path']: c for c in prior['configs']}
        for name in core.GAME_FILES:
            payload, info = core.extract_config(stream, names[name], encoded, key, reader, offset)
            patch = patch_configs[name]
            patch_file = prior_path.parent / patch['snapshot_file']
            if core.sha256(patch_file) != patch['payload_sha256']:
                raise ValueError('Patch config snapshot changed')
            label = patch['snapshot_file']
            files[label] = payload
            configs.append({**info, 'snapshot_file': label})
            base_values = {v['key']: v['value'] for v in info['values']}
            patch_values = {v['key']: v['value'] for v in patch['values']}
            comparisons.append(dict(path=name, base_sha256=info['payload_sha256'],
                patch_sha256=patch['payload_sha256'],
                values=[dict(key=k, base=base_values.get(k), patch=patch_values.get(k))
                        for k in sorted(base_values.keys() | patch_values.keys())]))
    after = ARCHIVE.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Base archive changed during recovery')
    files['directory.json'] = (json.dumps(directory, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    report = dict(schema_version=1, archive_role='base_install', source_exe=prior['source_exe'],
        exe_sha256=core.EXE_SHA256, source_archive=dict(path=str(ARCHIVE), size=before.st_size,
        modified_ns=before.st_mtime_ns), archive_sha256=ARCHIVE_SHA256,
        tool_sha256=core.sha256(Path(__file__)), recovery_tool_sha256=core.sha256(HERE / 'recover-pak-game-config.py'),
        patch_snapshot_sha256=PATCH_ID, key_callback=key_report, dependencies=dependencies,
        main_index=main_info, main_metadata=metadata, directory_index=directory_info,
        directory_sha256=core.hashlib.sha256(directory_raw).hexdigest(),
        directory_paths_file_sha256=core.hashlib.sha256(files['directory.json']).hexdigest(),
        configs=configs, patch_comparison=comparisons, authoritative_directory_for_archive=True,
        path_hash_side_index_verified=False, active_runtime_settings_verified=False,
        config_precedence_verified=False, network_ready=False)
    return report, files


if __name__ == '__main__':
    report, files = recover()
    manifest, identity = core.save(report, files)
    pointer = dict(manifest=str(manifest), sha256=identity,
                   directory_files=report['main_metadata']['entry_count'],
                   config_precedence_verified=False, active_runtime_settings_verified=False)
    (core.ROOT / 'code-clues/base-game-config-recovery.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))
