"""Extract named Game INIs from a release-audited PAK, with verified index hashes.

The historical key callback is an explicit key candidate. Successful SHA1 checks
prove decryption of this archive, not the callback binding in the new EXE.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recover(manifest_path, archive_path):
    core = load('release_config_core', HERE / 'recover-pak-game-config.py')
    if core.sha256(manifest_path) != manifest_path.parent.name:
        raise ValueError('Release manifest digest differs')
    release = json.loads(manifest_path.read_text('utf-8'))
    matches = [r for r in release['files'] if Path(r['path']).resolve() == archive_path.resolve()]
    if len(matches) != 1 or not matches[0].get('current', {}).get('sha256'):
        raise ValueError('Explicit archive requires a full hash in the release audit')
    source = matches[0]['current']
    before = archive_path.stat()
    if core.sha256(archive_path) != source['sha256']:
        raise ValueError('Archive changed since release audit')
    prior_path = core.ROOT / 'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json'
    if core.sha256(prior_path) != prior_path.parent.name:
        raise ValueError('Historical key provenance changed')
    prior = json.loads(prior_path.read_text('utf-8'))
    key_source = core.ROOT / 'client-code-snapshots' / core.EXE_SHA256 / 'ProjectRED-Win64-Shipping.exe'
    if core.sha256(key_source) != core.EXE_SHA256:
        raise ValueError('Historical key source changed')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    dll = Path('F:/PhoneExit Resources/RF Online Next/tools/oodle-data-shared.dll')
    dependencies = prior['dependencies']
    if core.sha256(reader_path) != dependencies['reader_sha256'] or core.sha256(dll) != dependencies['oodle_sha256']:
        raise ValueError('Pinned reader or Oodle changed')
    flow = core.load('release_config_key_flow', HERE / 'build-headless-cdn-json-flow.py')
    preparation = flow.body.head.headers.uri.http.preparation
    native = preparation.url.settings.config.native
    raw = key_source.read_bytes()
    key, key_report = core.recover_key(raw, native.Image(raw), native, preparation)
    reader = core.load('release_config_reader', reader_path)
    with archive_path.open('rb') as stream:
        stream.seek(-512, 2)
        tail = stream.read()
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if marker < 17 or tail[marker - 17:marker - 1] != bytes(16) or tail[marker - 1] != 1 or struct.unpack_from('<i', tail, marker + 4)[0] != 11:
            raise ValueError('Unsupported encrypted PAK footer')
        offset, size = struct.unpack_from('<QQ', tail, marker + 8)
        limit = before.st_size - 512 + marker - 17
        main_info = dict(offset=offset, size=size, sha1=tail[marker + 24:marker + 44].hex())
        main = core.read_verified_index(stream, main_info, key, limit)
        metadata, encoded = core.parse_main(main)
        directory_info = metadata['side_indexes']['full_directory']
        directory_raw = core.read_verified_index(stream, directory_info, key, limit)
        directory = core.parse_directory(directory_raw, metadata['entry_count'])
        entries = {row['path']: row for row in directory['entries']}
        files, configs = {}, []
        for name in core.GAME_FILES:
            payload, info = core.extract_config(stream, entries[name], encoded, key, reader, offset)
            label = 'DefaultGame.ini' if name.endswith('/DefaultGame.ini') else 'WindowsGame.ini'
            files[label] = payload
            configs.append({**info, 'snapshot_file': label})
    after = archive_path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or core.sha256(archive_path) != source['sha256']:
        raise ValueError('Archive changed during recovery')
    files['directory.json'] = (json.dumps(directory, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    report = dict(schema_version=1, release_manifest_sha256=manifest_path.parent.name,
        source_exe=release['exe']['path'], exe_sha256=release['exe']['sha256'],
        source_archive=dict(path=str(archive_path), size=before.st_size, modified_ns=before.st_mtime_ns),
        archive_sha256=source['sha256'], tool_sha256=core.sha256(Path(__file__)),
        recovery_tool_sha256=core.sha256(HERE / 'recover-pak-game-config.py'), dependencies=dependencies,
        key_candidate_source=str(key_source), key_candidate_source_sha256=core.EXE_SHA256,
        key_callback=key_report, key_binding_in_current_exe_verified=False,
        main_index=main_info, main_metadata=metadata, directory_index=directory_info,
        directory_sha256=core.hashlib.sha256(directory_raw).hexdigest(),
        directory_paths_file_sha256=core.hashlib.sha256(files['directory.json']).hexdigest(), configs=configs,
        authoritative_directory_for_archive=True, path_hash_side_index_verified=False,
        active_runtime_settings_verified=False, config_precedence_verified=False, network_ready=False)
    target, digest = core.save(report, files)
    print(json.dumps(dict(manifest=str(target), sha256=digest, directory_files=metadata['entry_count'],
                         configs=[dict(file=c['snapshot_file'], sha256=c['payload_sha256'], values=c['values']) for c in configs]), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    recover(args.manifest, args.archive)
