"""Snapshot explicit installed public manifestlist and parse its ClientVersion.

Does not update the installation or inspect private player/account files.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.patch_revision import parse_patch_client_revision

ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Saved/PersistentDownloadDir/Patch/windows.manifestlist')


def build(path):
    path = path.resolve(strict=True)
    if path.stat().st_size > 2097152: raise ValueError('Patch manifest too large')
    raw = path.read_bytes()
    revision = parse_patch_client_revision(raw)
    digest = hashlib.sha256(raw).hexdigest()
    folder = ROOT / 'patch-state-snapshots' / digest
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / 'windows.manifestlist'
    if target.exists() and target.read_bytes() != raw: raise ValueError('Immutable patch snapshot differs')
    if not target.exists(): target.write_bytes(raw)
    report = dict(source=str(path), source_sha256=digest, source_bytes=len(raw), snapshot=str(target),
                  client_revision=revision, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  parser_sha256=hashlib.sha256((HERE.parents[1] / 'vampir-shared/vampir_core/patch_revision.py').read_bytes()).hexdigest(),
                  limitations=['Installed manifestlist is explicit input; no game process or patch completion proof.',
                               'Snapshot identity does not certify freshness versus CDN or integrity of every referenced file.'])
    out = ROOT / 'code-clues/installed-patch-revision.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(), revision=revision, manifest_sha256=digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifestlist', type=Path, default=SOURCE)
    print(json.dumps(build(parser.parse_args().manifestlist)))
