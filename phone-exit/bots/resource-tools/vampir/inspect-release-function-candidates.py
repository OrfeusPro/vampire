"""Export instructions and pseudocode for priority pairs from a completed comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('comparison', type=Path)
    parser.add_argument('--dependencies', action='store_true', help='Inspect unresolved list-reader dependencies and observed callback words')
    parser.add_argument('--only', help='Comma-separated dependency pair names; avoid exporting already reviewed pairs')
    args = parser.parse_args()
    if args.only and not args.dependencies:
        parser.error('--only requires --dependencies')
    here = Path(__file__).resolve().parent
    root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
    provenance = args.comparison / 'provenance.json'
    receipt = json.loads(provenance.read_text('utf-8'))
    candidates = args.comparison / 'candidates.json'
    if digest(candidates) != receipt['files']['candidates.json']:
        raise ValueError('Candidate digest mismatch')
    for prefix in ('old', 'new'):
        if digest(Path(receipt[prefix + '_source'])) != receipt[prefix + '_source_sha256']:
            raise ValueError('Source digest mismatch')
    lock = json.loads((here / 'ghidra-tools.lock.json').read_text('utf-8'))
    tools = root / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if json.loads((tools / lock[name]['directory'] / '.phoneexit-verified.json').read_text('utf-8')) != lock[name]:
            raise ValueError('Pinned tool mismatch')
    script = here / 'InspectVampirReleaseCandidates.java'
    inputs = {str(p): digest(p) for p in (Path(__file__), script, candidates, provenance)}
    out = args.comparison / 'details' / ('run-' + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools / lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM'] = '8G'
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = '-Duser.home=' + (here.parents[2] / '.tools/vampir-ghidra-home').as_posix()
    command = [str(tools / lock['ghidra']['directory'] / 'support/analyzeHeadless.bat'),
               receipt['command'][1], 'NewRelease', '-process', Path(receipt['new_source']).name,
               '-noanalysis', '-max-cpu', '2', '-scriptPath', str(here), '-postScript', script.name,
               str(candidates), str(out)]
    if args.dependencies:
        command.append('dependencies')
    if args.only:
        command.append(args.only)
    invocation = dict(inputs=inputs, tools=lock, command=command)
    (out / 'invocation.json').write_text(json.dumps(invocation, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out))), flush=True)
    with (out / 'headless.log').open('w', encoding='utf-8') as stream:
        completed = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode or not (out / 'details.json').is_file():
        raise RuntimeError('Details not exported; inspect ' + str(out / 'headless.log'))
    if any(digest(Path(p)) != sha for p, sha in inputs.items()):
        raise ValueError('Inputs changed during export')
    invocation['files'] = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    (out / 'provenance.json').write_text(json.dumps(invocation, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(out / 'details.json'), sha256=digest(out / 'details.json'))), flush=True)


if __name__ == '__main__':
    main()
