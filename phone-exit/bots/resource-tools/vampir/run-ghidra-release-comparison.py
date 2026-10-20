"""Import a new saved EXE in an isolated project and correlate with old Ghidra data."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
OLD = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
NEW = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    lock = json.loads((HERE / 'ghidra-tools.lock.json').read_text('utf-8'))
    tools = ROOT / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if json.loads((tools / lock[name]['directory'] / '.phoneexit-verified.json').read_text('utf-8')) != lock[name]:
            raise ValueError('Pinned tool installation mismatch')
    source = ROOT / 'client-code-snapshots' / NEW / 'ProjectRED-Win64-Shipping.exe'
    old_source = ROOT / 'client-code-snapshots' / OLD / source.name
    if digest(source) != NEW or digest(old_source) != OLD:
        raise ValueError('Saved EXE mismatch')
    latest = ROOT / 'ghidra/latest-export.json'
    old_export = json.loads(latest.read_text('utf-8'))
    report_path = Path(old_export['output']) / 'functions.json'
    if old_export['source_sha256'] != OLD or digest(report_path) != old_export['report_sha256']:
        raise ValueError('Historical export changed')
    out = ROOT / 'ghidra/release-comparisons' / (OLD[:12] + '-' + NEW[:12]) / ('run-' + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    projects = out / 'projects'
    projects.mkdir()
    script = HERE / 'CompareVampirRelease.java'
    inputs = {str(p): digest(p) for p in (Path(__file__), script, latest, report_path)}
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools / lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM'] = '8G'
    home = HERE.parents[2] / '.tools/vampir-ghidra-home'
    home.mkdir(exist_ok=True)
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = '-Duser.home=' + home.as_posix()
    command = [str(tools / lock['ghidra']['directory'] / 'support/analyzeHeadless.bat'),
               str(projects), 'NewRelease', '-import', str(source), '-max-cpu', '2',
               '-analysisTimeoutPerFile', '900', '-scriptPath', str(HERE),
               '-postScript', script.name, str(ROOT / 'ghidra/projects'), 'Vampir_' + OLD[:12],
               OLD, NEW, str(out / 'candidates.json')]
    receipt = dict(schema=1, old_source=str(old_source), old_source_sha256=OLD,
                   new_source=str(source), new_source_sha256=NEW, inputs=inputs,
                   tools=lock, command=command, max_heap='8G', max_cpu=2, analysis_timeout_seconds=900)
    (out / 'invocation.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out), log=str(out / 'headless.log'))), flush=True)
    with (out / 'headless.log').open('w', encoding='utf-8') as stream:
        completed = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode or not (out / 'candidates.json').is_file():
        raise RuntimeError('Comparison did not produce a report; inspect ' + str(out / 'headless.log'))
    if any(digest(Path(p)) != sha for p, sha in inputs.items()):
        raise ValueError('Comparison inputs changed during execution')
    if digest(source) != NEW or digest(old_source) != OLD:
        raise ValueError('Source changed during comparison')
    result = json.loads((out / 'candidates.json').read_text('utf-8'))
    if result['old_source_sha256'] != OLD or result['new_source_sha256'] != NEW:
        raise ValueError('Comparison source mismatch')
    receipt['files'] = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    receipt['analysis_timed_out'] = result['analysis_timed_out']
    (out / 'provenance.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(out), analysis_timed_out=result['analysis_timed_out'],
                          matches={p['correlator']: len(p['matches']) for p in result['passes']})), flush=True)


if __name__ == '__main__':
    main()
