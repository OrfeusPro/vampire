"""Current complete game result mapper for the observed code 1 and control codes."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
COMPARISON = ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'


def main():
    spec = importlib.util.spec_from_file_location('release_result_mapper', HERE / 'replay-result-error-text.py')
    mapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mapper)
    spec = importlib.util.spec_from_file_location('release_result_audit', HERE / 'audit-client-release.py')
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    source = ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(source) != SHA:
        raise ValueError('Current result mapper source changed')
    evidence = {'run-4d1035d2befb': '26ed50f4c7ff83354cd36b651cfc7453f117a5587feca54f6ee36e81cde65ae1',
                'run-5f520de02cee': '329dcdce6357bcc5a9f1747dc992d17e7beb637acf457d02646cf8b18dacc88c'}
    for name, sha in evidence.items():
        if audit.sha256(COMPARISON / 'details' / name / 'details.json') != sha:
            raise ValueError('Current result mapper Ghidra evidence changed')
    if mapper.unicorn.__version__ != '2.1.4' or mapper.native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned native tools required')
    mapper.ENTRY, mapper.CONSTRUCT = 0x145814800, 0x141426a30
    raw = source.read_bytes()
    image = mapper.native.Image(raw)
    cases = [mapper.Replay(raw, image).execute(code) for code in (0, 1, 16, 58)]
    expected = {0: 'Success', 1: 'InvalidPacketVersion', 16: 'InvalidState', 58: 'BlockedIp'}
    if {case['code']: case['key'] for case in cases} != expected:
        raise ValueError('Current result labels differ')
    report = dict(schema=1, source=str(source), source_sha256=SHA, tool_sha256=audit.sha256(Path(__file__)),
                  ghidra_evidence=evidence, cases=cases, entry=hex(mapper.ENTRY), construct_fixture=hex(mapper.CONSTRUCT),
                  dependencies={name: audit.sha256(HERE / name) for name in ('replay-result-error-text.py',
                      'build-headless-ping-codec.py', 'build-native-entry-code.py', 'requirements-native.txt')},
                  native_execution=True, network_used=False,
                  limits=['Complete current mapper entry/return executes for four explicit result codes.',
                          'Existing bounded FString constructor fixture and reached-instruction tracer are reused.',
                          'Ghidra pseudo-code has bad/unreachable-instruction warnings; reached machine instructions determine these outputs.',
                          'Popup table override, rendered UI, server policy and the cause of code 1 are not executed.'])
    path = audit.save_snapshot(COMPARISON / 'result-error-replay', report)
    print(json.dumps(dict(report=str(path), sha256=audit.sha256(path), keys=expected), indent=2))


if __name__ == '__main__':
    main()
