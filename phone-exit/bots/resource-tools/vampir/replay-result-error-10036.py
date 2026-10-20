"""New lobby code input to the existing mapper; do not confuse with Winsock."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('lobby10036_mapper',HERE/'replay-result-error-text.py')
mapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(mapper)


def build():
    manifest=json.loads((mapper.native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
    raw=Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=manifest['source_sha256']:raise ValueError('Client changed')
    case=mapper.Replay(raw,mapper.native.Image(raw)).execute(10036)
    return dict(source_sha256=manifest['source_sha256'],tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        mapper_tool_sha256=hashlib.sha256((HERE/'replay-result-error-text.py').read_bytes()).hexdigest(),case=case,
        limits=['Existing mapper executed with newly observed input10036; FString constructor remains a fixture.',
            'Empty key gives no error meaning or server policy. Lobby response domain is not Winsock.',
            'No authentication, network connection or retry.'])


if __name__=='__main__':
    value=build();path=mapper.native.ROOT/'code-clues/lobby-result-error-10036-replay.json'
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),key=value['case']['key'])))
