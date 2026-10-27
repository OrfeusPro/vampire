"""Current Clock/Ping whole exported ranges and source-linked static windows."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify(h):
    context=json.loads((HERE/'knowledge/native-contexts/clock-replays-11318.json').read_text('utf-8'))
    if h.sha!=SHA or context['source_sha256']!=SHA or hashlib.sha256(h.raw).hexdigest()!=SHA:
        raise ValueError('Clock replay source differs')
    expected=context['exports'];actual={Path(e['path']).parent.name:e['sha256'] for e in h.evidence}
    if actual!=expected:raise ValueError('Clock replay export set differs')
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    for function in h.fragments:shapes.normalize_function(native,h.image,function)
    for at,window in context['windows'].items():
        raw=bytes.fromhex(window['bytes']);offset=h.image.offset(int(at,16)-h.image.pe.base)
        if h.raw[offset:offset+len(raw)]!=raw or hashlib.sha256(raw).hexdigest()!=window['sha256']:
            raise ValueError('Clock replay source window differs')
    for at,encoded in context['tables'].items():
        raw=bytes.fromhex(encoded);offset=h.image.offset(int(at,16)-h.image.pe.base)
        if h.raw[offset:offset+len(raw)]!=raw:raise ValueError('Clock replay vtable differs')
