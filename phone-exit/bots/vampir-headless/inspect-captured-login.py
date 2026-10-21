"""Offline CRC-checked Login shape report. No auth values or packet replay."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'vampir-shared'))
from vampir_core.frame_primitives import xor_transform,payload_crc32
from vampir_core.login_packet import decode_login_payload
from vampir_core.nid_metadata import NID_METADATA_KEYS, encode_nid_metadata_with_device_key


def inspect(path, *, flow, expected_sha256, _consume_frame=None):
    # Optional trusted in-memory analysis; raw bodies never enter this report.
    if _consume_frame is not None and not callable(_consume_frame):raise TypeError('Expected frame consumer')
    with Path(path).open('rb') as stream: raw=stream.read(12582913)
    if len(raw)>12582912 or not raw.endswith(b'\n'): raise ValueError('Capture bounds')
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=expected_sha256: raise ValueError('Capture SHA differs')
    # Run capture-inspect.js first for complete JSONL/flow/offset validation.
    records=[json.loads(line) for line in raw.decode('utf-8').splitlines()]
    selected=[r for r in records if r.get('flow')==flow and r.get('direction')=='c2s' and r.get('type')=='data']
    data=b''.join(base64.b64decode(r['data'],validate=True) for r in selected)
    logins=[];checked=0
    while data:
        size=int.from_bytes(data[:3],'little')
        if not 11<=size<=min(len(data),1048576): raise ValueError('Incomplete send frame')
        plain=xor_transform(data[3:size]);data=data[size:]
        if int.from_bytes(plain[:4],'little')!=payload_crc32(plain[4:]):raise ValueError('CRC or unsupported changed key')
        checked+=1
        if _consume_frame is not None:_consume_frame(int.from_bytes(plain[4:6],'little'),plain[8:])
        if int.from_bytes(plain[4:6],'little')!=3:continue
        body=plain[8:];value=decode_login_payload(body,max_payload_size=65536)
        if value.encode(max_payload_size=65536)!=body:raise ValueError('Login roundtrip differs')
        logins.append(value)
    if len(logins)!=1:raise ValueError('Exactly one Login required')
    value=logins[0]
    offsets=('10','20','30','40','58','68','78','88','a0','b8','c8','d8','e8','100','110')
    allowed=set(NID_METADATA_KEYS)|{'I_DeviceKey','I_LogDes'}
    pairs=json.loads(value.strings[11],object_pairs_hook=list) if value.strings[11] else []
    metadata=[]
    for key,item in pairs:
        metadata.append(dict(key=key if key in allowed else '<unknown>',
            utf8_bytes=len(item.encode('utf-8')) if type(item) is str else None,empty=not item))
    metadata_roundtrip = None
    if any(key == 'I_DeviceKey' for key,item in pairs):
        try:
            fields = dict(pairs)
            metadata_roundtrip = encode_nid_metadata_with_device_key(fields,
                device_key=fields['I_DeviceKey'], user_info_available=True) == value.strings[11]
        except (ValueError,TypeError): metadata_roundtrip = False
    return dict(capture_sha256=digest,flow=flow,checked_c2s_frames=checked,
        login_body_bytes=len(value.encode(max_payload_size=65536)),
        strings=[dict(offset='0x'+offset,utf8_bytes=len(s.encode('utf-8')),empty=not s)
            for offset,s in zip(offsets,value.strings)],integers=value.integers,raw_bytes=value.raw_bytes,
        raw128_zero=value.raw_128==0,metadata=metadata,metadata_device_key_roundtrip=metadata_roundtrip,
        initial_builder_shape_comparison=dict(metadata_empty_matches=not value.strings[11],
            raw_bytes_match=value.raw_bytes==(3,3,7,0,0),
            trailing_integers_match=value.integers[2:]==(207,1),raw128_zero_matches=value.raw_128==0),
        credentials_saved=False,network_used=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('capture',type=Path)
    parser.add_argument('--flow',type=int,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        result=inspect(args.capture,flow=args.flow,expected_sha256=args.sha256)
        with args.output.open('x',encoding='utf-8') as stream:stream.write(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(report=str(args.output),sha256=hashlib.sha256(args.output.read_bytes()).hexdigest())))
    except (ValueError,OSError,KeyError,TypeError):
        print(json.dumps(dict(status='capture_login_not_inspected')));sys.exit(2)
