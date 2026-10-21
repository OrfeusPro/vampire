"""Whole current SetCountryCode with notification disabled, synthetic strings."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SETTER = 0x144552430
EVIDENCE_SHA = '5acdfa85c303bda2002ab56a5e84fb3938c862afa8a46a7dfba217576983804b'


def run():
    spec = importlib.util.spec_from_file_location('country_setter_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    compare, assign, free = 0x14145f2c0, 0x141441e40, 0x141483160
    hooks = dict.fromkeys((compare, assign, free))
    h = archive.make_harness(extra_addresses=(SETTER,), fixtures=hooks)
    evidence = h.comparison / 'details/run-784447667bfa/details.json'
    if h.audit.sha256(evidence) != EVIDENCE_SHA: raise ValueError('Country setter Ghidra evidence changed')
    uc, x = h.uc, h.x
    obj, incoming, old_text, new_text = [h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000)]
    destination = obj + 0x3f0
    sentinel = 0x148a1742c
    offset = h.image.offset(sentinel - h.image.pe.base)
    expected_literal = 'A1\0'.encode('utf-16le')
    if h.raw[offset:offset+len(expected_literal)] != expected_literal:
        raise ValueError('Country sentinel differs')
    # RIP-referenced pages are mapped by the existing source-pinned harness.
    uc.mem_write(0x14b5662e0, bytes(4))
    uc.mem_write(0x14b1890f4, bytes(1))
    events = []

    def text(pointer):
        for count in range(128):
            if bytes(uc.mem_read(pointer + count*2,2)) == bytes(2):
                return bytes(uc.mem_read(pointer,count*2)).decode('utf-16le')
        raise ValueError('Synthetic string bound')

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a,b = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result = 0
        if at == compare:
            if b != sentinel: raise ValueError('Unexpected sentinel comparator')
            result = int(text(a) != 'A1')
            events.append('compare_sentinel')
        elif at == assign:
            if (a,b) != (destination,incoming): raise ValueError('Country assignment destination differs')
            machine.mem_write(a,bytes(machine.mem_read(b,16)))
            result = a
            events.append('assignment_fixture')
        elif at == free:
            if a != new_text: raise ValueError('Unexpected FString cleanup')
            events.append('input_cleanup_fixture')
        else: raise ValueError('Unexpected fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,result)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    for at in hooks: hooks[at] = fixture

    cases = []
    # None denotes a zero-count FString; '' denotes a NUL FString with count 1.
    for old,new in ((None,'A1'),('','A1'),('JP','A1'),('HK','A1'),('A1','A1'),
                    ('JP','HK'),('HK','HK'),('','JP'),('JP',''),('JP',None),
                    (None,None),('Я','Ю'),('JP','A1x'),('JP','a1')):
        uc.mem_write(obj,b'\xa5'*0x700)
        def descriptor(pointer,value,string_pointer):
            if value is None:
                raw = bytes(16)
            else:
                encoded = (value+'\0').encode('utf-16le')
                uc.mem_write(string_pointer,encoded+bytes(256))
                count = len(encoded)//2
                raw = struct.pack('<QII',string_pointer,count,count)
            uc.mem_write(pointer,raw)
            return raw
        old_descriptor = descriptor(destination,old,old_text)
        new_descriptor = descriptor(incoming,new,new_text)
        before = bytes(uc.mem_read(obj,0x700))
        events.clear()
        h.call(SETTER,obj,incoming,0,budget=4096)
        after = bytes(uc.mem_read(obj,0x700))
        ignored = new == 'A1' and bool(old)
        if after[0x3f0:0x400] != (old_descriptor if ignored else new_descriptor):
            raise ValueError('Country setter preservation/assignment differs')
        if before[:0x3f0] != after[:0x3f0] or before[0x400:] != after[0x400:]:
            raise ValueError('Country setter touched city or neighboring fields')
        if bytes(uc.mem_read(incoming,16)) != new_descriptor:
            raise ValueError('Input descriptor changed')
        if events.count('assignment_fixture') != int(not ignored):
            raise ValueError('Country setter assignment branch differs')
        if events.count('input_cleanup_fixture') != int(new is not None):
            raise ValueError('Country setter input cleanup differs')
        cases.append(dict(old=old,new=new,ignored=ignored,notification=False,events=events.copy()))
    report = dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),
        evidence_sha256=EVIDENCE_SHA, setter=hex(SETTER),destination_settings_offset=0x3f0,
        sentinel=dict(address=hex(sentinel),text='A1',bytes=expected_literal.hex()),
        cases=cases,fragments=h.fragments,native_execution=True,network_used=False,
        limits=['Whole current SetCountryCode executes with diagnostic logging disabled and notify flag 0, as in the observed GMC2 caller.',
            'FString comparison, assignment and cleanup are explicit synthetic fixtures; native allocation/free backend is not proved.',
            'Notification-enabled branch, generic JSON helpers, HTTP acceptance, full callback and whole writer/collector are not executed.',
            'No real country/IP/account values or live game session.'])
    return h,report


def main():
    h,report = run()
    target = h.audit.save_snapshot(h.comparison / 'country-setter-replay',report)
    print(json.dumps(dict(report=str(target),sha256=h.audit.sha256(target),cases=len(report['cases']))))


if __name__ == '__main__': main()
