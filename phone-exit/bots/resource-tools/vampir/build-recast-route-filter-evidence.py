"""Pin caller argument roles, projection filter and scalar path-filter branch."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    module=load('route_filter_harness','recast-route-filter-emulator.py');emulator=module.RouteFilterBranchEmulator(root)
    rows={r['address']:r for f in emulator.route_fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x145688edc,'call','0x1454dedd0'),(0x145688ef9,'mov','qword ptr [rsp + 0x68], rcx'),
        (0x145689006,'call','0x1454dee80'),(0x145689021,'mov','qword ptr [rsp + 0x60], rcx'),
        (0x14568902d,'call','0x1454e07b0'),(0x14568904d,'lea','r8, [rcx + 8]'),
        (0x145689057,'lea','rdx, [rax + 8]'),(0x14568905b,'mov','rax, qword ptr [rsp + 0x68]'),
        (0x145689073,'lea','r9, [rax + 8]'),(0x1456890a0,'mov','qword ptr [rsp + 0x38], rdx'),
        (0x1456890a8,'mov','qword ptr [rsp + 0x30], r8'),(0x1456890b2,'mov','qword ptr [rsp + 0x28], r9'),
        (0x1456890bf,'call','0x14569bcf0'),(0x14569bd31,'mov','r13, qword ptr [rbp + 0x1f8]'),
        (0x14569bd3b,'mov','r14, qword ptr [rbp + 0x208]'),(0x14569bd4e,'mov','rax, qword ptr [rbp + 0x200]'),
        (0x14569bd55,'mov','qword ptr [rbp + 0x70], rax'),(0x14569be4f,'mov','r9, r14'),
        (0x14569be8e,'call','0x1452451b0'),(0x14569bef4,'mov','r9, r14'),(0x14569bf23,'call','0x1452451b0'),
        (0x14569bf90,'movsd','xmm0, qword ptr [rsi]'),(0x14569bf98,'subsd','xmm0, qword ptr [rbx]'),
        (0x14569bf9c,'movsd','xmm1, qword ptr [rsi + 8]'),(0x14569bfa8,'subsd','xmm1, qword ptr [rbx + 8]'),
        (0x14569bfc1,'mulsd','xmm0, xmm0'),(0x14569bfc9,'mulsd','xmm1, xmm1'),(0x14569bfd1,'addsd','xmm1, xmm0'),
        (0x14569bfdd,'comisd','xmm1, xmmword ptr [rip + 0x41db51b]'),
        (0x14569bfe5,'cmovb','r13, qword ptr [rbp + 0x70]'),(0x14569bfea,'mov','qword ptr [rsp + 0x30], r13'),
        (0x14569bffe,'call','0x1452457b0')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed route filter anchor '+hex(address))
        anchors.append(row)
    address=rows[0x14569bfdd]['rip_references'][0];offset=emulator.image.offset(address-emulator.image.pe.base);raw=emulator.data[offset:offset+8]
    if struct.unpack('<d',raw)[0]!=9000000.:raise ValueError('Changed XY selection threshold')
    threshold=dict(address=address,file_offset=offset,raw_hex=raw.hex(),value_squared_world_units=9000000.)
    selection_path=root/'code-clues/recast-filter-selection-evidence.json';selection_raw=selection_path.read_bytes();selection=json.loads(selection_raw)
    audit=json.loads((selection_path.parent/'recast-filter-selection-audit.json').read_bytes())
    if audit['source_report_sha256']!=sha(selection_raw) or selection['sha256']!=sha(emulator.data):raise ValueError('Changed constructor/wrapper selection proof')
    if selection['wrappers']!=dict(Default=0x1454dedd0,ShortPath=0x1454e07b0,ExcludeHiddenPath=0x1454dee80):raise ValueError('Changed filter field role')
    cases=[]
    pairs=[([0.,0.,0.],[x,0.,0.]) for x in [0.,1.,100.,math.nextafter(3000.,0.),3000.,math.nextafter(3000.,math.inf),4000.]]
    pairs += [([0.,0.,0.],[1800.,2400.,0.]),([0.,0.,0.],[1800.,math.nextafter(2400.,0.),0.]),
              ([100.,200.,300.],[3100.,200.,1000000.]),([100.,200.,300.],[100.,200.,1000000.]),
              ([0.,0.,0.],[-3000.,0.,0.]),([-10000.,-20000.,3.],[-8200.,-17600.,3.])]
    for start,end in pairs:
        result=emulator.select(start,end);dx=start[0]-end[0];dy=start[1]-end[1];distance=dy*dy+dx*dx
        if result['distance_squared_xy']!=distance or result['filter']!=('ShortPath' if distance<9000000. else 'Default'):raise ValueError('Native route filter branch mismatch')
        cases.append(dict(start=start,end=end,result=result))
    report=dict(source=selection['source'],sha256=sha(emulator.data),selection_proof_sha256=sha(selection_raw),
        emulator_sha256=sha((HERE/'recast-route-filter-emulator.py').read_bytes()),
        base_emulator_sha256=sha((HERE/'recast-portal-emulator.py').read_bytes()),
        fragments=emulator.route_fragments,anchors=anchors,threshold=threshold,native_pages=list(emulator.pages.values()),cases=cases,
        executed_range=dict(begin=module.BEGIN,end_before_call=module.END),
        caller_filter_arguments=dict(argument6='Default',argument7='ShortPath',argument8='ExcludeHiddenPath'),
        static_query_roles=dict(endpoint_calls_1452451b0='ExcludeHiddenPath',query_1452457b0='ShortPath below threshold, Default at/above threshold'),
        summary=dict(native_cases=len(cases),finite_XY_filter_branch_verified=True,path_search_executed=False,
            runtime_request_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Only the scalar XY filter-selection block executes; point projection and path search are pinned static callsites only.',
            'Distinct synthetic filter pointers expose argument selection; there are no live classes, query filters or navigation data.',
            'Finite synthetic world coordinates are bounded to abs<=1e9, not asserted to be the game coordinate limit. Physical units/metres are not inferred.',
            'The role mapping describes this exact caller/callee pair, not all route callers or the currently selected gameplay request.',
            'Callee symbols are not recovered here; role labels describe the preserved caller/argument flow, not a recovered C++ name.',
            'Active mesh/tile coverage, topology availability, runtime link conditions and real route traversability remain unverified.'])
    path=root/'code-clues/recast-route-filter-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],anchors=len(anchors),fragments=len(emulator.route_fragments),sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
