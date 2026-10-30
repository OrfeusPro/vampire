"""Native Login reader and handler use one packet, with coordinator-controlled gating."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def native_method(wire_kind, offset):
    """Wire u64 includes native time wrappers that read through a stack value."""
    if wire_kind == 'u64':
        if offset in (0x58, 0xb0, 0xf0, 0x100, 0x110, 0x120): return 'time'
        if offset in (0x68, 0x80): return 'u64'
        raise ValueError('Composition u64/time field offset differs')
    if wire_kind == 'raw32': return 'u32'
    if wire_kind not in ('u32', 'u16', 'bool', 'string'):
        raise ValueError('Composition wire field kind differs')
    return wire_kind


def logical_entry_matches(method, destination, wire_kind, offset, packet):
    return method == native_method(wire_kind, offset) and destination == packet+offset


class ProtectedMemory:
    """Reject both native and fixture writes to reader-owned memory after reading."""
    def __init__(self, native): self.native, self.ranges = native, []
    def __getattr__(self, name): return getattr(self.native, name)
    def protect(self, ranges):
        if any(type(at) is not int or type(size) is not int or at < 0 or size <= 0 for at, size in ranges):
            raise ValueError('Composition protected memory range differs')
        self.ranges = [(at, at+size) for at, size in ranges]
    def writable(self, at, size):
        if size == 0: return
        if any(at < end and at+size > start for start, end in self.ranges):
            raise ValueError('Composition handler writes or reseeds reader-owned memory')
    def mem_write(self, at, data):
        self.writable(at, len(data)); return self.native.mem_write(at, data)


def verify(context, root):
    core = load('portable-native-family')
    reader = core.checked(Path(root), context['reader_context'], 'generated-native-contexts')
    handler = core.checked(Path(root), context['handler_context'], 'generated-native-contexts')
    gate = core.checked(Path(root), handler['gate_context'], 'generated-native-contexts')
    roots = {int(at, 16) for at in context['functions'].values()}
    h = load('verify-login-composition-harness').make_harness(context, context['exports'], roots,
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    h.uc = ProtectedMemory(h.uc)
    contract = load('login-composition-case-contracts')
    require_order = load('verify-login-nested-context').ORDER
    if contract.canonical(require_order) != contract.canonical(contract.ORDER):
        raise ValueError('Composition wire order differs from the checked reader')
    packet, archive, buffer, heap = [h.scratch+off for off in (0x1000, 0x2000, 0x5000, 0x10000)]
    functions = {name: int(at, 16) for name, at in reader['functions'].items()}
    methods = {name: int(at, 16) for name, at in reader['input']['functions'].items()}
    table = int(reader['input']['table'], 16)
    state, phase, observed = {}, {'value': 'prepare'}, {}
    uc, x = h.uc, h.x
    import unicorn

    def require(ok, message):
        if not ok: raise ValueError(message)
    def reg(name): return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))
    def position():
        value = int.from_bytes(uc.mem_read(archive+0x30, 8), 'little')-buffer
        require(0 <= value <= len(state['body']), 'Composition native cursor bound')
        return value
    def empty(machine):
        require(phase['value'] == 'prepare' and reg('RCX') == packet+0x140, 'Composition trailing constructor receiver differs')
        uc.mem_write(packet+0x140, bytes(16)); h.finish(packet+0x140)

    copy_at = int(context['helpers']['memcpy'], 16)
    copy_fixture = h.fixtures[copy_at]
    def guarded_copy(machine):
        uc.writable(reg('RCX'), reg('R8')); copy_fixture(machine)
    h.fixtures[copy_at] = guarded_copy
    h.add_fixture(int(reader['string_constructor'], 16), empty)
    load('login-result-string-fixtures').install(load, h, reader['input'], state, packet,
        [at for kind, at in contract.ORDER if kind == 'string'])
    reader_hooks = dict(h.fixtures)
    h.fixtures.clear(); h.fixtures[copy_at] = guarded_copy
    invoke_handler = load('login-composition-handler-fixtures').install(load, h, handler, gate, packet)
    handler_hooks = dict(h.fixtures)
    h.fixtures.clear(); h.fixtures.update(reader_hooks)
    abi = {name: 0xfedcba9876543210+i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i): 0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    packet_offsets = {at for _, at in contract.ORDER}
    targets = {methods[role]: role for role in ('u16', 'u32', 'u64', 'time', 'bool', 'string')}

    def trace(machine, at, size, unused):
        if phase['value'] == 'reader':
            if at == functions['reader']:
                require(not observed['reader_entries'] and reg('RCX') == packet, 'Composition reader entry pointer differs')
                observed['reader_entries'].append(reg('RCX'))
            if at in targets and reg('RDX')-packet in packet_offsets:
                count = len(observed['operations'])
                require(count < len(contract.ORDER) and reg('RCX') == archive, 'Composition logical input count/receiver differs')
                kind, offset = contract.ORDER[count]
                require(logical_entry_matches(targets[at], reg('RDX'), kind, offset, packet),
                    'Composition logical input kind/destination/order differs')
                observed['operations'].append([kind, hex(offset)])
        elif phase['value'] == 'handler' and at == int(handler['functions']['handler'], 16):
            require(not observed['handler_entries'] and reg('R8') == packet, 'Composition handler entry pointer differs')
            observed['handler_entries'].append(reg('R8'))
    uc.hook_add(unicorn.UC_HOOK_CODE, trace)
    def writes(machine, access, at, size, value, unused): uc.writable(at, size)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, writes)

    def guarded_call(at, receiver, budget=30000):
        for name, value in abi.items(): uc.reg_write(getattr(x, 'UC_X86_REG_'+name), value)
        result = h.call(at, receiver, budget=budget)
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch+0x38008,
            'Composition constructor/reader ABI differs')
        return result

    def check_reader_guards(before, archive_before, body):
        after = bytes(uc.mem_read(packet, 352))
        mutable = {i for kind, at in contract.ORDER for i in range(at, at+contract.WIDTH[kind])}
        require(all(a == b for i, (a,b) in enumerate(zip(before,after)) if i not in mutable), 'Composition reader modified padding/vptrs')
        require(bytes(uc.mem_read(packet-16, 16)) == b'\xa5'*16 and bytes(uc.mem_read(packet+352, 16)) == b'\xa6'*16,
            'Composition packet canaries differ')
        archive_after = bytes(uc.mem_read(archive-16, 96)); mutable = set(range(0x20,0x24)) | set(range(0x40,0x48))
        require(all(a == b for i, (a,b) in enumerate(zip(archive_before, archive_after)) if i not in mutable), 'Composition archive wrote outside cursor/bookkeeping')
        require(bytes(uc.mem_read(buffer-16,len(body)+32)) == b'\xa5'*16+body+b'\xa6'*16, 'Composition reader changed source buffer')
        for at,size in state['allocations'].items():
            require(bytes(uc.mem_read(at-16,16)) == b'\xa5'*16 and bytes(uc.mem_read(at+size,16)) == b'\xa6'*16,
                'Composition input allocation canary differs')

    def run(spec):
        scenario = spec['scenario']; body, values, _ = contract.encode(scenario)
        if spec['kind'] == 'truncated': body = body[:spec['cut']]
        elif spec['kind'] == 'trailing': body += bytes.fromhex(spec['tail_hex'])
        poison = scenario.get('poison', 0x55)
        uc.protect([]); phase['value'] = 'prepare'
        h.fixtures.clear(); h.fixtures.update(reader_hooks)
        state.clear(); state.update(body=body, heap=heap, allocations={}, strings={})
        observed.clear(); observed.update(operations=[], reader_entries=[], handler_entries=[])
        uc.mem_write(h.scratch+0x30000, bytes(0x8000))
        uc.mem_write(packet-16,b'\xa5'*16+bytes([poison])*352+b'\xa6'*16)
        require(guarded_call(functions['constructor'],packet) == packet, 'Composition packet constructor return differs')
        before = bytes(uc.mem_read(packet,352))
        uc.mem_write(archive-16,b'\xa5'*16+bytes([poison])*64+b'\xa6'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.reg_write(x.UC_X86_REG_RDX,buffer); uc.reg_write(x.UC_X86_REG_R8,len(body)); uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,struct.pack('<Q',0))
        require(guarded_call(methods['constructor'],archive) == archive, 'Composition buffer constructor return differs')
        require(bytes(uc.mem_read(archive,8)) == struct.pack('<Q',table)
            and bytes(uc.mem_read(archive+0x20,12)) == struct.pack('<QI',buffer,len(body)) and position()==0,
            'Composition native buffer binding differs')
        archive_before = bytes(uc.mem_read(archive-16,96))
        uc.reg_write(x.UC_X86_REG_RDX,archive); phase['value'] = 'reader'
        returned = guarded_call(functions['reader'],packet,budget=1000000)&255
        phase['value'] = 'prepare'; check_reader_guards(before,archive_before,body)
        require(observed['reader_entries'] == [packet], 'Composition whole reader did not execute once')
        read = dict(returned=returned,size=len(body),consumed=position(),operations=list(observed['operations']),guards=True,abi=True,
            scalar_values={},strings={})
        source_strings = []
        if returned:
            for kind,offset in contract.ORDER:
                if kind == 'string':
                    pointer,count,capacity = struct.unpack('<QII',bytes(uc.mem_read(packet+offset,16)))
                    require(count == capacity and 0 <= count <= 1024, 'Composition FString descriptor differs')
                    raw = bytes(uc.mem_read(pointer,count*2)) if count else b''
                    value = raw[:-2].decode('utf-16le') if count else ''
                    require(not count or raw.endswith(b'\0\0'), 'Composition FString terminator differs')
                    read['strings'][hex(offset)] = value
                    if count: source_strings.append((pointer,raw))
                else:
                    read['scalar_values'][hex(offset)] = int.from_bytes(uc.mem_read(packet+offset,contract.WIDTH[kind]),'little')
            expected = contract.expected_case(spec)['reader']
            require(contract.canonical(read) == contract.canonical(expected), 'Composition reader projection/matrix differs')
        else:
            require(spec['kind'] == 'truncated', 'Composition valid body rejected')
        require(state['heap'] <= h.scratch+0x28000, 'Composition reader allocation overlaps handler fixture storage')
        packet_before = bytes(uc.mem_read(packet-16,384)); archive_read = bytes(uc.mem_read(archive-16,96))
        regions = [(packet-16,384),(archive-16,96),(buffer-16,len(body)+32)]
        regions += [(at-16,size+32) for at,size in state['allocations'].items()]
        uc.protect(regions)
        handler_row = None
        if returned:
            h.fixtures.clear(); h.fixtures.update(handler_hooks); phase['value'] = 'handler'
            handler_row = invoke_handler(scenario)
        phase['value'] = 'prepare'
        require(bytes(uc.mem_read(packet-16,384)) == packet_before, 'Composition handler changed the reader packet')
        require(bytes(uc.mem_read(archive-16,96)) == archive_read, 'Composition handler changed the reader cursor/archive')
        require(bytes(uc.mem_read(buffer-16,len(body)+32)) == b'\xa5'*16+body+b'\xa6'*16, 'Composition handler changed the body')
        require(all(bytes(uc.mem_read(at,len(data))) == data for at,data in source_strings), 'Composition handler changed a decoded source string')
        check_reader_guards(before,archive_before,body)
        require(observed['handler_entries'] == ([packet] if returned else []), 'Composition handler invocation gate differs')
        return dict(spec=spec,reader=read,handler=handler_row,handler_invoked=bool(returned),same_packet_pointer=bool(returned),
            packet_reseeded=False,source_buffers_unchanged=True,packet_unchanged_by_handler=True,
            archive_unchanged_by_handler=True,guards=True,abi=True)

    cases = [run(spec) for spec in contract.scenarios()]
    result = dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',packet_bytes=352,
        cases=cases,operations=contract.ORDER,runtime=load('update-native-harness').runtime_inputs(),evidence=h.evidence,
        network_used=False,profile_activated=False,runtime_activated=False,native_dispatch_used=False,
        native_post_state_used=False,native_continuation_used=False,session_executed=False,
        same_packet_reader_used=True,native_handler_used=True,native_gate_used=True,native_strings=True,
        native_buffer_construction=True,native_scalars_used=True,native_nested_used=True,
        limits=['One native reader and handler use the same packet and decoded allocations; coordinator gates the direct handler call after reader AL success.',
            'No native dispatch, registration owner/window, real services, post-state/continuation integration or online session.',
            'Storage/growth/assignment/free/security, SDK/UI/clock/persistence and handler services remain explicit bounded fixtures.'])
    contract.validate_report(result,context)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));args=parser.parse_args()
    context=json.loads(args.context.read_text('utf-8'));result=verify(context,args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest())
    path=load('research-workflow').snapshot(args.root,'native-login-composition-checks',result)
    print(json.dumps(dict(report=str(path),cases=len(result['cases']))))
