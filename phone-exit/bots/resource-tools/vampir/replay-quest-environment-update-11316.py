"""Whole environment writer/retry and quest readiness, with explicit engine fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(context_name='quest-environment-update-11316.json'):
    if context_name not in ('quest-environment-update-11316.json','quest-environment-world-handler-11316.json'):
        raise ValueError('Explicit environment context required')
    path = HERE / 'knowledge/native-contexts' / context_name
    context = json.loads(path.read_text('utf-8'))
    h = load('native-request-harness-11316').make_harness(
        context['exports'], {int(v, 16) for v in context['functions']},
        leaves={int(a, 16):b for a, b in context['leaves'].items()})
    index = load('knowledge-index')
    legacy = []
    for f in h.fragments:
        if not f.get('block_coverage_complete') or index.missing_conditional_fallthroughs(f['instructions']):
            raise ValueError('Environment writer coverage incomplete')
        if f.get('direct_flow_coverage_complete') is not True:
            if f.get('direct_flow_coverage_complete') is not None or f['address'] not in context['legacy_direct_flow']:
                raise ValueError('Environment writer direct flow incomplete')
            legacy.append(f['address'])
    if h.sha != context['source_sha256']:
        raise ValueError('Environment writer source changed')
    uc, x, base = h.uc, h.x, h.scratch
    environment, task, record, data, model, world, text = [base+n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    world_table, guard_entry = base+0xe000, base+0xf000
    callback_payload, travel_context = base+0x1a000, base+0x1b000
    settings, services, listeners, other_service, other_table, input_packet, receiver_table = [base+n for n in
        (0x1d000, 0x1e000, 0x1f000, 0x21000, 0x22000, 0x23000, 0x2a000)]
    global_object, object_class, expected_class, parents, owner, token = [base+n for n in
        (0x10000, 0x14000, 0x15000, 0x16000, 0x17000, 0x18000)]
    current, calls = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (8*size))).to_bytes(size, 'little'))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def source(at):
        off = h.image.offset(at-h.image.pe.base)
        return int.from_bytes(h.raw[off:off+8], 'little')

    for slot, target in ((0x10, 0x14560e670), (0x70, 0x14561bca0),
                         (0xb8, 0x1418af880), (0xc8, 0x14144e120)):
        if source(0x149909370+slot) != target:
            raise ValueError('Environment table binding changed')

    def registration(machine):
        if reg('RCX') != environment+0x28:
            raise ValueError('Environment registration receiver')
        h.finish(reg('RCX'))

    def format_text(machine):
        template = reg('RDX')
        if template in (0x1499099f0, 0x149909e30):
            if reg('R8') & 0xffffffff != current['formatted']:
                raise ValueError('Environment formatting argument')
            calls.append('format')
        elif template == 0x149909ae0:
            before, after = current['phase_entries'][-1]
            if reg('R8') & 255 != before or reg('R9') & 255 != after:
                raise ValueError('Native phase diagnostic arguments')
        elif template not in (0x1489f18ac, 0x1496455f0):
            raise ValueError('Unexpected phase diagnostic template')
        uc.mem_write(reg('RCX'), bytes(16))
        h.finish(reg('RCX'))

    def phase_request(machine):
        if reg('RCX') != environment or reg('RDX') & 255 not in context['phase_values']:
            raise ValueError('Environment phase request scope')
        if get(reg('R8')) != 0:
            raise ValueError('Environment phase diagnostic fixture')
        current['phase_entries'].append((get(environment+0x30, 1), reg('RDX') & 255))
        calls.append('phase:'+str(reg('RDX') & 255))

    def append_empty(machine):
        if reg('R8') & 0xffffffff or get(reg('RCX')):
            raise ValueError('Phase empty diagnostic append')
        h.finish(reg('RCX'))

    def diagnostic_object(machine):
        uc.mem_write(reg('RCX'), bytes(0x90)); h.finish(reg('RCX'))

    def diagnostic_sink(machine):
        if reg('RCX') != 3 or reg('RDX') != 0:
            raise ValueError('Phase diagnostic sink arguments')
        h.finish()

    def phase_notify(machine):
        if reg('RCX') != base+0x19000 or get(reg('RDX')):
            raise ValueError('Phase notify arguments')
        if get(environment+0x30, 1) != current['phase_entries'][-1][1]:
            raise ValueError('Phase notification occurred before actual state write')
        current['phase_notifications'] += 1; h.finish()

    def convert_text(machine):
        uc.mem_write(reg('RCX'), bytes(32)); calls.append('convert'); h.finish(reg('RCX'))

    def class_get(machine):
        calls.append('object-class'); h.finish(expected_class)

    def fallback_get(machine):
        calls.append('fallback')
        h.finish(0 if current['lookup']=='fallback-missing' else token)

    def resolve_context(machine):
        if reg('RCX') != token:
            raise ValueError('Environment context resolution input')
        calls.append('resolve')
        h.finish(0 if current['lookup']=='resolve-missing' else owner)

    def guard(machine):
        if reg('RCX') != world:
            raise ValueError('Environment guard receiver')
        calls.append('guard'); h.finish(int(current['guard']=='allow'))

    def string_init(machine):
        uc.mem_write(reg('RCX'), bytes(16)); h.finish(reg('RCX'))

    def callback_sink(machine):
        if get(reg('RCX')) != 0x145606830 or reg('XMM2') != 0 or reg('R9') != 0x14b5912e8:
            raise ValueError('Environment callback submission differs')
        payload = bytes(uc.mem_read(reg('RCX')+0x28, 16))
        if payload != bytes(16) or current['queued_callback'] is not None:
            raise ValueError('Environment callback capture/queue differs')
        current['queued_callback'] = (get(reg('RCX')), payload)
        # Explicit moved-callback fixture. Execution occurs after the writer returns.
        calls.append('callback'); put(reg('RCX'), 0); h.finish()

    def callback_context(machine):
        calls.append('callback-context'); h.finish(token)

    def callback_guard(machine):
        if reg('RCX') != world:
            raise ValueError('Callback guard receiver')
        calls.append('callback-guard'); h.finish(int(current['travel_can']))

    def callback_engine(machine):
        if reg('RCX') != get(0x14b559008) or reg('RDX') != owner:
            raise ValueError('Callback engine context arguments')
        calls.append('callback-engine'); h.finish(travel_context)

    def callback_copy(machine):
        if reg('RCX') != owner+0x738 or reg('RDX') != callback_payload or get(callback_payload):
            raise ValueError('Callback string assignment arguments')
        uc.mem_write(owner+0x738, bytes(16)); calls.append('callback-copy'); h.finish(reg('RCX'))

    def callback_process(machine):
        if reg('RCX') != world or reg('RDX') != callback_payload or reg('R8') & 255:
            raise ValueError('Callback process forwarding differs')
        if get(owner+0x731, 1) != 2:
            raise ValueError('Callback dispatch before context state write')
        calls.append('callback-process'); h.finish()

    def receiver_branch(machine):
        if reg('RCX') != environment:
            raise ValueError('Receiver branch predicate scope')
        h.finish(1)

    def receiver_notice(machine):
        if reg('RCX') != other_service or reg('RDX') & 0xffffffff != current['old_kind'] or reg('R8') & 255 != 2:
            raise ValueError('Receiver previous-context notification differs')
        current['receiver_notices'] += 1; h.finish()

    def receiver_pending(machine):
        if reg('RCX') & 0xffffffff != current['requested']:
            raise ValueError('Receiver pending selection argument differs')
        current['selected_pending'].append(reg('RCX') & 0xffffffff); h.finish()

    def receiver_old_context(machine):
        if reg('RCX') != services+0x348 or reg('RDX') & 0xffffffff != current['old_kind']:
            raise ValueError('Receiver old-context dispatch differs')
        current['old_context_notices'] += 1; h.finish()

    def model_lookup(machine):
        if reg('RCX') != model or reg('RDX') != 110120:
            raise ValueError('Environment readiness model scope')
        h.finish(record)

    def unexpected_free(machine):
        raise ValueError('Empty-string fixture unexpectedly freed memory')

    callbacks = {0x144286f50:registration, 0x141433340:format_text,
        0x14566d560:convert_text,
        0x143befc30:class_get, 0x1445c32b0:fallback_get, 0x143c1bac0:resolve_context,
        guard_entry:guard, 0x141426b30:string_init, 0x144a78160:callback_sink,
        0x141426950:string_init, 0x14142b620:string_init, 0x141429e10:append_empty,
        0x14143ae20:diagnostic_object, 0x144403310:diagnostic_sink,
        0x14563dd30:lambda machine:h.finish(base+0x19000), 0x145639100:phase_notify,
        0x145490870:callback_context, base+0xf100:callback_guard, base+0xf200:callback_process,
        0x1442ba3a0:callback_engine, 0x141441d60:callback_copy,
        0x14563dd10:lambda machine:h.finish(settings), 0x1454e6500:lambda machine:h.finish(services),
        0x145594de0:lambda machine:h.finish(listeners), 0x14560ad60:lambda machine:h.finish(other_service),
        base+0xf300:receiver_branch, base+0xf400:receiver_notice,
        0x145e0f840:receiver_pending, 0x14230ae00:receiver_old_context,
        0x1455bbcb0:model_lookup, 0x141483080:unexpected_free,
        0x1487e8ce0:lambda machine:h.finish(reg('RAX'))}
    for at, callback in callbacks.items():
        h.add_fixture(at, callback)
    binding = load('quest-world-handler-binding-11316').install(h) if context.get('handler_binding') else None
    import unicorn
    uc.hook_add(unicorn.UC_HOOK_CODE, lambda machine, at, size, user:calls.append('world'),
        begin=0x1445d2a20, end=0x1445d2a20)
    uc.hook_add(unicorn.UC_HOOK_CODE, lambda machine, at, size, user:phase_request(machine),
        begin=0x145618b30, end=0x145618b30)
    uc.hook_add(unicorn.UC_HOOK_CODE,
        lambda machine, at, size, user:current.update(pending_at_writer=get(environment+0x44, 4)),
        begin=0x14560f9e0, end=0x14560f9e0)

    def setup_lookup(mode):
        current['lookup'] = mode
        uc.mem_write(global_object, bytes(0x1300))
        uc.mem_write(object_class, bytes(0x80)); uc.mem_write(expected_class, bytes(0x80))
        uc.mem_write(parents, bytes(0x80)); uc.mem_write(owner, bytes(0x800))
        put(0x14b559008, 0 if mode in ('fallback', 'fallback-missing') else global_object)
        put(global_object+0x10, object_class); put(global_object+0x11f8, token)
        put(object_class+0x38, 1 if mode=='wrong-depth' else 2, 4)
        put(expected_class+0x38, 2, 4); put(object_class+0x30, parents)
        put(parents+16, 0 if mode=='wrong-parent' else expected_class+0x30)
        put(owner+0x158, 0 if mode=='owner-empty' else world)

    def setup(old, requested, flag, phase, guard_mode):
        current.clear(); current.update(requested=requested, guard=guard_mode, formatted=requested if flag else old)
        current.update(phase_entries=[], phase_notifications=0, queued_callback=None, travel_can=True)
        current.update(old_kind=old, receiver_notices=0, selected_pending=[], old_context_notices=0, pending_at_writer=None)
        calls.clear(); uc.mem_write(environment, bytes(0x200))
        if h.call(0x1456001d0, environment) != environment:
            raise ValueError('Environment constructor return')
        h.call(0x14560e670, environment)
        put(environment+0x40, old, 4); put(environment+0x44, requested, 4)
        put(environment+0xc1, flag, 1); put(environment+0x30, phase, 1)
        put(world, world_table); put(world_table+0x7b8, guard_entry)
        put(world_table+0x7f8, base+0xf100); put(world_table+0x800, base+0xf200)
        setup_lookup('fallback-missing' if guard_mode=='missing' else 'global')
        uc.mem_write(callback_payload, bytes(16)); uc.mem_write(travel_context, bytes(0x100))
        uc.mem_write(token, bytes(0x200))
        put(owner+0x731, 0xa5, 1); put(owner+0x718, 0x12345678, 4)
        uc.mem_write(text, bytes(16)); put(0x14b5e4d60, model)
        uc.mem_write(record, bytes(0x60)); uc.mem_write(task, bytes(0x60))
        uc.mem_write(data, bytes(0x60))
        put(record+0x30, task); put(task+0x40, data); put(data+0x14, requested, 4)

    cases = []
    for path_name in ('direct', 'retry'):
      for guard_mode in ('missing', 'deny', 'allow'):
       for old in (0, 5):
        for requested in (0, 1, 0xffffffff):
            setup(old, requested, 1, 7, guard_mode)
            if path_name=='direct':put(environment+0xc1,0,1)
            immutable = [(a, bytes(uc.mem_read(a, 0x60))) for a in (record, task, data)]
            before = h.call(0x14568cad0, 110120) & 255
            if path_name == 'direct':
                uc.reg_write(x.UC_X86_REG_RDX, requested)
                uc.reg_write(x.UC_X86_REG_R8, text)
                h.call(0x14560f9e0, environment)
            elif h.call(source(0x149909370+0x70), environment) != 0:
                raise ValueError('Environment retry return changed')
            after = h.call(0x14568cad0, 110120) & 255
            allowed = guard_mode == 'allow'
            expected = requested if allowed else old
            if get(environment+0x40, 4) != expected or get(environment+0x44, 4) != (0 if allowed else requested):
                raise ValueError('Environment committed/pending fields differ')
            if before != int(old==requested) or after != int(expected==requested):
                raise ValueError('Environment writer/readiness linkage differs')
            if get(environment+0xc1, 1) != int(path_name=='retry' or not allowed) or calls.count('callback') != int(allowed):
                raise ValueError('Environment deferred flag/callback differs')
            if calls.count('phase:3') != 1 or calls.count('phase:5'):
                raise ValueError('Environment writer phase submission differs')
            if get(environment+0x30, 1) != 3 or current['phase_notifications'] != 1:
                raise ValueError('Native writer phase state/notification differs')
            callback_al = None
            if allowed:
                callback_address, payload = current['queued_callback']
                uc.mem_write(callback_payload, payload)
                before_callback = bytes(uc.mem_read(environment, 0x200))
                callback_al = h.call(callback_address, callback_payload) & 255
                if callback_al != 1 or get(owner+0x731, 1) != 2 or calls.count('callback-process') != 1:
                    raise ValueError('Captured native callback application differs')
                if bytes(uc.mem_read(environment, 0x200)) != before_callback:
                    raise ValueError('Callback unexpectedly advanced environment state')
            elif current['queued_callback'] is not None:
                raise ValueError('Refused environment writer queued a callback')
            if any(bytes(uc.mem_read(a, len(value))) != value for a, value in immutable):
                raise ValueError('Environment writer changed task/model inputs')
            cases.append(dict(path=path_name, guard=guard_mode, old=old, requested=requested,
                actual=get(environment+0x40, 4), pending=get(environment+0x44, 4), flag_c1=get(environment+0xc1,1),
                ready_before=bool(before), ready_after=bool(after), phase_after=get(environment+0x30, 1),
                phase_notifications=current['phase_notifications'], callback_al=callback_al, calls=calls.copy()))
    for old in (0, 5):
      for phase in (0, 2, 3, 4, 5, 7):
        setup(old, 1, 0, phase, 'allow')
        result = h.call(source(0x149909370+0x70), environment)
        selected = phase in (2, 3, 4)
        if result != int(selected) or get(environment+0x40, 4) != old or get(environment+0x44, 4) != 1:
            raise ValueError('Environment non-retry phase branch differs')
        if calls != (['format', 'phase:5'] if selected else []):
            raise ValueError('Environment non-retry performed unexpected work')
        if get(environment+0x30, 1) != (5 if selected else phase) or current['phase_notifications'] != int(selected):
            raise ValueError('Native non-retry phase state/notification differs')
        cases.append(dict(path='phase', old=old, phase=phase, result=result,
            phase_after=get(environment+0x30, 1), phase_notifications=current['phase_notifications'], calls=calls.copy()))
    lookup_cases = []
    for mode in ('global', 'fallback', 'wrong-depth', 'wrong-parent', 'fallback-missing',
                 'resolve-missing', 'owner-empty', 'explicit-owner', 'explicit-empty'):
        setup(0, 1, 0, 7, 'allow'); setup_lookup('owner-empty' if mode=='explicit-empty' else mode)
        calls.clear()
        actual = h.call(0x1445d2a20, owner if mode.startswith('explicit-') else 0)
        expected = 0 if mode in ('fallback-missing', 'resolve-missing', 'owner-empty', 'explicit-empty') else world
        expected_calls = ['world']
        if not mode.startswith('explicit-'):
            if mode not in ('fallback', 'fallback-missing'):expected_calls.append('object-class')
            if mode in ('fallback', 'fallback-missing', 'wrong-depth', 'wrong-parent'):expected_calls.append('fallback')
            if mode!='fallback-missing':expected_calls.append('resolve')
        if actual!=expected or calls!=expected_calls:
            raise ValueError('Native environment object lookup differs: '+repr((mode, actual, calls)))
        lookup_cases.append(dict(mode=mode, found=bool(actual), calls=calls.copy()))
    phase_cases = []
    for previous in (0, 7):
      for phase in context['phase_values']:
        setup(0, 1, 0, previous, 'allow'); calls.clear()
        expected = bytearray(uc.mem_read(environment, 0x200)); expected[0x30] = phase
        # Deliberately dirty upper bits: the native interface uses DL only.
        uc.reg_write(x.UC_X86_REG_RDX, 0x12340000 | phase)
        uc.reg_write(x.UC_X86_REG_R8, text)
        h.call(0x145618b30, environment)
        if bytes(uc.mem_read(environment, 0x200)) != expected or current['phase_notifications'] != 1:
            raise ValueError('Native phase handler write footprint/notification differs')
        if current['phase_entries'] != [(previous, phase)] or calls != ['phase:'+str(phase)]:
            raise ValueError('Native phase diagnostic observation differs')
        phase_cases.append(dict(previous=previous, phase=phase, phase_after=get(environment+0x30, 1),
            notifications=current['phase_notifications']))
    callback_cases = []
    for present in (False, True):
     for can in (False, True):
      for count in (0, 1, 2):
       for external_flag in (0, 1):
        setup(0, 1, 0, 7, 'allow'); current['travel_can'] = can
        put(owner+0x158, world if present else 0); put(travel_context+0x80, external_flag, 1)
        put(owner+0x738, base+0x1c000 if count else 0); put(owner+0x740, count, 4)
        put(owner+0x744, count, 4)
        uc.mem_write(base+0x1c000, bytes(4) if count<2 else b'X\x00\x00\x00')
        context_before = bytearray(uc.mem_read(owner, 0x800))
        environment_before = bytes(uc.mem_read(environment, 0x200)); calls.clear()
        result = h.call(0x145606830, callback_payload) & 255
        accepted = not present or can
        copied = accepted and count<2 and not external_flag
        if accepted:context_before[0x731] = 2
        if copied:
            context_before[0x738:0x748] = bytes(16)
            if not present:context_before[0x718:0x71c] = bytes(4)
        if result != int(accepted) or bytes(uc.mem_read(owner, 0x800)) != context_before:
            raise ValueError('Native callback result/context footprint differs')
        expected_counts = {'callback-guard':int(present), 'callback-engine':int(accepted and count<2),
            'callback-copy':int(copied), 'callback-process':int(copied and present)}
        if any(calls.count(name)!=n for name,n in expected_counts.items()):
            raise ValueError('Native callback gates/dispatch differ')
        if bytes(uc.mem_read(environment, 0x200)) != environment_before:
            raise ValueError('Native callback changed environment phase/kind')
        callback_cases.append(dict(present=present, can=can, count=count, external_flag=external_flag,
            result_al=result, copied=bool(copied), process_calls=calls.count('callback-process'),
            phase_after=get(environment+0x30, 1), calls=calls.copy()))
    receiver_cases = []
    vector = struct.pack('<ddd', -0.0, 12.5, -44.25)
    source_table_offset = h.image.offset(0x149909370-h.image.pe.base)
    for old in (0, 5):
     for requested in (0, 1, 10012, 0xffffffff):
      for incoming_enum in (0, 3):
       for guard_mode in ('missing', 'deny', 'allow'):
        setup(old, requested, 0, 7, guard_mode); current['formatted']=requested
        uc.mem_write(settings, bytes(0x200)); uc.mem_write(listeners, bytes(0x40))
        uc.mem_write(receiver_table, h.raw[source_table_offset:source_table_offset+0xd8])
        put(receiver_table+0xa8, base+0xf300); put(environment, receiver_table)
        put(other_service, other_table); put(other_table+0x60, base+0xf400)
        put(environment+0x44, 0xaabbccdd, 4); put(environment+0x58, 2, 1)
        uc.mem_write(input_packet, bytes(0x50)); put(input_packet+0x14, requested, 4)
        uc.mem_write(input_packet+0x18, vector); put(input_packet+0x30, incoming_enum, 1)
        if binding:binding.prepare(input_packet)
        packet_before = bytes(uc.mem_read(input_packet, 0x50))
        ready_before = h.call(0x14568cad0, 110120) & 255
        if binding:
            binding.dispatch(input_packet,0,False)
        else:
            uc.reg_write(x.UC_X86_REG_RDX, input_packet); h.call(0x145dad170, environment)
        allowed = guard_mode=='allow'
        if current['pending_at_writer'] != requested or current['selected_pending'] != [requested]:
            raise ValueError('Receiver did not produce the pending value consumed by writer')
        if get(environment+0xf4, 4)!=old or get(environment+0x44, 4)!=(0 if allowed else requested):
            raise ValueError('Receiver previous/pending fields differ')
        if get(environment+0x40, 4)!=(requested if allowed else old):
            raise ValueError('Receiver/writer committed field differs')
        if bytes(uc.mem_read(environment+0x60, 24))!=vector or get(environment+0x59, 1)!=incoming_enum:
            raise ValueError('Receiver vector/enum transfer differs')
        if bytes(uc.mem_read(input_packet, 0x50))!=packet_before:
            raise ValueError('Receiver changed input packet')
        if current['receiver_notices']!=1 or current['old_context_notices']!=int(old!=0):
            raise ValueError('Receiver external notification arguments differ')
        if get(listeners+8)!=0x100 or get(listeners+0x24, 4)!=0:
            raise ValueError('Receiver empty listener state differs')
        callback_al = None
        if allowed:
            callback_address, payload = current['queued_callback']; uc.mem_write(callback_payload, payload)
            callback_al = h.call(callback_address, callback_payload) & 255
            if callback_al!=1 or calls.count('callback-process')!=1:
                raise ValueError('Receiver/writer captured callback differs')
        elif current['queued_callback'] is not None:
            raise ValueError('Refused receiver branch queued callback')
        if get(environment+0x30, 1)!=3 or current['phase_notifications']!=1:
            raise ValueError('Receiver phase did not remain at writer phase3')
        ready_after = h.call(0x14568cad0, 110120) & 255
        if ready_before!=int(old==requested) or ready_after!=int(allowed or old==requested):
            raise ValueError('Receiver-to-readiness equality predicate differs')
        receiver_cases.append(dict(old=old, requested=requested, incoming_enum=incoming_enum, guard=guard_mode,
            pending_at_writer=current['pending_at_writer'], pending=get(environment+0x44, 4),
            actual=get(environment+0x40, 4), previous=get(environment+0xf4, 4),
            vector_hex=bytes(uc.mem_read(environment+0x60, 24)).hex(), phase_after=get(environment+0x30, 1),
            callback_al=callback_al, ready_before=bool(ready_before), ready_after=bool(ready_after),
            branch_fixture='virtual_a8_true'))
    binding_report = binding.verify_rejections(input_packet,environment) if binding else None
    audit = load('audit-client-release')
    report = dict(source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)),
        context_sha256=audit.sha256(path), exports=h.evidence, legacy_direct_flow_checked=legacy,
        cases=cases, lookup_cases=lookup_cases, phase_cases=phase_cases, callback_cases=callback_cases,
        receiver_cases=receiver_cases, handler_binding=binding_report,
        native_execution=True, network_used=False, action_admitted=False, limits=context['limits'])
    target = audit.save_snapshot(h.root/('code-clues/quest-environment-world-handler-11316' if binding else
        'code-clues/quest-environment-update-11316'), report)
    return target, report


if __name__ == '__main__':
    target, result = run()
    print(json.dumps(dict(artifact=str(target), cases=len(result['cases']),
        lookup_cases=len(result['lookup_cases']), phase_cases=len(result['phase_cases']),
        callback_cases=len(result['callback_cases']), receiver_cases=len(result['receiver_cases'])), ensure_ascii=False))
