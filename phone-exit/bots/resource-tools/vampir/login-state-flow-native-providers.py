"""Declared providers for native post-state and continuation integration.

Only provider objects and backend effects are synthetic.  The wrapper, target,
constructor, getter leaves and final virtual reset remain exact source code.
"""
import struct


LEVELS = (0xf0, 0x140, 0x190, 0x210, 0x260, 0x2b0, 0x300)
VALUES = LEVELS + (0x1a0, 0x1b0, 0x220, 0x240, 0x244, 0x248, 0x24c, 0x270, 0x290,
                  0x294, 0x298, 0x29c, 0x2c0, 0x2e0, 0x2e4, 0x2e8, 0x2ec, 0x338, 0x33c)
POST_DEFAULTS = dict(present=True, class_count=3, class_index=2, class_match=True,
                     active=True, busy=False, occupied=False, mode=0, predicate=False,
                     fallback=False, list_match=True, eligible=False, object_index=0,
                     object_count=1, flag=1)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def captured_second(offset, actual_rdx, table):
    """Preserve the observed source-table carry at the first low-level call.

    This names a concrete register observation, not a helper argument contract.
    Every other call retains its complete previous uint32 projection.
    """
    require(type(offset) is int and offset >= 0 and type(actual_rdx) is int
            and 0 <= actual_rdx < (1 << 64) and type(table) is int and 0 < table < (1 << 64),
            'State-flow captured register input differs')
    if offset == 43:
        require(actual_rdx == table, 'State-flow source virtual table register carry differs')
        return 'source_vtable_low32'
    return actual_rdx & 0xffffffff


def install(h, context, post, continuation, *, caller, map_source, box):
    uc, x = h.uc, h.x
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    post_functions = {key: int(at, 16) for key, at in post['functions'].items()}
    continuation_functions = {key: int(at, 16) for key, at in continuation['functions'].items()}
    service, actor, info, klass, chain, table, chunks, chunk0, chunk1 = [h.scratch + off for off in
        (0xc0000, 0xc1000, 0xc2000, 0xc3000, 0xc4000, 0xc5000, 0xc6000, 0xc7000, 0xc9000)]
    obj = h.scratch + 0xd0000
    post_globals = {key: int(at, 16) for key, at in post['globals'].items()}
    singleton, flag = (int(continuation[key], 16) for key in ('singleton', 'flag'))
    source_table, base_table = (int(continuation[key], 16) for key in ('table', 'base_table'))
    post_getter, continuation_getter = int(post['service_getter'], 16), int(continuation['getter'], 16)
    virtual = {'continuation_singleton': (singleton, 8), 'continuation_flag': (flag, 1),
        'post_state_service': (post_globals['service'], 8), 'post_state_chunks': (post_globals['chunks'], 8),
        'post_state_count': (post_globals['count'], 4)}
    require(set(context['virtual_globals']) == set(virtual), 'State-flow virtual providers differ')
    for role, (at, size) in virtual.items():
        item = context['virtual_globals'][role]
        require(int(item['address'], 16) == at and item['size_bytes'] == size,
                'State-flow virtual provider address/width differs')
        # Admission validates the complete PE span; virtual tails have no raw bytes.
        try:
            h.image.offset(at - h.image.pe.base)
        except ValueError:
            pass
        else:
            raise ValueError('State-flow virtual provider unexpectedly has raw backing')
        map_source(at, size)
    for at, size in ((source_table, 0x30), (base_table, 8)):
        map_source(at, size)

    def reg(name): return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))
    def put(at, fmt, *values): uc.mem_write(at, struct.pack('<' + fmt, *values))
    def number(at, size=8): return int.from_bytes(uc.mem_read(at, size), 'little')
    def snapshot(at, size): return uc.snapshot(at, size)

    require(number(source_table + 0x28) == continuation_functions['reset'], 'State-flow final reset slot differs')
    current, observed = {}, {}
    fixture_names = {int(at, 16): name for name, at in post['fixtures'].items()}
    helpers = {int(at, 16) for at in continuation['helpers_captured']}

    def backend(machine, name):
        a, b, c, d = (reg(key) for key in ('RCX', 'RDX', 'R8', 'R9'))
        value = 0
        if name == 'class':
            value = info
        elif name == 'lookup':
            require(a == service and b == info, 'State-flow post lookup arguments differ')
            value = actor if current['post']['present'] else 0
        elif name == 'occupied':
            require(a == service + 0x250, 'State-flow post slot argument differs'); value = int(current['post']['occupied'])
        elif name == 'mode':
            require(a == actor, 'State-flow post mode receiver differs'); value = current['post']['mode']
        elif name in ('predicate', 'fallback', 'eligible'):
            require(a == actor, 'State-flow post predicate receiver differs'); value = int(current['post'][name])
        elif name == 'list_match':
            require(a == service + 0x2c8 and b == actor, 'State-flow post list arguments differ'); value = int(current['post']['list_match'])
        elif name == 'assign':
            require(a == service + 0x250 and b == actor, 'State-flow post assignment arguments differ')
        elif name == 'hide':
            require(a == actor and b == 1 and c & 255 == 0 and d & 255 == 1 and number(reg('RSP') + 0x28) & 255 == 1,
                    'State-flow post hide arguments differ')
        elif name == 'settle':
            require(a == service and b == 0x1234 and c == actor, 'State-flow post settle arguments differ')
        elif name == 'mark':
            settings = current['post']; index = settings['object_index']
            expected = (chunk1 if index >> 16 else chunk0) + (index & 0xffff) * 0x18
            require(a == (expected if index < settings['object_count'] else 0) and b == 0x40000000,
                    'State-flow post mark arguments differ')
        else:
            raise ValueError('State-flow unknown post backend')
        observed['post']['events'].append(name); h.finish(value)

    for at, name in fixture_names.items():
        h.add_fixture(at, lambda machine, name=name: backend(machine, name))
    for i, slot in enumerate((0x2e8, 0x4c8, 0x540)):
        at = h.scratch + 0xcf000 + i * 16; put(table + slot, 'Q', at)
        def callback(machine, slot=slot):
            require(reg('RCX') == actor, 'State-flow post virtual receiver differs')
            observed['post']['events'].append('virtual_' + hex(slot)); h.finish()
        h.add_fixture(at, callback)
    def continuation_helper(machine, at):
        role, offset = caller(at)
        require(role in ('continuation.constructor', 'continuation.reset'), 'State-flow continuation helper caller differs')
        if role == 'continuation.reset':
            a, b = reg('RCX'), reg('RDX')
            observed['continuation']['events'].append(dict(call_offset=offset,
                offset=hex(a - obj) if obj <= a < obj + 0x400 else None, second=captured_second(offset, b, source_table)))
        h.finish(0)
    for at in helpers:
        h.add_fixture(at, lambda machine, at=at: continuation_helper(machine, at))

    def native_regions():
        return [(service + 0x250, 8), (obj, 0x400), (singleton, 8), (flag, 1)]

    def trace(machine, at, size, unused):
        if not current:
            return
        p, c = observed['post'], observed['continuation']
        if at == continuation_functions['constructor']:
            require(current['phase'] == 'constructor' and reg('RCX') == obj, 'State-flow constructor entry differs')
            c['constructor_calls'] += 1
        elif at == post_functions['wrapper']:
            role, _ = caller(at)
            require(current['phase'] == 'delivery' and role == 'composition.handler.handler', 'State-flow post wrapper caller differs')
            p['wrapper_calls'] += 1; current['wrapper_stack'] = reg('RSP')
        elif at == post_getter:
            role, _ = caller(at); require(role == 'post_state.wrapper', 'State-flow post getter caller differs')
            p['getter_calls'] += 1
        elif at == post_functions['target']:
            require(current['phase'] == 'delivery' and p['wrapper_calls'] == 1, 'State-flow post tail entered outside wrapper')
            item = dict(service=reg('RCX') == service, actor=reg('RDX') == actor, flag=reg('R8') & 255,
                        tail_stack_preserved=reg('RSP') == current['wrapper_stack'])
            require(item == dict(service=True, actor=True, flag=1, tail_stack_preserved=True), 'State-flow post tail arguments differ')
            p['target_entry'].append(item)
        elif at == continuation_getter:
            role, _ = caller(at)
            require(current['phase'] == 'delivery' and role == 'composition.handler.handler' and number(singleton) == obj,
                    'State-flow continuation getter caller/singleton differs')
            c['getter_calls'] += 1
        elif at == continuation_functions['reset']:
            role, _ = caller(at)
            require(current['phase'] == 'delivery' and role == 'composition.handler.handler'
                    and c['getter_calls'] == 1 and reg('RCX') == obj and number(obj) == source_table
                    and number(source_table + 0x28) == at, 'State-flow source virtual reset entry differs')
            c['reset_calls'] += 1; c['reset_via_source_vtable'] = True

    def memory(machine, access, at, size, value, unused):
        if not current:
            return
        value &= (1 << (size * 8)) - 1
        if service <= at < service + 0x300:
            require(at == service + 0x250 and size == 8 and current['phase'] == 'delivery', 'State-flow post store extent differs')
            observed['post']['writes'].append(dict(offset=hex(at-service), size=size, value=value,
                instruction_offset=reg('RIP') - post_functions['target']))
        if obj <= at < obj + 0x400:
            phase = current['phase']; require(phase in ('constructor', 'delivery'), 'State-flow object store phase differs')
            if phase == 'constructor':
                if at == obj and size == 8:
                    label = 'base_table' if value == base_table else 'table' if value == source_table else None
                    require(label is not None, 'State-flow constructor vptr differs')
                    observed['continuation']['ctor_vptrs'].append(label)
            else:
                require(observed['continuation']['reset_calls'] == 1, 'State-flow continuation store before native reset')
                observed['continuation']['writes'].append(dict(phase='reset', offset=hex(at-obj), size=size, value=value,
                    instruction_offset=reg('RIP') - continuation_functions['reset']))
        if at == singleton:
            require(current['phase'] == 'constructor' and size == 8 and value == obj, 'State-flow singleton publication differs')
            current['singleton_writes'] += 1

    def prepare(spec, call):
        current.clear(); current.update(phase='setup', post=dict(POST_DEFAULTS), singleton_writes=0, wrapper_stack=None)
        current['post'].update(spec['post_settings']); levels = spec['continuation_settings']
        require(set(levels) == {'level', 'capacity'} and levels['level'] in (0, 1, 2, 5) and levels['capacity'] in (128, 256),
                'State-flow continuation settings differ')
        observed.clear(); observed.update(post=dict(settings=dict(current['post']), wrapper_calls=0, getter_calls=0, target_entry=[], events=[], writes=[]),
            continuation=dict(level=levels['level'], capacity=levels['capacity'], constructor_calls=0, getter_calls=0, reset_calls=0,
                ctor_vptrs=[], constructor_published_singleton=False, reset_via_source_vtable=False, events=[], writes=[]))
        for at, size in ((service, 0x300), (actor, 0x340), (info, 0x40), (klass, 0x40), (chain, 0x40)):
            box(at, size, 0)
        box(obj, 0x400, 0x5a)
        settings = current['post']
        require(0 <= settings['class_index'] <= 3, 'State-flow synthetic class index differs')
        put(service + 0x250, 'Q', 0xaabbccdd); put(service + 0x260, 'BB', int(settings['active']), int(settings['busy']))
        put(actor, 'Q', table); put(actor + 0x10, 'Q', klass); put(actor + 0xc, 'I', settings['object_index']); put(actor + 0x328, 'Q', 0x1234)
        put(info + 0x38, 'i', settings['class_index']); put(klass + 0x30, 'Qi', chain, settings['class_count'])
        put(chain + settings['class_index'] * 8, 'Q', info + 0x30 if settings['class_match'] else 0)
        put(post_globals['service'], 'Q', service); put(post_globals['chunks'], 'Q', chunks); put(post_globals['count'], 'I', settings['object_count'])
        put(chunks, 'QQ', chunk0, chunk1); put(singleton, 'Q', 0); put(flag, 'B', 0)
        current['phase'] = 'constructor'
        require(call(continuation_functions['constructor'], obj) == obj, 'State-flow constructor returned foreign object')
        require(number(singleton) == obj and current['singleton_writes'] == 1 and number(obj) == source_table
                and observed['continuation']['ctor_vptrs'] == ['base_table', 'table'], 'State-flow native constructor publication differs')
        observed['continuation']['constructor_published_singleton'] = True
        current['phase'] = 'setup'
        for offset in LEVELS: put(obj + offset, 'I', levels['level'])
        for offset in (0x244, 0x294, 0x2e4): put(obj + offset, 'I', levels['capacity'])
        put(obj + 0x308, 'H', 0xffff); put(flag, 'B', 1)
        current.update(actor_before=snapshot(actor, 0x340), service_before=snapshot(service, 0x300), reset_before=snapshot(obj, 0x400))
        uc.protect([(service, 0x250), (service+0x258, 0xa8), (actor, 0x340), (info, 0x40), (klass, 0x40), (chain, 0x40),
                    (table, 0x548), (chunks, 16), (singleton, 8), (source_table, 0x30), (base_table, 8)]
                    + [(post_globals['service'], 8), (post_globals['chunks'], 8), (post_globals['count'], 4)])

    def enter_delivery():
        require(current['phase'] == 'setup', 'State-flow delivery provider phase differs'); current['phase'] = 'delivery'

    def finish():
        p, c = observed['post'], observed['continuation']
        require(snapshot(actor, 0x340) == current['actor_before'], 'State-flow native post changed actor provider')
        after = snapshot(service, 0x300)
        require(all(a == b for i, (a, b) in enumerate(zip(current['service_before'], after)) if not 0x250 <= i < 0x258),
                'State-flow post changed unrelated service fields')
        p.update(slot=number(service+0x250), guards=True, actor_unchanged=True, unrelated_service_unchanged=True, arguments_checked=True)
        reset = bool(c['reset_calls']); require(c['reset_calls'] in (0, 1), 'State-flow reset called repeatedly')
        current_after = snapshot(obj, 0x400)
        if not reset:
            require(current_after == current['reset_before'] and number(flag, 1) == 1, 'State-flow negative path changed prepared reset state')
        else:
            allowed = {i for w in c['writes'] for i in range(int(w['offset'], 16), int(w['offset'], 16) + w['size'])}
            require(all(a == b for i, (a, b) in enumerate(zip(current['reset_before'], current_after)) if i not in allowed),
                    'State-flow continuation unattributed store')
        for at, size in ((service, 0x300), (actor, 0x340), (info, 0x40), (klass, 0x40), (chain, 0x40), (obj, 0x400)):
            require(snapshot(at-16,16) == b'\xa5'*16 and snapshot(at+size,16) == b'\xa6'*16, 'State-flow provider guard changed')
        c.update(values={hex(offset): number(obj+offset,4) for offset in VALUES} if reset else None,
                 field308=number(obj+0x308,2), flag=number(flag,1), reset_state_unchanged=not reset,
                 guards=True, constructor_guards=True, unattributed_store=False, abi=True)
        current['phase'] = 'finished'
        return dict(post_state=p, continuation=c)

    return dict(prepare=prepare, enter_delivery=enter_delivery, finish=finish, trace=trace,
                memory=memory, native_regions=native_regions)
