"""Compare isolated, bounded emulation of client rotator math with the decoder.

Only math instructions and file-backed constant pages are emulated. No game process,
OS calls, imports, sockets or live memory. The caller's stack-cookie check is skipped;
all arithmetic, including the client's vector trig helper, runs inside Unicorn.
"""
import hashlib, importlib.util, itertools, json, os, random, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    def module(name, file):
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    native = module('rotation_native', 'build-native-entry-code.py')
    model = module('rotation_model', 'lift-transform-math.py')
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Use pinned Unicorn 2.1.4 in phone-exit/.tools/vampir-analysis')
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    exe = Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(exe)
    fragments = native.decode_ranges(im, {im.roots[im.containing(a)] for a in [0x1414fd980, 0x148799250, 0x14550d6c0]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if (rows[0x1414fdaad]['mnemonic'], rows[0x1414fdaad]['operands']) != ('call', '0x148796040'):
        raise ValueError('Changed caller stack-cookie check')
    trampoline_offset = im.offset(0x8796aa0)
    trampoline = exe[trampoline_offset:trampoline_offset + 5]
    if trampoline != bytes.fromhex('e9ab270000'):
        raise ValueError('Changed vector trig trampoline')
    allowed = [(im.pe.base + f['begin_rva'], im.pe.base + f['end_rva']) for f in fragments]
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x2000000, 0x20000)
    emu.mem_map(0x3000000, 0x1000)
    pages = {}

    def map_page(uc, access, address, size, value, data):
        if access == unicorn.UC_MEM_WRITE_UNMAPPED:
            return False
        page = address & ~4095
        if page in pages:
            return False
        try:
            offset = im.offset(page - im.pe.base)
        except ValueError:
            return False
        raw = exe[offset:offset + 4096]
        if len(raw) != 4096:
            return False
        uc.mem_map(page, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        uc.mem_write(page, raw)
        pages[page] = dict(address=page, file_offset=offset, sha256=hashlib.sha256(raw).hexdigest())
        return True

    def guard(uc, address, size, data):
        if address == 0x1414fdaad:
            uc.reg_write(x.UC_X86_REG_RIP, address + 5)
        elif address != 0x148796aa0 and not any(lo <= address < hi for lo, hi in allowed):
            raise ValueError('Unexpected emulated code: ' + hex(address))

    emu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, map_page)
    emu.hook_add(unicorn.UC_HOOK_CODE, guard)
    placement_path = root / 'maps/navigation-study/level/lift-placements.json'
    placements = json.loads(placement_path.read_text('utf-8'))
    decoder = module('rotation_placement_decoder', 'decode-lift-placements.py')
    for lift in placements['lifts']:
        component = lift['scene_component']
        raw = (placement_path.parent / component['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != component['export']['sha256']:
            raise ValueError('Changed placement component')
        if decoder.decode(raw)['properties'] != lift['placement']['properties']:
            raise ValueError('Placement report differs from component bytes')
    samples = [dict(kind='placement', parent_index=r['parent']['export']['index'], rotation=r['placement']['properties']['RelativeRotation'])
               for r in placements['lifts'] if 'RelativeRotation' in r['placement']['properties']]
    samples += [dict(kind='axis', rotation=r) for r in [[0, 0, 0], [90, 0, 0], [0, 90, 0], [0, 0, 90], [-90, 0, 0], [0, -90, 0], [0, 0, -90], [180, 180, 180], [360, -360, 720], [1e6, -1e6, 1e6]]]
    rng = random.Random(1414)
    samples += [dict(kind='mixed', rotation=[rng.uniform(-1e6, 1e6) for _ in range(3)]) for _ in range(128)]
    results = []
    for sample in samples:
        rotation = sample['rotation']
        emu.mem_write(0x3000000, struct.pack('<ddd', *rotation))
        emu.mem_write(0x3000100, bytes(32))
        rsp = 0x2010000 - 8
        emu.mem_write(rsp, struct.pack('<Q', 0x2000000))
        for register, value in [(x.UC_X86_REG_RSP, rsp), (x.UC_X86_REG_RCX, 0x3000000), (x.UC_X86_REG_RDX, 0x3000100), (x.UC_X86_REG_MXCSR, 0x1f80)]:
            emu.reg_write(register, value)
        emu.emu_start(0x1414fd980, 0x2000000, timeout=2000000, count=100000)
        if emu.reg_read(x.UC_X86_REG_RIP) != 0x2000000:
            raise ValueError('Math emulation did not return within bounds')
        actual = list(struct.unpack('<dddd', emu.mem_read(0x3000100, 32)))
        expected = model.rotator_to_quaternion(rotation)
        error = max(abs(a - b) for a, b in zip(actual, expected))
        if not error <= 2e-14:
            raise ValueError('Client rotation formula differs: ' + str(sample))
        results.append(dict(**sample, native_emulated=actual, calculated=expected, max_absolute_error=error))
    # The native accumulator starts with [(0,0,-10),(0,0,10)], so equal endpoints
    # still include that initial box. Compare all transformed corners of that box.
    # SmartLink/SegmentLinks stay null; no navigation traversal is emulated.
    projections = []
    for index, sample in enumerate(samples):
        rotation = sample['rotation']
        quaternion = model.rotator_to_quaternion(rotation)
        point = [rng.uniform(-5000, 5000) for _ in range(3)]
        translation = [rng.uniform(-500000, 500000) for _ in range(3)]
        scale = [rng.uniform(-5, 5) for _ in range(3)] if index % 3 else [1., 1., 1.]
        if index == 0:
            scale = [0., 0., 0.]
        actor, component, array, output = 0x3000200, 0x3000800, 0x3000b00, 0x3000c00
        emu.mem_write(actor, bytes(0x500))
        emu.mem_write(actor + 0x1b8, struct.pack('<Q', component))
        emu.mem_write(actor + 0x3e0, struct.pack('<Qii', array, 1, 1))
        emu.mem_write(component + 0x1d0, struct.pack('<12d', *quaternion, *translation, 0., *scale, 0.))
        emu.mem_write(array, bytes(0x70))
        emu.mem_write(array + 0x40, struct.pack('<6d', *point, *point))
        emu.mem_write(output, bytes(64))
        rsp = 0x2010000 - 8
        emu.mem_write(rsp, struct.pack('<Q', 0x2000000))
        for register, value in [(x.UC_X86_REG_RSP, rsp), (x.UC_X86_REG_RCX, actor), (x.UC_X86_REG_RDX, output), (x.UC_X86_REG_MXCSR, 0x1f80)]:
            emu.reg_write(register, value)
        emu.emu_start(0x14550d6c0, 0x2000000, timeout=2000000, count=100000)
        if emu.reg_read(x.UC_X86_REG_RIP) != 0x2000000:
            raise ValueError('Bounds emulation did not return within bounds')
        actual = list(struct.unpack('<6d', emu.mem_read(output, 48)))
        local_low = [min(0., point[0]), min(0., point[1]), min(-10., point[2])]
        local_high = [max(0., point[0]), max(0., point[1]), max(10., point[2])]
        corners = [model.transform_point(corner, translation, quaternion, scale)
                   for corner in itertools.product(*zip(local_low, local_high))]
        expected = [min(c[i] for c in corners) for i in range(3)] + [max(c[i] for c in corners) for i in range(3)]
        error = max(abs(a - b) for a, b in zip(actual, expected))
        if not error <= 2e-9 or emu.mem_read(output + 48, 1) != b'\x01':
            raise ValueError('Client point projection differs: ' + str(dict(index=index, actual=actual, expected=expected, error=error, valid=emu.mem_read(output + 48, 1).hex())))
        projections.append(dict(rotation=rotation, point=point, translation=translation, scale=scale,
                                local_bounds=[local_low, local_high], native_emulated_bounds=actual, calculated_world_bounds=expected, max_absolute_error=error))
    constants = []
    for row in rows.values():
        if row['address'] >= 0x1414fdacb or row['mnemonic'] not in ['divpd', 'mulpd', 'xorps']:
            continue
        for va in row['rip_references']:
            offset = im.offset(va - im.pe.base)
            constants.append(dict(instruction=row, file_offset=offset, bytes=exe[offset:offset + 16].hex()))
    seed_constants = []
    for address, expected in [(0x14550d6cf, 10.), (0x14550d6da, -10.)]:
        instruction = rows[address]
        offset = im.offset(instruction['rip_references'][0] - im.pe.base)
        if struct.unpack_from('<d', exe, offset)[0] != expected:
            raise ValueError('Changed native bounds seed')
        seed_constants.append(dict(instruction=instruction, file_offset=offset, bytes=exe[offset:offset + 8].hex(), value=expected))
    report = dict(source=source, model_sha256=hashlib.sha256((HERE / 'lift-transform-math.py').read_bytes()).hexdigest(),
                  placements_sha256=hashlib.sha256(placement_path.read_bytes()).hexdigest(), native_fragments=fragments, constants=constants,
                  trig_trampoline=dict(address=0x148796aa0, file_offset=trampoline_offset, bytes=trampoline.hex(), target=0x148799250),
                  bounds_seed=dict(min=[0., 0., -10.], max=[0., 0., 10.], native_constants=seed_constants),
                  emulation=dict(engine='Unicorn', version=unicorn.__version__, max_instructions_per_case=100000, timeout_us=2000000,
                                 skipped_stack_cookie_call=rows[0x1414fdaad], pages=list(pages.values()), results=results, point_projections=projections),
                  summary=dict(samples=len(results), placement_rotations=sum(r['kind'] == 'placement' for r in results),
                               max_absolute_error=max(r['max_absolute_error'] for r in results), formula_verified=True,
                               bounds_comparison_samples=len(projections), bounds_max_absolute_error=max(r['max_absolute_error'] for r in projections),
                               transform_math_checked_against_bounds=True, world_endpoints_verified=False),
                  reference='https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Core/TRotator',
                  limitations=['Finite rotations within +/-1e6 degrees checked; extreme/nonfinite input excluded by model.',
                               'Isolated native math emulation verifies conversion, not game initialization, runtime state or map projection.',
                               'Native bounds compared to corner-wise scale/rotate/translate; initial bounds are [(0,0,-10),(0,0,10)]. Inputs are synthetic, not effective instance world transforms.',
                               'Native CDO values, attachment resolution and effective instance endpoints remain separate work.'])
    path = root / 'maps/navigation-study/lift-blueprints/rotation-evidence.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(summary=report['summary'], sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
