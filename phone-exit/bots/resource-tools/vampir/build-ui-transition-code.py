"""Source evidence for transition setup, easing start and completion callback."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('transition_manager', HERE / 'build-ui-manager-code.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
native, ROOT = manager.native, manager.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source_path = ROOT / 'code-clues/ui-manager-code.json'
    source = json.loads(source_path.read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    addresses = (0x144a4c440, 0x144a45830, 0x144a5b0f0, 0x1445d0bd0, 0x1445d33b0, 0x144a7b5e0,
                 0x1445ccb90, 0x1445d31d0, 0x1445d2f70, 0x1445d2690)
    roots = {image.roots[image.containing(address)] for address in addresses}
    fragments = native.decode_ranges(image, roots)
    rows = {row['address']: row for fragment in fragments for row in fragment['instructions']}
    start = 0x1445d0f70
    offset = image.offset(start - image.pe.base)
    raw = data[offset:offset + 9]
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    leaf = [dict(address=ins.address, mnemonic=ins.mnemonic, operands=ins.op_str, bytes=bytes(ins.bytes).hex())
            for ins in decoder.disasm(raw, start)]
    if len(leaf) != 2 or sum(len(bytes.fromhex(row['bytes'])) for row in leaf) != 9:
        raise ValueError('Start wrapper boundary changed')
    rows.update({row['address']: row for row in leaf})
    groups = [dict(id='completion_delegate_setup', anchors=[
        (0x144a4c694, 'lea', 'rax, [rip - 0x6e6b]'),
        (0x144a4c69b, 'mov', 'qword ptr [rbp - 9], rax'),
        (0x144a4c6a8, 'movaps', 'xmmword ptr [rbx + 0xac0], xmm0'),
        (0x144a4c6c6, 'mov', 'qword ptr [rbp + 0x1f], rbx'),
        (0x144a4c6ce, 'movaps', 'xmmword ptr [rbx + 0xae0], xmm0')]),
        dict(id='start_wrapper_and_delegate_copy', anchors=[
        (0x1445d0f70, 'lea', 'rdx, [rcx + 0x20]'),
        (0x1445d0f74, 'jmp', '0x1445d0bd0'),
        (0x1445d0c7e, 'lea', 'rdx, [rsi + 0x70]'),
        (0x1445d0c82, 'lea', 'rcx, [rbx + 0x90]'),
        (0x1445d0c89, 'call', '0x14143bbb0')]),
        dict(id='easing_function_and_timer_failures', anchors=[
        (0x1445d0cbc, 'mov', 'qword ptr [rbx + 0xf8], rax'),
        (0x1445d0cc6, 'jne', '0x1445d0d3e'),
        (0x1445d0d41, 'call', '0x1445d33b0'),
        (0x1445d0d46, 'test', 'al, al'),
        (0x1445d0d48, 'jne', '0x1445d0d6e')]),
        dict(id='completion_updates_then_drains', anchors=[
        (0x144a45846, 'call', '0x1417f4580'),
        (0x144a4584d, 'je', '0x144a45863'),
        (0x144a45856, 'call', '0x144a5b0f0'),
        (0x144a4585e, 'call', '0x144a5aef0')]),
        dict(id='timer_registration_and_tick', anchors=[
        (0x1445d34d1, 'lea', 'rax, [rip - 0x6948]'),
        (0x1445d34d8, 'mov', 'qword ptr [rsi + 0x20], rax'),
        (0x1445d34dc, 'mov', 'qword ptr [rsi + 0x18], rbx'),
        (0x1445ccb96, 'cmp', 'qword ptr [rcx + 0x10], 0'),
        (0x1445ccbed, 'call', '0x1445d31d0'),
        (0x1445ccbf9, 'cmp', 'qword ptr [rbx + 0xf0], rax'),
        (0x1445ccc00, 'jg', '0x1445ccc0f'),
        (0x1445ccc0a, 'jmp', '0x1445d2f70')]),
        dict(id='completion_callback_after_handle_clear', anchors=[
        (0x1445d2fde, 'inc', 'dword ptr [rbx + 0x104]'),
        (0x1445d2fea, 'cmp', 'dword ptr [rbx + 0x40], eax'),
        (0x1445d2fed, 'jg', '0x1445d3131'),
        (0x1445d3090, 'mov', 'rdi, qword ptr [rbx + 0x90]'),
        (0x1445d309a, 'mov', 'qword ptr [rbx + 0x10], r8'),
        (0x1445d309e, 'mov', 'qword ptr [rbx + 0xe0], r8'),
        (0x1445d30db, 'call', 'rdi'),
        (0x1445d314a, 'call', '0x1445d33b0')]),
        dict(id='separate_stop_path_without_completion_dispatch', anchors=[
        (0x1445d2694, 'cmp', 'byte ptr [rcx + 0x44], 0'),
        (0x1445d2698, 'jne', '0x1445d2748'),
        (0x1445d26a8, 'lea', 'rbx, [rcx + 0x10]'),
        (0x1445d2717, 'call', '0x1442a8480'),
        (0x1445d2722, 'call', '0x1442953d0'),
        (0x1445d2732, 'call', '0x1442a2b70'),
        (0x1445d2737, 'mov', 'qword ptr [rbx], 0')])]
    for group in groups:
        group['instructions'] = [manager.verify_anchor(rows, *anchor) for anchor in group.pop('anchors')]
        group['used_for_bot_input'] = False
    strings = []
    for fragment in fragments:
        for row in fragment['instructions']:
            for address in row['rip_references']:
                try:
                    position = image.offset(address - image.pe.base)
                except ValueError:
                    continue
                match = re.match(rb'(?:[\x20-\x7e]\x00){5,}', data[position:position + 2048])
                if match:
                    text = match.group().decode('utf-16le')
                    strings.append(dict(instruction=row, literal=dict(text=text, file_offset=position, encoding='utf-16le')))
    required = {'FNnEasingVar::Start()', 'invalid Function', 'failed to _StartTimer()'}
    if not required <= {row['literal']['text'] for row in strings}:
        raise ValueError('Easing diagnostics changed')
    catalog_dir = ROOT / 'ui-catalog'
    widget_candidates = []
    for item in json.loads((catalog_dir / 'index.json').read_text(encoding='utf-8'))['windows']:
        if item['name'] not in ('WBP_FaderUI', 'WBP_MediaUI'):
            continue
        path = catalog_dir / item['file']
        resource = json.loads(path.read_text(encoding='utf-8'))
        controls = [control for control in resource['controls'] if control['name'] == 'ImageFader']
        if not controls:
            raise ValueError('Fader candidate control changed')
        widget_candidates.append(dict(catalog_file=item['file'], catalog_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            name=resource['name'], source=resource['source'], entry=resource['entry'],
            asset_sha256=resource['asset_sha256'], body_sha256=resource['body_sha256'], controls=controls,
            binding_status='name_candidate_only_native_class_binding_unresolved'))
    report = dict(source=source['source'], sha256=source['sha256'],
        ui_manager_report_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        fragments=fragments, reviewed_links=groups, diagnostic_references=strings,
        image_fader_widget_candidates=widget_candidates,
        start_wrapper=dict(start=start, end=start + 9, file_offset=offset,
            sha256=hashlib.sha256(raw).hexdigest(), instructions=leaf),
        limitations=['Conditional timer tick-to-completion callback path proven; native timer manager implementation and actual runtime scheduling unverified.',
                     'Weak-owner check may skip completion callback body.',
                     'Start can fail; no unconditional success or fixed delay inferred.',
                     'Separate stop helper has no completion dispatch; full reset-to-stop chain and reentrancy not fully reconstructed.',
                     'Repeat/direction flag meanings, enum names and Android behavior remain unverified.'])
    output = ROOT / 'code-clues/ui-transition-code.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(roots=len(roots), fragments=len(fragments), instructions=len(rows),
                         reviewed_links=len(groups), diagnostic_references=len(strings))))


if __name__ == '__main__':
    main()
