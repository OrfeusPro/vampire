"""Capture reviewed UI-manager list operations without inventing pure predicates."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('manager_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
ROOT = native.ROOT


def verify_anchor(instructions, address, mnemonic, operands):
    row = instructions.get(address)
    if row is None or row['mnemonic'] != mnemonic or row['operands'] != operands:
        raise ValueError('UI-manager anchor changed: ' + hex(address))
    return row


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    entry_path = ROOT / 'code-clues/entry-window-code.json'
    entry = json.loads(entry_path.read_text(encoding='utf-8'))
    data = Path(entry['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    addresses = (0x144a1cbf0, 0x144a240d0, 0x144a24f80, 0x144a55e30, 0x144a2a530, 0x144a720c0, 0x144a48d20,
                 0x144a5a650, 0x144a5aef0, 0x144a4ca20)
    roots = {image.roots[image.containing(address)] for address in addresses}
    fragments = native.decode_ranges(image, roots)
    rows = {row['address']: row for fragment in fragments for row in fragment['instructions']}
    # Leaf callback has no exception-directory entry. Bound it at the reviewed RET;
    # do not decode the alignment bytes or adjacent function as part of the leaf.
    callback_start, callback_end = 0x144a1ce60, 0x144a1ce85
    callback_offset = image.offset(callback_start - image.pe.base)
    callback_raw = data[callback_offset:callback_offset + callback_end - callback_start]
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    callback = [dict(address=ins.address, mnemonic=ins.mnemonic, operands=ins.op_str,
                     bytes=bytes(ins.bytes).hex()) for ins in decoder.disasm(callback_raw, callback_start)]
    if sum(len(bytes.fromhex(row['bytes'])) for row in callback) != len(callback_raw) or callback[-1]['mnemonic'] != 'ret':
        raise ValueError('Leaf callback boundary changed')
    rows.update({row['address']: row for row in callback})
    groups = [dict(id='list_lookup', observation='Scans list [RCX+0x18], count [RCX+0x20], resolves entries and compares against input RDX.',
        anchors=[(0x144a1cc04, 'mov', 'rbx, qword ptr [rcx + 0x18]'),
                 (0x144a1cc08, 'mov', 'rsi, rdx'),
                 (0x144a1cc0b, 'movsxd', 'rax, dword ptr [rcx + 0x20]'),
                 (0x144a1cc23, 'call', '0x1417f24d0'),
                 (0x144a1cc28, 'cmp', 'rax, rsi'),
                 (0x144a1cc2b, 'je', '0x144a1cc4d'),
                 (0x144a1cc36, 'xor', 'al, al')]),
        dict(id='found_item_has_side_effects', observation='Found item causes tail inspection, calls while tail differs, then virtual slot +0x520 and manager call before AL=1. Not a pure contains/is-visible predicate.',
        anchors=[(0x144a1cc60, 'mov', 'eax, dword ptr [rdi + 0x20]'),
                 (0x144a1cc63, 'dec', 'eax'),
                 (0x144a1cc75, 'cmp', 'rax, rsi'),
                 (0x144a1cc78, 'je', '0x144a1cc8f'),
                 (0x144a1cc82, 'call', '0x144a240d0'),
                 (0x144a1cc8b, 'jg', '0x144a1cc60'),
                 (0x144a1cc95, 'call', 'qword ptr [rax + 0x520]'),
                 (0x144a1cca8, 'call', '0x144a27a50'),
                 (0x144a1ccad, 'mov', 'al, 1')]),
        dict(id='tail_processing', observation='Called helper inspects the preceding list element and invokes virtual methods; a later helper may handle list mutations. Full async/delegate semantics unresolved.',
        anchors=[(0x144a2415f, 'movsxd', 'rax, dword ptr [rdi + 0x20]'),
                 (0x144a24173, 'mov', 'rcx, qword ptr [rax + rcx*8 - 0x10]'),
                 (0x144a241b9, 'call', 'qword ptr [rdx + 0x4f0]'),
                 (0x144a24215, 'call', 'qword ptr [rdx + 0x4f8]'),
                 (0x144a2426a, 'call', '0x144a720c0'),
                 (0x144a2429f, 'call', '0x144a2a530')]),
        dict(id='presenter_checks_same_list', observation='Presenter accesses the same list/count, compares the last resolved object against input and checks a caller flag before bypassing later work.',
        anchors=[(0x144a24fc5, 'test', 'rdx, rdx'),
                 (0x144a24fca, 'xor', 'al, al'),
                 (0x144a25221, 'mov', 'eax, dword ptr [r15 + 0x20]'),
                 (0x144a25232, 'mov', 'rax, qword ptr [r15 + 0x18]'),
                 (0x144a2523f, 'cmp', 'byte ptr [rbp + 0x100], 0'),
                 (0x144a25248, 'cmp', 'rax, rsi'),
                 (0x144a25250, 'jmp', '0x144a254ee')]),
        dict(id='deferred_callback_targets_removal', observation='Transition branch stores callback address and owner/argument payload; callback tail-jumps to the same removal root as immediate branch. Execution timing unresolved.',
        anchors=[(0x144a24236, 'lea', 'rax, [rip - 0x73dd]'),
                 (0x144a2423d, 'mov', 'qword ptr [rsp + 0x30], rdi'),
                 (0x144a24242, 'mov', 'dword ptr [rsp + 0x38], esi'),
                 (0x144a24257, 'mov', 'qword ptr [rsp + 0x40], rax'),
                 (0x144a24265, 'movups', 'xmmword ptr [rsp + 0x68], xmm0'),
                 (0x144a2426a, 'call', '0x144a720c0'),
                 (0x144a1ce79, 'mov', 'edx, dword ptr [rcx + 8]'),
                 (0x144a1ce7c, 'mov', 'rcx, qword ptr [rcx]'),
                 (0x144a1ce7f, 'jmp', '0x144a2a530')]),
        dict(id='tail_record_removed', observation='Removal root reads last record and decrements the same list count. A transition helper transfers the callback into another object; actual scheduling/duration unresolved.',
        anchors=[(0x144a2a541, 'mov', 'r8d, dword ptr [rcx + 0x20]'),
                 (0x144a2a589, 'mov', 'rcx, qword ptr [rdx + rax*8 - 8]'),
                 (0x144a2a791, 'dec', 'dword ptr [rdi + 0x20]'),
                 (0x144a2a794, 'lea', 'rcx, [rdi + 0x18]'),
                 (0x144a2a798, 'call', '0x14167f5a0'),
                 (0x144a72150, 'mov', 'rdx, rsi'),
                 (0x144a72156, 'call', '0x144a48d20')]),
        dict(id='callback_queue_or_dispatch', observation='Field +0xb40 selects branches: value 2 queues callback in array +0xa08/count +0xa10; value 3 reaches indirect tail dispatch. State names and completion trigger unresolved.',
        anchors=[(0x144a48d50, 'mov', 'ecx, dword ptr [rbx + 0xb40]'),
                 (0x144a48d63, 'sub', 'ecx, 2'),
                 (0x144a48d66, 'je', '0x144a48eb4'),
                 (0x144a48d6c, 'cmp', 'ecx, 1'),
                 (0x144a48d6f, 'je', '0x144a48e7b'),
                 (0x144a48eb1, 'jmp', 'rax'),
                 (0x144a48ebe, 'movsxd', 'rsi, dword ptr [rbx + 0xa10]'),
                 (0x144a48ec8, 'mov', 'dword ptr [rbx + 0xa10], eax'),
                 (0x144a48ee7, 'shl', 'rcx, 6'),
                 (0x144a48eeb, 'add', 'rcx, qword ptr [rbx + 0xa08]')]),
        dict(id='completion_drains_queue_then_changes_state', observation='Walks 64-byte callback records, invokes nonnull function pointers, clears count, then maps prior state 0 to 1 and other values to 3 before optional follow-up branch.',
        anchors=[(0x144a5af02, 'lea', 'rdi, [rcx + 0xa08]'),
                 (0x144a5af13, 'shl', 'r14, 6'),
                 (0x144a5af40, 'call', 'rsi'),
                 (0x144a5af42, 'add', 'rbx, 0x40'),
                 (0x144a5af5e, 'mov', 'dword ptr [rdi + 8], esi'),
                 (0x144a5af82, 'mov', 'eax, 3'),
                 (0x144a5af8e, 'cmove', 'eax, edx'),
                 (0x144a5af98, 'mov', 'dword ptr [rbp + 0xb40], eax')]),
        dict(id='reset_clears_queues_without_dispatch_loop', observation='Reset helper processes/clears arrays +0xa08 and +0xa18 and sets state 1; this function lacks the completion callback invocation loop. Callee internals and external cancellation semantics unresolved.',
        anchors=[(0x144a4ca32, 'lea', 'rbx, [rdi + 0xa08]'),
                 (0x144a4ca4a, 'mov', 'dword ptr [rbx + 8], 0'),
                 (0x144a4ca6f, 'lea', 'rbx, [rdi + 0xa18]'),
                 (0x144a4ca87, 'mov', 'dword ptr [rbx + 8], 0'),
                 (0x144a4cab1, 'mov', 'dword ptr [rdi + 0xb40], 1')]),
        dict(id='small_parameter_completes_synchronously', observation='Compares masked parameter +0xb60 against a float threshold. JA takes the alternate starter; fallthrough calls update helper and completion directly. Full NaN/default/time semantics unresolved.',
        anchors=[(0x144a5a688, 'movss', 'xmm0, dword ptr [rcx + 0xb60]'),
                 (0x144a5a690, 'andps', 'xmm0, xmmword ptr [rip + 0x3f32cb9]'),
                 (0x144a5a697, 'comiss', 'xmm0, dword ptr [rip + 0x3f45922]'),
                 (0x144a5a69e, 'ja', '0x144a5a6bb'),
                 (0x144a5a6ac, 'call', '0x144a5b0f0'),
                 (0x144a5a6b4, 'call', '0x144a5aef0'),
                 (0x144a5a6c2, 'call', '0x1445d0f70')])]
    for group in groups:
        group['instructions'] = [verify_anchor(rows, *anchor) for anchor in group.pop('anchors')]
        group['used_for_bot_input'] = False
    comparison = rows[0x144a5a697]
    threshold_address = comparison['rip_references'][0]
    threshold_offset = image.offset(threshold_address - image.pe.base)
    threshold_bytes = data[threshold_offset:threshold_offset + 4]
    report = dict(source=entry['source'], sha256=entry['sha256'],
        entry_window_report_sha256=hashlib.sha256(entry_path.read_bytes()).hexdigest(),
        fragments=fragments, reviewed_operations=groups,
        leaf_callback=dict(start=callback_start, end=callback_end, file_offset=callback_offset,
                           sha256=hashlib.sha256(callback_raw).hexdigest(), instructions=callback,
                           boundary_evidence='reviewed entry target and terminating RET; no unwind record'),
        pure_visibility_predicate=False, runtime_visibility_verified=False,
        transition_threshold=dict(address=threshold_address, file_offset=threshold_offset,
            bytes=threshold_bytes.hex(), float32=struct.unpack('<f', threshold_bytes)[0],
            units='unresolved; do not label as seconds'),
        limitations=['List ownership/types and method names not fully reconstructed.',
                     'Callback path to list decrement proven; virtual method names and actual callback scheduling/duration unresolved.',
                     'No UI clicks or Android execution; no calling native helpers from bot.'])
    output = ROOT / 'code-clues/ui-manager-code.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(roots=len(roots), fragments=len(fragments), instructions=len(rows),
                         reviewed_operations=len(groups), pure_visibility_predicate=False)))


if __name__ == '__main__':
    main()
