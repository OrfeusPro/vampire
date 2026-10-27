"""Generate reviewable source-specific SDK replay candidates from fixed alignment.

Generated files are ordinary Python, never loaded through a runtime AST adapter.
Generation does not claim semantic verification or activate a profile.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import io
import tokenize

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(root, alignment, exports):
    align = load('align-sdk-batch-11318')
    alignment = Path(alignment).resolve()
    if alignment.parent.name != hashlib.sha256(alignment.read_bytes()).hexdigest():
        raise ValueError('SDK alignment manifest digest differs')
    report = json.loads(alignment.read_text('utf-8'))
    if report['source_sha256'] != align.NEW or report['baseline_sha256'] != align.OLD or report['unknown']:
        raise ValueError('SDK alignment unresolved or source differs')
    native = load('build-native-entry-code')
    images = {}
    for sha in (align.OLD, align.NEW):
        raw = (root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('SDK generation source differs')
        images[sha] = native.Image(raw)
    links = {int(a, 16):int(bs[0], 16) for a, bs in report['links'].items() if len(bs) == 1}

    def address(at):
        if at not in links:
            raise ValueError('Unmapped SDK replay address ' + hex(at))
        return links[at]

    def payload(sha, at, size):
        image = images[sha];off = image.offset(at - image.pe.base)
        return image.data[off:off + size]

    current_exports = {}
    available = set()
    for path in exports:
        path = Path(path).resolve()
        if not path.is_relative_to((root / 'ghidra/request-exports' / align.NEW).resolve()) or path.name != 'details.json':
            raise ValueError('SDK export outside current source library')
        data = path.read_bytes();document = json.loads(data)
        if document['new_source_sha256'] != align.NEW:
            raise ValueError('SDK export source differs')
        current_exports[path.parent.name] = hashlib.sha256(data).hexdigest()
        available.update(int(f['address'], 16) for f in document['functions'] if f['decompilation_completed'])
    if not set(int(v, 16) for v in report['roots'].values()) <= available:
        raise ValueError('Current SDK export root missing')
    # Export references are selected per generated replay below. Old artifacts
    # remain immutable; no old digest is relabelled as evidence for a new source.
    file_names = {name + '.py':name.replace('11316', '11318') + '.py' for name in align.SCRIPTS}
    export_replacements = {}
    old_artifacts = set()
    for name in align.SCRIPTS:
        tree = ast.parse((HERE / (name + '.py')).read_text('utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(r'run-[a-f0-9]{12}', node.value):
                old_artifacts.add(node.value)
    # The first export is the newly collected batch. The remaining receipts
    # supply the shared roots already checked in previous packages.
    current_run, current_digest = next(iter(current_exports.items()))
    for run in old_artifacts:
        path = root / 'ghidra/request-exports' / align.OLD / run / 'details.json'
        if not path.is_file():
            raise ValueError('Baseline SDK export missing ' + run)
        export_replacements[run] = current_run
        export_replacements[hashlib.sha256(path.read_bytes()).hexdigest()] = current_digest
    byte_replacements = {}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True

    def leaf(at, size):
        new = address(at);before = payload(align.OLD, at, size);after = payload(align.NEW, new, size)
        a = list(decoder.disasm(before, at));b = list(decoder.disasm(after, new))
        if sum(i.size for i in a) != size or len(a) != len(b) or sum(i.size for i in b) != size:
            raise ValueError('SDK leaf instruction coverage differs')
        for x, y in zip(a, b):
            encoded = []
            for ins in (x, y):
                raw = bytearray(ins.bytes)
                if ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP):
                    if ins.imm_size:
                        target = ins.operands[0].imm
                        if ins is x:
                            target_old = target
                        elif at <= target_old < at + size:
                            if target - new != target_old - at:
                                raise ValueError('SDK leaf local branch differs')
                        elif address(target_old) != target:
                            raise ValueError('SDK leaf target binding differs')
                        raw[ins.imm_offset:ins.imm_offset + ins.imm_size] = bytes(ins.imm_size)
                if any(op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP for op in ins.operands):
                    old_target = x.address + x.size + next(op.mem.disp for op in x.operands if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP)
                    new_target = y.address + y.size + next(op.mem.disp for op in y.operands if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP)
                    if old_target in links and links[old_target] != new_target:
                        raise ValueError('SDK leaf RIP link differs')
                    links[old_target] = new_target
                    raw[ins.disp_offset:ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
                encoded.append(raw)
            if encoded[0] != encoded[1]:
                raise ValueError('SDK leaf native shape changed')
        byte_replacements[before.hex()] = after.hex()
        byte_replacements[hashlib.sha256(before).hexdigest()] = hashlib.sha256(after).hexdigest()

    for at, size in ((0x14145f1e0, 0x47), (0x14145f230, 0x4b), (0x144552240, 7), (0x141453890, 5)):
        leaf(at, size)
    # Source-pinned branch and mode-mask bytes in the static NID audit.
    for at, size in ((0x1450f30bb, 5), (0x1450f43a1, 11)):
        leaf(at, size)
    class Port(ast.NodeTransformer):
        def visit_Assign(self, node):
            if any(isinstance(target, ast.Name) and target.id in ('EXPORTS', 'exports') for target in node.targets):
                node.value = ast.parse(repr(current_exports), mode='eval').body
                return node
            return self.generic_visit(node)

        def visit_Constant(self, node):
            value = node.value
            if isinstance(value, int) and 0x140000000 <= value < 0x150000000:
                return ast.copy_location(ast.Constant(address(value)), node)
            if isinstance(value, str):
                if value.startswith('Source-bound 1.13.16 '):value=value.replace('1.13.16','1.13.18',1)
                if value in byte_replacements:value = byte_replacements[value]
                elif value in export_replacements:value = export_replacements[value]
                elif value == align.OLD:value = align.NEW
                elif value in file_names:value = file_names[value]
                elif align.OLD in value:value = value.replace(align.OLD, align.NEW)
                elif value.startswith('code-clues/') or '/code-clues/' in value:value = value.replace('11316', '11318')
                return ast.copy_location(ast.Constant(value), node)
            return node

        def visit_Call(self, node):
            self.generic_visit(node)
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'make_harness':
                node.keywords.extend((ast.keyword(arg='source_sha256', value=ast.Constant(align.NEW)),
                                      ast.keyword(arg='copy_thunk', value=ast.Constant(address(0x1487f5ab9)))))
            return node
    generated = {}
    for name in align.SCRIPTS:
        path = HERE / (name + '.py');source = path.read_text('utf-8')
        tree = Port().visit(ast.parse(source));ast.fix_missing_locations(tree)
        target = HERE / file_names[path.name]
        text = '# Generated candidate by generate-sdk-replays-11318.py; review and native replay required.\n'
        text += ast.unparse(tree) + '\n'
        if name == 'replay-sdk-overrides-11316':
            permitted = {address(at) for at in (0x14125b710, 0x1456579d0, 0x14125b740,
                0x14125b770, 0x14125b7d0, 0x14560aed0, 0x144529d60, 0x1444b3290)}
            marker = "        for function in report['functions']:\n"
            if text.count(marker) != 1:raise ValueError('SDK override export filter site changed')
            text = text.replace(marker, marker + '            if int(function[\'address\'], 16) not in ' + repr(permitted) + ':\n                continue\n')
        if name == 'audit-nid-result-11316':
            marker = "functions = {int(f['address'], 16): f for f in report['functions']}"
            replacement = "functions = {int(f['address'], 16): f for f in report['functions'] if int(f['address'], 16) in " + repr({address(0x1450f2c80), address(0x1450f3e40)}) + '}'
            if text.count(marker) != 1:raise ValueError('NID static root filter site changed')
            text = text.replace(marker, replacement)
        tokens=[]
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type==tokenize.NUMBER:
                try:value=int(token.string,0)
                except ValueError:value=0
                if 0x140000000<=value<0x150000000:
                    token=token._replace(string=hex(value))
            tokens.append(token)
        text=tokenize.untokenize(tokens)
        generated[target] = text
    # Fail before writing any generated file if an address is unresolved.
    for path, text in generated.items():
        compile(text, str(path), 'exec')
    for path, text in generated.items():
        path.write_text(text, encoding='utf-8', newline='\n')
    switches=[]
    for item in report['switches']:
        raw=payload(align.NEW,int(item['table'],16),item['count']*4)
        switches.append(dict(item,bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()))
    context=dict(schema=1,source_sha256=align.NEW,baseline_sha256=align.OLD,
                 roots=report['roots'],exports=current_exports,switches=switches,
                 alignment_sha256=hashlib.sha256(alignment.read_bytes()).hexdigest(),
                 generated_files={path.name:hashlib.sha256(text.encode()).hexdigest() for path,text in generated.items()},
                 limits=['Fixed SDK/GMC2/NID source roots; no active settings, authentication or runtime promotion.'])
    context_path=HERE/'knowledge/native-contexts/sdk-batch-11318.json'
    context_path.write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    output = dict(source_sha256=align.NEW, alignment=str(alignment), alignment_sha256=hashlib.sha256(alignment.read_bytes()).hexdigest(),
                  baseline_scripts={name+'.py':hashlib.sha256((HERE/(name+'.py')).read_bytes()).hexdigest() for name in align.SCRIPTS},
                  generated={str(path):hashlib.sha256(text.encode()).hexdigest() for path, text in generated.items()},
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  context=str(context_path),context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
                  semantic_verification=False, network_used=False, profile_activated=False)
    return load('research-workflow').snapshot(root, 'sdk-batch-generated-11318', output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--alignment', type=Path, required=True)
    parser.add_argument('--export', type=Path, action='append', required=True)
    args = parser.parse_args()
    print(run(args.root, args.alignment, args.export))
