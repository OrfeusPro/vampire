"""Source-bound SDK auth graph. Static installed-client data only; no Saved files."""
import hashlib,importlib.util,json,re
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('auth_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

SELECTORS=[
    'Netmarble::Service::FAuthImpl::SignIn(',
    'Netmarble::Service::FAuthImpl::ExecSignIn(',
    'Netmarble::Service::FAuthImpl::SignInSilently(',
    'Netmarble::Service::FAuthImpl::RefreshToken(',
    'Netmarble::Service::FAuthImpl::GetTokenByLauncher(',
    'Netmarble::Service::FAuthImpl::SignInByLauncher(',
    'Netmarble::Service::FChannelManagerImpl::CreateLauncherCredential(',
    'Netmarble::Service::FChannelManagerImpl::IsRunningOnLauncher(',
    'Netmarble::Service::FNetmarbleIDProvider::SignIn(',
    'Netmarble::Service::FNetmarbleIDProvider::InternalSignIn(',
    'Netmarble::Service::FNetmarbleIDProvider::ShowWebview(',
    'Netmarble::Service::FNetmarbleIDProvider::GetAccessTokenByAuthorizationCode(',
    'Netmarble::Service::FNetmarbleIDProvider::GetAccessTokenByRefreshToken(',
    'Netmarble::Service::FNetmarbleIDProvider::GetUserDetail(',
    'Netmarble::Service::FNetmarbleIDProvider::IdpSignIn(',
    'Netmarble::Service::FNetmarbleIDProvider::GetIdpToken(',
    'Netmarble::Service::FNetmarbleIDProvider::GetCredential(',
    'Netmarble::Service::FNetmarbleIDProvider::SignInSilentlyOnStandalone(',
    'Netmarble::Service::FNetmarbleIDProvider::SignInSilentlyOnLauncher(',
    'Netmarble::Service::FNetmarbleIDContent::ApplyImmutableConfig(',
    'Netmarble::Service::FNetmarbleIDContent::OnDeepLink(',
    'Netmarble::Service::FNetmarbleIDContent::OnSignIn(',
    'Netmarble::Service::FNetmarbleIDContent::OnFinishSignIn(',
    'Netmarble::Service::FNetmarbleIDContent::SendSignInCallback(',
]


def native_escape_primitives():
    spec=importlib.util.spec_from_file_location('auth_ping',HERE/'build-headless-ping-codec.py')
    ping=importlib.util.module_from_spec(spec);spec.loader.exec_module(ping)
    emulator=ping.PingEmulator();cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    cs.detail=True;bodies=[];references=set()
    for address in [0x141c06750,0x1415ad670]:
        off=emulator.image.offset(address-emulator.image.pe.base);instructions=[]
        for i in cs.disasm(emulator.raw[off:off+2048],address):
            instructions.append(i)
            for op in i.operands:
                if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP:
                    references.add(i.address+i.size+op.mem.disp)
            if i.mnemonic=='call':raise ValueError('Escape helper has unexpected calls')
            if i.mnemonic=='ret':break
        if not instructions or instructions[-1].mnemonic!='ret':raise ValueError('Escape leaf not bounded')
        size=instructions[-1].address+instructions[-1].size-address
        content=emulator.raw[off:off+size]
        bodies.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest()))
        emulator.ranges.append((address,address+size))
    pages={p for row in bodies for p in range(row['address']&~4095,(row['address']+len(bytes.fromhex(row['bytes']))+4095)&~4095,4096)}
    pages.update(a&~4095 for a in references);regions=list(emulator.uc.mem_regions())
    for page in pages:
        if any(lo<=page<=hi for lo,hi,_ in regions):continue
        emulator.uc.mem_map(page,4096)
        try:off=emulator.image.offset(page-emulator.image.pe.base)
        except ValueError:continue
        emulator.uc.mem_write(page,emulator.raw[off:off+4096])
    data_proofs=[]
    for address in sorted(references):
        try:off=emulator.image.offset(address-emulator.image.pe.base)
        except ValueError:continue
        data=emulator.raw[off:off+128]
        data_proofs.append(dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
    emulator.copy_sizes=[];emulator.io_entries=[];cases=[];b=emulator.scratch
    for value in range(256):
        safe=emulator.call(0x141c06750,value)
        emulator.uc.mem_write(b+0x1000,bytes([value]))
        import struct
        emulator.uc.mem_write(b+0x2000,struct.pack('<QI',b+0x1000,1))
        emulator.call(0x1415ad670,b+0x2000,b+0x3000)
        text=bytes(emulator.uc.mem_read(b+0x3000,4)).decode('utf-16le')
        if text!=f'{value:02X}':raise ValueError('Native hex conversion differs')
        cases.append(dict(byte=value,safe=safe,hex=text))
    return dict(bodies=bodies,data=data_proofs,cases=cases,
                safe_ascii=''.join(chr(row['byte']) for row in cases if row['safe']))


def main():
    upstream=native.ROOT/'code-clues/headless-network-index.json'
    meta=json.loads(upstream.read_text('utf-8'));raw=Path(meta['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=meta['sha256']:raise ValueError('Client changed')
    image=native.Image(raw);symbols=[]
    for match in re.finditer(rb'[ -~]{8,}',raw):
        text=match.group().decode('ascii')
        selected=[s for s in SELECTORS if s in text]
        if not selected:continue
        address=image.pe.address(match.start())
        if address is None:continue
        data=match.group()+b'\0'
        if raw[match.end()]!=0:raise ValueError('Unterminated SDK diagnostic')
        symbols.append(dict(selectors=selected,name=text,address=address,file_offset=match.start(),
                            bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
    targets={s['address']:s for s in symbols}
    candidates=native.rip_candidates(image,targets)
    roots={image.roots[f] for address,_ in candidates if (f:=image.containing(address)) is not None}
    fragments=native.decode_ranges(image,roots)
    rows={i['address']:i for f in fragments for i in f['instructions']}
    xrefs=[];rejected=[]
    for address,target in candidates:
        row=rows.get(address)
        if row is None or row['mnemonic']!='lea' or target not in row['rip_references']:
            rejected.append(dict(address=address,target=target));continue
        xrefs.append(dict(symbol=targets[target]['name'],selectors=targets[target]['selectors'],
                          instruction=row,root=image.pe.base+image.roots[image.containing(address)][0]))
    helpers=native.decode_ranges(image,{image.roots[image.containing(a)] for a in
                                       [0x14451c570,0x14451c600,0x144586a30,0x141c13850]})
    constants=[]
    constant_rows={i['address']:i for f in fragments+helpers for i in f['instructions']}
    for row in constant_rows.values():
        if row['mnemonic']!='lea':continue
        for address in row['rip_references']:
            try:off=image.offset(address-image.pe.base)
            except ValueError:continue
            data=raw[off:off+2048];encoding='utf-16le' if data[1:2]==b'\0' else 'ascii'
            if encoding=='utf-16le':
                end=next((i for i in range(0,len(data)-1,2) if data[i:i+2]==b'\0\0'),None)
            else:end=data.find(b'\0')
            if end is None or end<2:continue
            content=data[:end+(2 if encoding=='utf-16le' else 1)]
            try:text=data[:end].decode(encoding)
            except UnicodeDecodeError:continue
            if not text or not all(c.isprintable() for c in text) or len(text)>600:continue
            # Diagnostic/type strings are already recorded; retain short protocol/config values.
            if '__cdecl' in text or text.startswith('.?AV'):continue
            constants.append(dict(text=text,encoding=encoding,address=address,file_offset=off,
                                  bytes=content.hex(),instruction=row))
    present={s for row in symbols for s in row['selectors']}
    escape=native_escape_primitives()
    report=dict(schema_version=1,source=meta['source'],sha256=meta['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),selectors=SELECTORS,
                symbols=symbols,xrefs=xrefs,rejected_candidates=rejected,fragments=fragments,
                referenced_constants=constants,missing=[s for s in SELECTORS if s not in present],
                request_helper_fragments=helpers,escape_primitives=escape,
                statistics=dict(symbols=len(symbols),xrefs=len(xrefs),roots=len(roots),constants=len(constants),native_escape_cases=512),
                network_ready=False,limitations=['Static SDK diagnostic LEA roots/constants only, not complete execution/call semantics.',
                'No launcher/process/browser memory, Saved profile, tokens, account or network access.',
                'URLs/config keys are client candidates, not verified current production endpoints.',
                'Password/auth-code/refresh-token acquisition and game Login handoff remain incomplete.'])
    path=native.ROOT/'code-clues/headless-auth-index.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],safe_ascii=escape['safe_ascii'],missing=report['missing'],rejected=len(rejected))))


if __name__=='__main__':main()
