"""Native CDN fallback orchestration with explicit SHA/EVP backend shims."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fallback_body', HERE / 'build-headless-cdn-body.py')
body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(body)
FALLBACK, DIGEST, GET_CIPHER = 0x145653dd0, 0x1483f9cd0, 0x14840a8b0
NEW, INIT, UPDATE, FINAL, FREE = 0x148406230, 0x148406a20, 0x148406a50, 0x148406850, 0x1484061f0
DESCRIPTORS = (0x14a723e80, 0x14a723e20)
CPU_FLAGS = 0x14b6319e4


def backend_info():
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    return dict(cryptography=cryptography.__version__, openssl=backend.openssl_version_text())


class FallbackEmulator(body.BodyEmulator):
    def __init__(self, raw, image, fragments, fail=None, cpu_flags=0):
        super().__init__(raw, image, fragments)
        self.fail = fail
        if fail not in (None, 'init', 'update', 'final') or cpu_flags not in (0, 0x2000000):
            raise ValueError('Invalid fallback fixture override')
        roots = {image.roots[image.containing(a)][0] for a in [FALLBACK, 0x1445df150]}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra.append((GET_CIPHER, GET_CIPHER + 29))
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        pages.update(a & ~4095 for a in [DIGEST, NEW, INIT, UPDATE, FINAL, FREE, CPU_FLAGS, *DESCRIPTORS])
        for f in fragments:
            for row in f['instructions']:
                if any(lo <= row['address'] < hi for lo, hi in extra):
                    pages.update(a & ~4095 for a in row['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[off:off + 4096])
        self.uc.mem_write(CPU_FLAGS, struct.pack('<I', cpu_flags))
        self.cpu_flags = cpu_flags
        self.ctx, self.decryptor, self.unpadder = None, None, None
        self.captured = {}

    def shim_return(self, result, kind):
        rsp = self.uc.reg_read(self.x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(self.uc.mem_read(rsp, 8)))[0]
        self.uc.reg_write(self.x.UC_X86_REG_RAX, result)
        self.uc.reg_write(self.x.UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(self.x.UC_X86_REG_RIP, ret)
        self.calls.append(dict(kind=kind))

    def hook(self, uc, address, size, user):
        x = self.x
        a, b, c, d = [uc.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
        if address == 0x1487a2e25:
            self.bounded(a, c)
            uc.mem_write(a, bytes([b & 255]) * c)
            self.shim_return(a, 'bounded_memset')
            return
        if address == DIGEST:
            self.bounded(a, b)
            self.bounded(c, 32)
            seed = bytes(uc.mem_read(a, b))
            digest = hashlib.sha256(seed).digest()
            uc.mem_write(c, digest)
            self.captured.update(seed_hex=seed.hex(), sha256_hex=digest.hex())
            self.shim_return(c, 'sha256_backend_shim')
            return
        if address == NEW:
            if self.ctx is not None:
                raise ValueError('Duplicate fallback context allocation')
            self.ctx = self.allocate(128)
            self.shim_return(self.ctx, 'evp_new_fixture')
            return
        if address in (INIT, UPDATE, FINAL, FREE):
            if a != self.ctx or self.ctx is None:
                raise ValueError('Unexpected fallback EVP context')
            if address == FREE:
                del self.allocations[self.ctx]
                self.ctx, self.decryptor, self.unpadder = None, None, None
                self.shim_return(0, 'evp_free_fixture')
                return
            if address == INIT:
                from cryptography.hazmat.primitives import padding
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                if b not in DESCRIPTORS or c != 0:
                    raise ValueError('Unexpected fallback cipher/engine')
                self.bounded(d, 32)
                key = bytes(uc.mem_read(d, 32))
                rsp = uc.reg_read(x.UC_X86_REG_RSP)
                iv_ptr = struct.unpack('<Q', bytes(uc.mem_read(rsp + 0x28, 8)))[0]
                self.bounded(iv_ptr, 16)
                iv = bytes(uc.mem_read(iv_ptr, 16))
                self.captured.update(cipher_descriptor=b, key_hex=key.hex(), iv_hex=iv.hex())
                self.decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                self.unpadder = padding.PKCS7(128).unpadder()
                self.shim_return(int(self.fail != 'init'), 'evp_init_backend_shim')
                return
            self.bounded(c, 4)
            if address == UPDATE:
                rsp = uc.reg_read(x.UC_X86_REG_RSP)
                length = struct.unpack('<I', bytes(uc.mem_read(rsp + 0x28, 4)))[0]
                if length:
                    self.bounded(d, length)
                encrypted = bytes(uc.mem_read(d, length)) if length else b''
                self.captured['ciphertext_hex'] = encrypted.hex()
                output = self.unpadder.update(self.decryptor.update(encrypted))
                success, kind = self.fail != 'update', 'evp_update_backend_shim'
            else:
                try:
                    output = self.unpadder.update(self.decryptor.finalize()) + self.unpadder.finalize()
                    success = self.fail != 'final'
                except ValueError:
                    output, success = b'', False
                kind = 'evp_final_backend_shim'
            self.bounded(b, len(output))
            if output:
                uc.mem_write(b, output)
            uc.mem_write(c, struct.pack('<i', len(output)))
            self.shim_return(int(success), kind)
            return
        return super().hook(uc, address, size, user)

    def decrypt(self, payload):
        if not isinstance(payload, bytes) or len(payload) > 512:
            raise ValueError('Synthetic fallback fixture exceeds budget')
        span, data, output = self.scratch + 0x1000, self.scratch + 0x10000, self.scratch + 0x6000
        self.uc.mem_write(data, payload or b'\0')
        self.uc.mem_write(span, struct.pack('<QQQ', data, data + len(payload), data + len(payload)))
        self.run(FALLBACK, rcx=self.scratch + 0x2000, rdx=output, r8=span)
        if self.ctx is not None:
            raise ValueError('Fallback context was not freed')
        return dict(payload_hex=payload.hex(), output_hex=self.string_bytes(output).hex(),
                    fail_fixture=self.fail, cpu_flags_fixture=self.cpu_flags,
                    captured=self.captured, calls=list(self.calls), evp_context_freed=True,
                    crypto_primitives_are_backend_shims=True)


def encrypt_fixture(plaintext, key, iv, pad=True):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if pad:
        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def build():
    config = body.head.headers.uri.http.preparation.url.settings.config
    native = config.native
    prior_path = native.ROOT / 'code-clues/headless-cdn-body.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = native.Image(raw)
    addresses = [body.head.HEAD_SIZE, body.head.STATUS, body.head.AVAILABLE, body.head.SCAN,
                 FALLBACK, DIGEST, INIT, UPDATE, FINAL, 0x1445df150, body.CALLBACK]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    literal = config.read_literal(raw, image, rows[0x145653e5b]['rip_references'][0])
    seed = literal['text'].encode('ascii')
    if len(seed) != 28:
        raise ValueError('Fallback seed literal changed')
    anchors = []
    for address, count in [(GET_CIPHER, 29), *[(a, 96) for a in DESCRIPTORS]]:
        off = image.offset(address - image.pe.base)
        data = raw[off:off + count]
        anchors.append(dict(address=address, file_offset=off, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    # Bind native descriptor nid 427 to its exact compiled ASN.1 name record.
    name = b'AES-256-CBC\0'
    off = raw.index(name)
    pointer = struct.pack('<Q', image.pe.address(off))
    record = raw.index(pointer)
    record_bytes = raw[record:record + 40]
    if struct.unpack_from('<I', record_bytes, 16)[0] != 427:
        raise ValueError('Cipher name record changed')
    name_binding = dict(name='AES-256-CBC', name_file_offset=off, name_bytes=name.hex(),
                        record_file_offset=record, record_bytes=record_bytes.hex(), nid=427)
    key, iv = hashlib.sha256(seed).digest(), bytes(range(16))
    valid = [encrypt_fixture(plain, key, iv) for plain in
             [b'', b'{}', b'{"NetmarbleS":{"Zone":"real"}}', 'Привет'.encode(), b'a\0b', b'x' * 15, b'x' * 16, b'x' * 128]]
    inputs = [b'', b'x', b'x' * 15, iv, iv + b'x', iv + b'x' * 15] + valid
    inputs += [encrypt_fixture(b'x' * 16, key, iv, pad=False),
               encrypt_fixture(b'x' * 15 + b'\0', key, iv, pad=False), valid[2][:-1]]
    cases = [FallbackEmulator(raw, image, fragments).decrypt(payload) for payload in inputs]
    failure_cases = [FallbackEmulator(raw, image, fragments, fail=step).decrypt(valid[2])
                     for step in ('init', 'update', 'final')]
    alternate = FallbackEmulator(raw, image, fragments, cpu_flags=0x2000000).decrypt(valid[2])
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                body_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, seed_literal=literal, anchors=anchors, cipher_name_binding=name_binding,
                cases=cases, failure_cases=failure_cases, alternate_descriptor_case=alternate,
                backend=backend_info(), network_ready=False, limitations=[
                    'Whole native fallback orchestration executes, including actual cipher getter and descriptor selection.',
                    'SHA256 and EVP primitives are explicit hashlib/cryptography backend shims, not execution of native crypto core.',
                    'Native argument capture proves seed bytes, key/IV/ciphertext split, cipher descriptor and result/error handling.',
                    'Only synthetic ciphertext/IV/plaintext; no actual CDN response, network, process or account data.',
                    'Callback branch to fallback remains static evidence; full JSON parser/callback and downstream config not executed.'])


if __name__ == '__main__':
    report = build()
    target = body.head.headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-fallback.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_orchestration_cases=len(report['cases']) + len(report['failure_cases']) + 1), indent=2))
