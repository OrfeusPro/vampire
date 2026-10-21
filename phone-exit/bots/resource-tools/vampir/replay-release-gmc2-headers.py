"""Current GMC2 constructor and request header slice; synthetic HTTP captures only."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.gmc2_request import plan_gmc2_get_request

START, STOP, GMC = 0x1444fcc70, 0x1444fcec1, 0x1444c5080


def main():
    spec = importlib.util.spec_from_file_location('current_gmc_url', HERE / 'replay-release-gmc2-url.py')
    url = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(url)
    h = url.make_harness(extra_addresses=(START, GMC))
    rbp, manager, settings = h.gmc_rbp, h.gmc_manager, h.gmc_settings
    h.gmc_build_output = rbp - 0x48
    request, table, account_class, account = [h.scratch + n for n in (0x1b000, 0x1a000, 0x1c000, 0x1d000)]
    url_string, service, etag = [h.scratch + n for n in (0x17000, 0x17100, 0x17200)]
    set_url, set_header, set_method = [h.scratch + n for n in (0x3d000, 0x3d010, 0x3d020)]
    h.uc.mem_write(request, struct.pack('<Q', table))
    for offset, target in ((0x68, set_url), (0xb0, set_header), (0x60, set_method)):
        h.uc.mem_write(table + offset, struct.pack('<Q', target))
    h.uc.mem_write(account_class + 0x110, struct.pack('<Q', account))
    values, headers, options, events = {}, [], {}, []

    def text(address):
        if not h.scratch <= address <= h.scratch + 0x40000 - 16:
            raise ValueError('Header FString object bound')
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 256:
            raise ValueError('Header FString counts')
        if not count:
            return ''
        if not h.scratch <= pointer <= h.scratch + 0x40000 - count * 2:
            raise ValueError('Header FString data bound')
        data = bytes(h.uc.mem_read(pointer, count * 2))
        if data[-2:] != bytes(2):
            raise ValueError('Header FString termination')
        return data[:-2].decode('utf-16le')

    original_utf16 = h.fixtures[0x141426c10]

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        result = 0
        if address in (set_url, set_header, set_method):
            if a != request:
                raise ValueError('HTTP capture receiver changed')
            if address == set_header:
                headers.append((text(b), text(c)))
            else:
                key = 'url' if address == set_url else 'method'
                if key in values:
                    raise ValueError('Duplicate HTTP property')
                values[key] = text(b)
            events.append(dict(action='http_virtual_capture', target=hex(address)))
        elif address in (0x141426a30, 0x141426c10):
            if address == 0x141426c10 and not manager <= a <= manager + 0x300 - 16:
                original_utf16(machine)
                return
            if not (manager <= a <= manager + 0x300 - 16 or rbp - 0x80 <= a <= rbp or a == h.scratch + 0x8060):
                raise ValueError('Header literal storage destination')
            offset = h.image.offset(b - h.image.pe.base)
            data = h.raw[offset:offset + 512]
            width = 2 if address == 0x141426c10 else 1
            end = next(i for i in range(0, len(data) - width + 1, width) if data[i:i + width] == bytes(width))
            h.gmc_put(a, data[:end].decode('utf-16le' if width == 2 else 'ascii'))
            result = a
        elif address == 0x1444ed700:
            if a != rbp - 0x38:
                raise ValueError('Device-key fixture destination')
            h.gmc_put(a, options['device_key'])
            result = a
        elif address in (0x1444b22a0, 0x1444b23c0):
            result = account_class
        elif address == 0x14452c490:
            if a != account or b != rbp - 0x28:
                raise ValueError('Player-id fixture receiver/destination')
            h.gmc_put(b, options['player_id'])
            result = b
        else:
            raise ValueError('Unreviewed GMC2 header fixture')
        h.gmc_finish(result)

    fixture_addresses = (set_url, set_header, set_method, 0x141426a30, 0x141426c10,
                         0x1444ed700, 0x1444b22a0, 0x1444b23c0, 0x14452c490)
    for address in fixture_addresses:
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
        h.fixtures[address] = fixture

    def run(inputs):
        options.clear(); options.update(inputs)
        values.clear(); headers.clear(); events.clear()
        h.gmc_heap[0] = h.scratch + 0x20000
        h.uc.mem_write(manager - 16, b'\xa5' * 0x320)
        if h.call(GMC, manager, budget=10000) != manager:
            raise ValueError('GMC constructor return differs')
        if text(manager + 0x190) != 'netmarbles' or text(manager + 0x1c8) != 'netmarbles-v5':
            raise ValueError('Current constructor service/group differs')
        for initializer in url.INITIALIZERS:
            h.call(initializer, 0, budget=1024)
        h.gmc_put(settings + 0x38, inputs['game_code'])
        h.uc.mem_write(settings + 0x48, bytes([inputs['build_code']]))
        h.gmc_put(account + 0x78, inputs['access_token'])
        for destination, value in ((url_string, inputs['url']), (service, inputs['service_code']), (etag, inputs['etag'])):
            h.gmc_put(destination, value)
        stack = h.scratch + 0x8000
        h.uc.mem_write(stack + 0x38, struct.pack('<Q', request))
        h.uc.mem_write(stack + 0x60, struct.pack('<Q', service))
        for reg, value in ((h.x.UC_X86_REG_RSP, stack), (h.x.UC_X86_REG_RBP, rbp),
                           (h.x.UC_X86_REG_R14, manager), (h.x.UC_X86_REG_R12, etag), (h.x.UC_X86_REG_RDI, url_string)):
            h.uc.reg_write(reg, value)
        h.uc.emu_start(START, STOP, count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('Header slice instruction budget')
        plan = plan_gmc2_get_request(**inputs)
        if values != dict(url=plan.url, method=plan.method) or tuple(headers) != plan.headers:
            raise ValueError('Current native HTTP capture differs from portable plan')
        if bytes(h.uc.mem_read(manager - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(manager + 0x300, 16)) != b'\xa5' * 16:
            raise ValueError('GMC constructor crossed manager guards')
        return dict(inputs=inputs, actual=dict(**values, headers=headers.copy()), events=events.copy(), guards_unchanged=True)

    cases = [run(dict(url='https://config.invalid/request', service_code='service-fixture', game_code='game-fixture',
                      build_code=code, etag=tag, access_token=token, device_key='device-fixture', player_id='player-fixture'))
             for code, tag, token in itertools.product((0, 1, 2, 255), ('', 'etag-fixture'), ('', 'token-fixture'))]
    cases.append(run(dict(url='https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp',
                          service_code='netmarbles', game_code='thered', build_code=0, etag='', access_token='', device_key='', player_id='')))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
                  ghidra_evidence=h.gmc_evidence, fragments=h.fragments, start=hex(START), stop=hex(STOP), cases=cases,
                  fixtures=[hex(a) for a in (*h.gmc_fixtures, *fixture_addresses)],
                  dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-gmc2-url.py',
                      'replay-release-archive-input.py', 'replay-release-nested-read-thunk.py', 'build-native-entry-code.py', 'requirements-native.txt')},
                  portable_helper_sha256=h.audit.sha256(HERE.parents[1] / 'vampir-shared/vampir_core/gmc2_request.py'),
                  native_execution=True, network_ready=False,
                  limits=['Actual current GMC2 constructor, build initializers/getter and HTTP argument/header slice execute.',
                          'HTTP virtual methods are captures; FString/CDO/allocator/free/device and player getters are explicit fixtures.',
                          'All identities are synthetic or explicitly empty. No request creation, TLS/console gates, HTTP transport or authentication.'])
    path = h.audit.save_snapshot(h.comparison / 'gmc2-headers-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
