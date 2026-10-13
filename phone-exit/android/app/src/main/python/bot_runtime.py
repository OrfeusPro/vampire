"""Load verified private packages. No network, OCR or platform dependencies."""
import importlib.util
import json
import time
import re
from pathlib import Path

_loaded = None
_module = None
_state = {}


class HostError(RuntimeError):
    pass


class Host:
    def __init__(self, bridge):
        self.bridge = bridge
        self.timings = {}

    def call(self, command, **args):
        started = time.monotonic()
        result = json.loads(str(self.bridge.call(command, json.dumps(args))))
        self.timings[command] = self.timings.get(command, 0) + round((time.monotonic() - started) * 1000)
        if 'error' in result:
            reason = str(result['error'])
            raise HostError(reason if re.fullmatch(r'[a-z0-9_]{1,80}', reason) else 'bot_host_failed')
        return result


def tick(directory, generation, bridge, settings):
    global _loaded, _module, _state
    key = (directory, generation)
    if _loaded != key:
        spec = importlib.util.spec_from_file_location('phoneexit_game', Path(directory) / 'bot.py')
        _module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_module)
        _state = {}
        _loaded = key
    host = Host(bridge)
    try:
        result = _module.tick(host, json.loads(settings), _state, directory)
    except HostError as error:
        result = {'status': 'error', 'step': 'host_operation_failed', 'error': str(error), 'pause': True}
    result['hostTimingsMs'] = host.timings
    return json.dumps(result, ensure_ascii=False)
