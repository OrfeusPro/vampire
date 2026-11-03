"""Publication v3 поверх неизменённых native drivers и их stage keys."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def run(index, args, sha, journal, database, *, cache_only=False):
    parent = index.extension('update-native-drivers-v2')
    proxy = SimpleNamespace(**vars(index))
    extension = index.extension
    proxy.extension = lambda name: extension('native-publication-v3') if name == 'native-publication-v2' else extension(name)
    return parent.run(proxy, args, sha, journal, database, cache_only=cache_only)


def merge(native, checks, extra):
    spec = importlib.util.spec_from_file_location('drivers_v3_parent', HERE/'update-native-drivers-v2.py')
    parent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parent)
    return parent.merge(native, checks, extra)
