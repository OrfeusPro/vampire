"""Read only explicit WidgetTree.RootWidget; unreviewed bindings fail closed."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('widget_tree_unversioned', Path(__file__).with_name('decode-canvas-slots.py'))
canvas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canvas)


def decode_root(raw):
    reader = canvas.Reader(raw)
    fields = reader.header()
    if fields not in ([], [(0, False)], [(0, True)]):
        raise ValueError('Unreviewed WidgetTree properties; no root inferred')
    value = None if not fields else 0 if fields[0][1] else reader.read('<i')
    if reader.read('<I') != 0 or reader.pos != len(raw):
        raise ValueError('Unaccounted WidgetTree suffix')
    return dict(explicit_root_widget=value, serialized_fields=fields,
                root_omitted=not fields, inherited_defaults_applied=False)
