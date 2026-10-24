"""Append stable per-resource checkbox tasks without changing existing marks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sync(index_path, destination):
    index = json.loads(index_path.read_text('utf-8'))
    if destination.exists():
        text = destination.read_text('utf-8')
    else:
        text = ('# Окна Vampir: задачи восстановления\n\n'
                'Дополняет [основной план](UI-TASKS.md), этапы UI-01 / UI-11 / UI-12.\n'
                'ID построен из полного пути ресурса и не зависит от порядка каталога.\n'
                'Архивные варианты относятся к одному пункту; дочерний виджет не считается\n'
                'отдельным игровым экраном. Здесь учитывается весь извлечённый каталог.\n\n'
                'Критерий закрытия каждого пункта: установлен тип компонента и его место\n'
                'в иерархии, восстановлены доступные оформление и контролы, известные\n'
                'переходы интерактивны, ограничения указаны и результат проверен.\n'
                'Просмотр структуры в каталоге проверки сам по себе пункт не закрывает.\n'
                'Для неизвестных действий добавлять вложенные подзадачи с чекбоксами.\n\n')
    added = 0
    spec = importlib.util.spec_from_file_location('ui_builder', HERE / 'build-ui-prototype.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    for path, variants in sorted(builder.catalog_entries(index).items()):
        task_id = 'UI-W-' + hashlib.sha256(path.encode()).hexdigest()[:12]
        if task_id + '.' in text:
            continue
        text += '- [ ] ' + task_id + '. `' + path + '` — вариантов: ' + str(len(variants)) + '.\n'
        added += 1
    destination.write_text(text, 'utf-8')
    return added


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, default=Path('F:/PhoneExit Resources/Vampir/ui-catalog/index.json'))
    parser.add_argument('--output', type=Path, default=HERE.parents[1] / 'vampir/UI-WINDOW-TASKS.md')
    args = parser.parse_args()
    print(json.dumps(dict(added=sync(args.index, args.output), output=str(args.output)), ensure_ascii=False))
