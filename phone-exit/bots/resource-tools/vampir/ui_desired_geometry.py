"""Compile source-bound desired-size trees; excluded demo branches stay assumptions."""


def compile_tree(package, control_name, policy):
    controls = {row['export']: row for row in package['controls']}
    names = {}
    for row in controls.values():
        names.setdefault(row['name'], []).append(row)
    if len(names.get(control_name, [])) != 1:
        raise ValueError('Неоднозначный корень desired size: ' + control_name)
    excluded = policy.get('exclude', {})
    used_exclusions = set()
    children = {}
    for slot in package['decoded_slots']:
        children.setdefault(slot['decoded']['parent_export'], []).append(slot)

    def visit(row, seen):
        index = row['export']
        if index in seen:
            raise ValueError('Цикл desired size')
        seen = seen | {index}
        source = dict(export=index, name=row['name'], sha256=row['sha256'])
        if row['name'] in excluded:
            used_exclusions.add(row['name'])
            return dict(kind=row['type'], source=source, excluded_reason=excluded[row['name']])
        if row['type'] == 'SizeBox':
            sizes = row.get('size_constraints', {})
            w, h = sizes.get('WidthOverride', {}), sizes.get('HeightOverride', {})
            if w.get('status') != 'explicitly_enabled' or h.get('status') != 'explicitly_enabled':
                raise ValueError('Нужны обе явные размерности: ' + row['name'])
            return dict(kind='fixed', width=w['value'], height=h['value'], source=source,
                constraints=sizes, assumptions=['Использованы явные WidthOverride / HeightOverride ' + row['name'] + '; неизвестные inherited min/max в демо не применяются.'])
        if row['type'] not in ('Overlay', 'HorizontalBox', 'VerticalBox'):
            raise ValueError('Desired size не разобран: ' + row['name'])
        result = dict(kind=row['type'], source=source, children=[])
        for slot in children.get(index, []):
            d = slot['decoded']
            content = controls.get(d['content_export'])
            if not content:
                raise ValueError('Нет контрола desired size')
            child = dict(node=visit(content, seen), provenance=slot['provenance'])
            if child['node'].get('excluded_reason'):
                # A locally absent branch contributes neither content nor slot padding.
                child['padding'] = dict(left=0, top=0, right=0, bottom=0)
            elif 'padding' in d:
                child['padding'] = d['padding']
            elif policy.get('omitted_padding_zero'):
                child['padding'] = dict(left=0, top=0, right=0, bottom=0)
                child['node'].setdefault('assumptions', []).append('Несериализованный padding slot ' + str(slot['provenance']['slot_export']) + ' принят нулевым только в демо.')
            else:
                raise ValueError('Неизвестный padding desired size')
            result['children'].append(child)
        if not result['children']:
            raise ValueError('Нет детей desired size: ' + row['name'])
        return result

    root = names[control_name][0]
    tree = visit(root, set())
    if used_exclusions != set(excluded):
        raise ValueError('Исключённая ветка не найдена в desired tree')
    return {str(root['export']): tree}
