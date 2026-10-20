"""Read existing CSV extractions; do not infer live server IDs from UI order."""
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
TABLES = ROOT / 'table-study'
SPECS = (
    ('index.json', 'ProjectRED-Windows-6107.csv', 'ServerGroupType', (251, 256)),
    ('index.json', 'ProjectRED-Windows-6108.csv', 'Type', (253,)),
    ('index-pakchunk1-Windows.json', 'pakchunk1-Windows-516.csv', 'ServerGroupType', (251, 256)),
    ('index-pakchunk1-Windows.json', 'pakchunk1-Windows-517.csv', 'Type', (253,)),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build():
    evidence = []
    for index_name, filename, type_column, identifiers in SPECS:
        index_raw = (TABLES / index_name).read_bytes()
        index = json.loads(index_raw)
        entries = [row for row in index['tables'] if row['file'] == filename]
        if len(entries) != 1:
            raise ValueError('Missing or ambiguous extraction entry')
        entry = entries[0]
        raw = (TABLES / filename).read_bytes()
        if sha(raw) != entry['sha256']:
            raise ValueError('Extracted CSV changed')
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
        if not {'Id', type_column, 'Name'} <= set(reader.fieldnames or ()):
            raise ValueError('Unexpected server label schema')
        selected = []
        rows = list(reader)
        for identifier in identifiers:
            matches = [(position, row) for position, row in enumerate(rows, 1)
                       if row['Id'] == str(identifier) and row[type_column] == 'Real_JP']
            if len(matches) != 1:
                raise ValueError('Missing or ambiguous JP label')
            position, row = matches[0]
            selected.append(dict(record_number=position, id=identifier,
                                 type_column=type_column, type_value=row[type_column], name=row['Name']))
        evidence.append(dict(file=filename, csv_sha256=sha(raw),
                             index=index_name, index_sha256=sha(index_raw),
                             extraction={key: entry[key] for key in ('source', 'entry', 'offset', 'size')},
                             rows=selected))
    return dict(tool_sha256=sha(Path(__file__).read_bytes()), tables=evidence,
                limits=['Extracted label rows only; group IDs and server IDs are separate tables.',
                        'No live names or UI localization lookup executed; no network or credentials.'])


if __name__ == '__main__':
    report = build()
    target = ROOT / 'code-clues/server-name-evidence.json'
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(target), sha256=sha(target.read_bytes()),
                         labels=[dict(file=t['file'], rows=t['rows']) for t in report['tables']])))
