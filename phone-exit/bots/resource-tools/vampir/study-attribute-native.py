"""Bounded string discovery only; absence of names does not prove absence of calculations."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
TERMS = ['StatConvert', 'CalculateStat', 'CalcStat', 'GetStatValue', 'GetCombatPower',
         'CalcCombat', 'GetAttackPower', 'StatMultiplier', 'StatFormula']


def main(root=ROOT):
    native = json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
    raw = Path(native['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != native['sha256']:
        raise ValueError('Changed native client')
    found = []
    patterns = [('ascii', rb'[A-Za-z_][A-Za-z0-9_:./]{6,160}'),
                ('utf-16le', rb'(?:[A-Za-z_]\x00)(?:[A-Za-z0-9_:./]\x00){6,160}')]
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, raw):
            text = match.group().decode(encoding)
            if any(term.lower() in text.lower() for term in TERMS):
                found.append(dict(offset=match.start(), encoding=encoding, text=text))
    report = dict(source=native['source'], sha256=native['sha256'], terms=TERMS, strings=found,
        scope='Full executable bytes, bounded ASCII/UTF-16LE identifier patterns only',
        limitations=['This is not a disassembly or function-use proof.',
                     'EStatConvertType enum names alone do not establish conversion formulas.',
                     'No matching function name does not prove absence of stripped native code or server calculations.'])
    out = root/'code-clues/attribute-native-discovery.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(report=str(out), matches=len(found)), ensure_ascii=False))
    return report


if __name__ == '__main__':
    main()
