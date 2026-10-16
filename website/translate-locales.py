"""Generate draft translations of public storefront copy; never sends order data."""
import concurrent.futures
import json
import pathlib
import time
import re
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
LOCALES = ROOT / 'dist' / 'locales'
BASE = json.loads((LOCALES / 'en.json').read_text(encoding='utf-8'))
REGISTRY = json.loads((LOCALES / 'languages.json').read_text(encoding='utf-8'))

def translate(entry):
    code = entry['code']
    target = {'nb': 'no', 'sr-Latn': 'sr'}.get(code, code)
    existing_path = LOCALES / (code + '.json')
    existing = json.loads(existing_path.read_text(encoding='utf-8')) if existing_path.exists() else {}
    tokens = {'VAMPIR.TOP':'918273601','VAMPIR':'918273602','USDT':'918273603','USD':'918273604','{id}':'918273605','{pricePer1000}':'918273609','Netmarble':'918273606','Discord':'918273607','Telegram':'918273608'}
    keys = [key for key, value in BASE.items() if key == 'sending' or any(existing.get(key,'').count(token) != value.count(token) for token in tokens)] if '--repair' in sys.argv else list(BASE)
    if not keys: return code, 'unchanged'
    texts = []
    for key in keys:
        value = 'Saving your request…' if key == 'sending' else BASE[key]
        for token, marker in tokens.items(): value = value.replace(token,marker)
        texts.append(value.replace('\n',' | '))
    query = '\n'.join(texts)
    url = 'https://translate.googleapis.com/translate_a/single?' + urllib.parse.urlencode(
        {'client': 'gtx', 'sl': 'en', 'tl': target, 'dt': 't', 'q': query})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=12) as response:
                data = json.load(response)
            lines = ''.join(part[0] for part in data[0]).strip().split('\n')
            if len(lines) != len(keys):
                raise ValueError(f'Expected {len(BASE)} lines, got {len(lines)}')
            result = dict(zip(keys, (line.strip() for line in lines)))
            for key, value in result.items():
                for token, marker in tokens.items(): value = value.replace(marker,token)
                result[key] = value
            result = existing | result
            if not all(result.values()):
                raise ValueError('Empty translation')
            # Keep legal attribution unchanged; it is a brand/copyright line.
            result['footer'] = result['footer'].split(' | ')[0].split('\n')[0] + '\n' + BASE['footer'].split('\n')[1]
            (LOCALES / (code + '.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            return code, 'OK'
        except Exception as error:
            if attempt == 2:
                return code, str(error)
            time.sleep(2 + attempt)

if __name__ == '__main__':
    pending = [entry for entry in REGISTRY['languages'] if entry['code'] not in ['en','ru','uk','nn','rm','sr-Latn'] and ('--repair' in sys.argv or not (LOCALES / (entry['code']+'.json')).exists())]
    for entry in pending:
        code, status = translate(entry)
        print(code + ': ' + status, flush=True)
