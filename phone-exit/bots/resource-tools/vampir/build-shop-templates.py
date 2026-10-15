"""Reproduce reviewed template crops from saved Pixel 5 screenshots, without OCR."""
import hashlib
import json
import os
from pathlib import Path
from PIL import Image
import cv2
import math

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'
SPECS = {
    'shop_guide_title': ('guide.jpg', (895, 149, 1125, 171), [.65, .17, .95, .26]),
    'shop_guide_task': ('guide.jpg', (897, 180, 1098, 201), [.65, .22, .95, .32]),
    'shop_merchant_header': ('list.jpg', (976, 4, 1114, 61), [.68, 0, .90, .12]),
    'shop_small_row': ('list.jpg', (117, 149, 385, 172), [.04, .15, .36, .34]),
    'shop_row_gold75': ('list.jpg', (118, 178, 175, 199), [.04, .18, .23, .34]),
    'shop_small_popup': ('confirm.jpg', (406, 74, 660, 122), [.25, .05, .72, .23]),
    'shop_quantity_one': ('confirm.jpg', (597, 341, 644, 384), [.44, .44, .55, .56]),
    'shop_amount_label': ('confirm.jpg', (513, 530, 687, 560), [.35, .68, .57, .80]),
    'shop_amount75': ('confirm.jpg', (737, 530, 780, 560), [.55, .68, .65, .80]),
    'shop_buy_button': ('confirm.jpg', (649, 599, 869, 640), [.45, .78, .72, .92]),
    'shop_exit': ('list.jpg', (1220, 14, 1263, 53), [.92, 0, 1, .11]),
    'connection_terminated_inspect': ('session-terminated.jpg', (490, 294, 793, 347), [.30, .30, .70, .55]),
}


def main():
    folder = ROOT / 'phone-tests/shop-901030'
    config = json.loads((MODULE / 'vision.json').read_text(encoding='utf-8'))
    evidence = []
    alternatives = {}
    for name, (file, rect, region) in SPECS.items():
        source = folder / file
        with Image.open(source) as image:
            if image.size != (1280, 720):
                raise ValueError('Reference screenshot size changed')
            destination = MODULE / 'templates' / (name + '.png')
            image.crop(rect).save(destination)
        config['templates'][name] = dict(file=destination.name, threshold=.94, region=region, scales=[.95, 1, 1.05])
        evidence.append(dict(name=name, source=file, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                             crop=rect, template_sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
        if name in ('shop_guide_title', 'shop_guide_task', 'shop_row_gold75', 'shop_small_popup',
                    'shop_amount_label', 'connection_terminated_inspect'):
            alternatives[name] = []
            for factor in (.75, 1.25):
                alias = name + ('_compact' if factor < 1 else '_large')
                width, height = round(1280 * factor), round(720 * factor)
                image = cv2.resize(cv2.imread(str(source)), (width, height), interpolation=cv2.INTER_LINEAR)
                left, top, right, bottom = [math.floor(x * factor + .5) for x in rect]
                destination = MODULE / 'templates' / (alias + '.png')
                success, encoded = cv2.imencode('.png', image[top:bottom, left:right])
                if not success:
                    raise ValueError('Cannot encode scaled template')
                destination.write_bytes(encoded.tobytes())
                config['templates'][alias] = dict(file=destination.name, threshold=.94, region=region,
                    scales=[.95, 1, 1.05], reference_size=[width, height])
                alternatives[name].append(alias)
                evidence.append(dict(name=alias, source=file, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                    resize_factor=factor, interpolation='OpenCV INTER_LINEAR', crop=[left, top, right, bottom],
                    reference_size=[width, height], template_sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    config.setdefault('match_alternatives', {}).update(alternatives)
    (folder / 'template-provenance.json').write_text(json.dumps(dict(reference_size=[1280, 720],
        phone='Google Pixel 5 JP', templates=evidence,
        manual_actions=['Guide opened merchant', 'small potion selected', 'purchase cancelled; no item bought',
                        'Session terminated before further purchase test; no dismissal automated']), indent=2), encoding='utf-8')
    (folder / 'vision-shop-draft.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Reproduced', len(evidence), 'templates with source hashes')


if __name__ == '__main__':
    main()
