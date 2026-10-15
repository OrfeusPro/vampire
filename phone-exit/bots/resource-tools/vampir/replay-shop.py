"""Offline replay of the real bot on saved screenshots; never connects to a phone.

Desktop OpenCV emulates the relevant BotVision template operations. This does
not replace Android OpenCV validation or supply a fabricated purchase result.
"""
import hashlib
import importlib.util
import json
import math
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import cv2
import numpy as np

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'
TRANSFORMS = [('native', 1, 0, 0), ('compact', .75, 0, 0), ('large', 1.25, 0, 0), ('shift', 1, 8, 6)]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReplayHost:
    def __init__(self, directory):
        self.directory, self.frame, self.name = directory, None, None
        self.taps, self.cache = [], {}

    def capture(self, frame, name):
        self.frame, self.name, self.cache = frame, name, {}

    def call(self, command, **args):
        if command == 'foreground':
            return dict(package='com.netmarble.thered')
        if command == 'capture':
            height, width = self.frame.shape[:2]
            return dict(width=width, height=height)
        if command == 'tap':
            journal = self.directory.parent / 'vampir-purchases.json'
            self.taps.append(dict(frame=self.name, args=args,
                journal=json.loads(journal.read_text(encoding='utf-8')) if journal.exists() else {}))
            return dict(performed=True)
        if command != 'match':
            raise ValueError('Unsupported replay command: ' + command)
        spec = args['spec']
        key = args['name'] + json.dumps(spec, sort_keys=True)
        if key in self.cache:
            return self.cache[key]
        height, width = self.frame.shape[:2]
        region = spec.get('region', [0, 0, 1, 1])
        left, top, right, bottom = [math.floor(v * side + .5) for v, side in zip(region, [width, height, width, height])]
        area = self.frame[max(0, top):min(height, bottom), max(0, left):min(width, right)]
        template = cv2.imread(str(self.directory / 'templates' / spec['file']), cv2.IMREAD_UNCHANGED)
        if template is None:
            raise ValueError('Missing replay template: ' + spec['file'])
        mask = None
        if template.shape[2] == 4:
            mask = np.where(template[:, :, 3] > 1, 255, 0).astype('uint8')
            template = template[:, :, :3]
        if spec.get('blackMask'):
            mask = np.where(cv2.cvtColor(template, cv2.COLOR_BGR2GRAY) > 8, 255, 0).astype('uint8')
        detector = spec.get('detector', {})
        if detector.get('type') == 'edge_template':
            area = cv2.Canny(cv2.cvtColor(area, cv2.COLOR_BGR2GRAY), detector.get('canny_low', 45), detector.get('canny_high', 140))
            template = cv2.Canny(cv2.cvtColor(template, cv2.COLOR_BGR2GRAY), detector.get('canny_low', 45), detector.get('canny_high', 140))
            mask = None
        elif detector:
            raise ValueError('Unsupported replay detector: ' + detector['type'])
        if spec.get('angle'):
            raise ValueError('Rotated templates not implemented in this replay')
        best = dict(found=False, confidence=0, point=[0, 0], rect=[0, 0, 0, 0])
        for scale in spec.get('scales', [1]):
            w, h = math.floor(template.shape[1] * scale + .5), math.floor(template.shape[0] * scale + .5)
            if min(w, h) < 1 or w > area.shape[1] or h > area.shape[0]:
                continue
            sample = cv2.resize(template, (w, h))
            alpha = cv2.resize(mask, (w, h), interpolation=cv2.INTER_NEAREST) if mask is not None else None
            lower = mask is not None or spec.get('method') == 'sqdiff'
            method = cv2.TM_SQDIFF_NORMED if lower else cv2.TM_CCOEFF_NORMED
            scores = cv2.matchTemplate(area, sample, method, mask=alpha)
            scores = np.nan_to_num(scores, nan=1 if lower else 0)
            minimum, maximum, minloc, maxloc = cv2.minMaxLoc(scores)
            confidence, location = (1 - minimum, minloc) if lower else (maximum, maxloc)
            if math.isfinite(confidence) and confidence > best['confidence']:
                x, y = left + location[0], top + location[1]
                best = dict(found=confidence >= spec.get('threshold', .82), confidence=min(1, confidence),
                            point=[x + w // 2, y + h // 2], rect=[x, y, x + w, y + h])
        self.cache[key] = best
        return best


def run_case(base, name, frames, expect_taps, expect_step):
    directory = base / name / 'payload'
    shutil.copytree(MODULE, directory, ignore=shutil.ignore_patterns('__pycache__'))
    bot = load('vampir_replay_' + name, directory / 'bot.py')
    host, state, now, observed = ReplayHost(directory), {}, 1000, []
    for label, frame, seconds in frames:
        if label == 'restart_pending':
            bot = load('vampir_replay_restart_' + name, directory / 'bot.py')
            state = {}
        host.capture(frame, label)
        now += seconds
        with patch.object(bot.time, 'monotonic', return_value=now):
            result = bot.tick(host, dict(quest_enabled=True, autostart_enabled=False, skip_cutscenes_enabled=True), state, str(directory))
        observed.append(result)
    passed = len(host.taps) == expect_taps and observed[-1]['step'] == expect_step
    if expect_taps == 3:
        passed &= host.taps[-1]['journal'] == {'901030010': 'reserved'}
        passed &= [r['step'] for r in observed[:3]] == ['quest_shop_open', 'quest_shop_selected', 'quest_shop_purchased']
        passed &= observed[-1].get('error') == 'quest_shop_purchase_outcome_unknown'
    elif expect_taps == 2:
        passed &= [r['step'] for r in observed[:2]] == ['quest_shop_open', 'quest_shop_selected']
        passed &= observed[-1].get('error') == 'quest_shop_screen_not_advanced'
    else:
        passed &= observed[-1].get('pause') is True
    return dict(case=name, passed=bool(passed), taps=host.taps, results=observed)


def main():
    folder = ROOT / 'phone-tests/shop-901030'
    images = {file: cv2.imread(str(folder / file)) for file in ('guide.jpg', 'list.jpg', 'confirm.jpg', 'session-terminated.jpg')}
    if any(frame is None for frame in images.values()):
        raise ValueError('Missing source screenshots')
    negatives = {}
    mutations = {}
    base = images['confirm.jpg']
    for name, rectangle in [('missing_7', (743, 533, 754, 555)), ('missing_5', (754, 533, 770, 555)),
                             ('missing_quantity', (605, 344, 636, 380)), ('missing_small_name', (405, 72, 474, 102))]:
        image = base.copy()
        left, top, right, bottom = rectangle
        image[top:bottom, left:right] = np.median(base[558:562, 740:780], axis=(0, 1))
        negatives[name] = image
        mutations[name] = dict(type='erase', rectangle=rectangle)
    digit = base[350:375, 612:630]
    mask = cv2.cvtColor(digit, cv2.COLOR_BGR2GRAY) > 160
    ys, xs = np.where(mask)
    digit = digit[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    digit = cv2.resize(digit, (7, 17))
    mask = cv2.cvtColor(digit, cv2.COLOR_BGR2GRAY) > 160
    for name, x in (('prefix_digit', 734), ('suffix_digit', 770)):
        image = base.copy()
        region = image[534:551, x:x + 7]
        region[mask] = digit[mask]
        negatives[name] = image
        mutations[name] = dict(type='insert_source_glyph', source_rectangle=[612, 350, 630, 375],
                               resized=[7, 17], destination=[x, 534], bright_threshold=160)
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary)
        cases = []
        for tag, factor, dx, dy in TRANSFORMS:
            def variant(image):
                scaled = cv2.resize(image, None, fx=factor, fy=factor)
                if dx or dy:
                    scaled = cv2.warpAffine(scaled, np.float32([[1, 0, dx], [0, 1, dy]]), (scaled.shape[1], scaled.shape[0]))
                return scaled
            prefix = [('guide', variant(images['guide.jpg']), 3), ('list', variant(images['list.jpg']), 3)]
            cases.append(run_case(destination, 'purchase_once_' + tag, prefix + [('confirm', variant(base), 3),
                ('confirm_again', variant(base), 3), ('restart_pending', variant(base), 3),
                ('confirm_timeout', variant(base), 21)], 3, 'quest_shop_verify_result'))
            for name, frame in negatives.items():
                changed = variant(frame)
                cases.append(run_case(destination, name + '_' + tag, prefix + [(name, changed, 3),
                    (name + '_timeout', changed, 21)], 2, 'quest_shop_selected'))
            cases.append(run_case(destination, 'session_terminated_' + tag,
                [('terminated', variant(images['session-terminated.jpg']), 3)], 0, 'waiting_connection_terminated_inspect'))
    report = dict(opencv=cv2.__version__, phone_commands_sent=0, cases=cases,
        module_version=json.loads((MODULE / 'manifest.json').read_text(encoding='utf-8'))['version'],
        module_sha256={file: hashlib.sha256((MODULE / file).read_bytes()).hexdigest()
                       for file in ('bot.py', 'shop.py', 'quests.py', 'vision.json', 'shop-reference.json')},
        template_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (MODULE / 'templates').glob('*.png')},
        transforms=[dict(name=tag, factor=factor, shift=[dx, dy]) for tag, factor, dx, dy in TRANSFORMS],
        screenshot_sha256={file: hashlib.sha256((folder / file).read_bytes()).hexdigest() for file in images},
        negative_mutations=mutations,
        limitations=['Desktop replay, not Android OpenCV', 'No successful post-purchase frame exists; result remains unknown',
                     'Negative screenshots are synthetic erasures with recorded rectangles; not game observations'])
    report['passed'] = all(c['passed'] for c in cases)
    (folder / 'bot-replay.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], cases=[dict(case=c['case'], passed=c['passed'], taps=len(c['taps'])) for c in cases])))
    if not report['passed']:
        raise ValueError('Shop replay failed; inspect bot-replay.json')


if __name__ == '__main__':
    main()
