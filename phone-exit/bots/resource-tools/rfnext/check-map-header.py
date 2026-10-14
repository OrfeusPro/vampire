"""Replay the runtime map-header detector on supplied local frames (no OCR).

Usage: python check-map-header.py map.jpg hud.jpg ...
Reports scores; classify the supplied frames yourself before changing thresholds.
"""
import json
import sys
from pathlib import Path
import cv2

module = Path(__file__).resolve().parents[2] / 'rfonlinenext'
spec = json.loads((module / 'vision.json').read_text('utf-8'))['templates']['map_title']
raw = cv2.imread(str(module / 'templates' / spec['file']))
detector = spec['detector']
template = cv2.Canny(cv2.cvtColor(raw, cv2.COLOR_BGR2GRAY), detector['canny_low'], detector['canny_high'])
for source in sys.argv[1:]:
    image = cv2.imread(source)
    if image is None:
        raise ValueError('Cannot decode ' + source)
    h, w = image.shape[:2]
    x, y, right, bottom = [round(v * d) for v, d in zip(spec['region'], [w, h, w, h])]
    hay = cv2.Canny(cv2.cvtColor(image[y:bottom, x:right], cv2.COLOR_BGR2GRAY), detector['canny_low'], detector['canny_high'])
    best = 0.0
    for scale in spec['scales']:
        sample = cv2.resize(template, (round(template.shape[1] * scale), round(template.shape[0] * scale)))
        if sample.shape[0] <= hay.shape[0] and sample.shape[1] <= hay.shape[1]:
            best = max(best, cv2.minMaxLoc(cv2.matchTemplate(hay, sample, cv2.TM_CCOEFF_NORMED))[1])
    print(Path(source).name, round(best, 3), 'map' if best >= spec['threshold'] else 'other')
