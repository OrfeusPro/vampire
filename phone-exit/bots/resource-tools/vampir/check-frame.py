"""Replay color/edge template matching on one saved frame, without phone input.

Development OpenCV replay, not a replacement for Android runtime verification.
"""
import argparse
import hashlib
import json
from pathlib import Path

import cv2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('frame', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    module = Path(__file__).resolve().parents[2] / 'vampir'
    config = json.loads((module / 'vision.json').read_text(encoding='utf-8'))
    frame = cv2.imread(str(args.frame))
    if frame is None:
        raise ValueError('Frame unreadable')
    height, width = frame.shape[:2]
    reference = config.get('reference_size', [1280, 720])
    frame_scale = min(width / reference[0], height / reference[1])
    result = []
    for name, spec in config['templates'].items():
        x, y, right, bottom = [round(v * size) for v, size in zip(spec['region'], [width, height, width, height])]
        hay = frame[y:bottom, x:right]
        template = cv2.imread(str(module / 'templates' / spec['file']))
        if template is None:
            raise ValueError('Template unreadable: ' + name)
        detector = spec.get('detector', {})
        if detector.get('type') == 'edge_template':
            def edges(image):
                return cv2.Canny(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY), detector.get('canny_low', 45), detector.get('canny_high', 140))
            hay, template = edges(hay), edges(template)
        best, point = 0, None
        for scale in spec.get('scales', [1]):
            scale *= frame_scale
            tw, th = round(template.shape[1] * scale), round(template.shape[0] * scale)
            if tw < 1 or th < 1 or tw > hay.shape[1] or th > hay.shape[0]:
                continue
            sample = cv2.resize(template, (tw, th))
            _, score, _, loc = cv2.minMaxLoc(cv2.matchTemplate(hay, sample, cv2.TM_CCOEFF_NORMED))
            if score > best:
                best, point = score, [x + loc[0] + tw // 2, y + loc[1] + th // 2]
        result.append(dict(name=name, confidence=best, found=best >= spec['threshold'], point=point))
    report = dict(frame=str(args.frame.resolve()), sha256=hashlib.sha256(args.frame.read_bytes()).hexdigest(),
                  opencv=cv2.__version__, vision_sha256=hashlib.sha256((module / 'vision.json').read_bytes()).hexdigest(),
                  matches=result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps([r for r in result if r['found']]))


if __name__ == '__main__':
    main()
