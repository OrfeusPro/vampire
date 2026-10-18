"""Locate old/future World Map captures on the full Nocturne texture, offline.

This relates image pixels only. No world XY, live character position or clicks.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
BOT = Path(__file__).resolve().parents[2] / 'vampir'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    image = cv2.imdecode(np.frombuffer(path.read_bytes(), np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError('Invalid image: ' + str(path))
    return image


def header_score(image):
    spec = json.loads((BOT / 'vision.json').read_text('utf-8-sig'))['templates']['world_map_header']
    template = read(BOT / 'templates' / spec['file'])
    h, w = image.shape[:2]
    if w != 1280:
        image = cv2.resize(image, (1280, round(h*1280/w)))
        h, w = image.shape[:2]
    x, y, right, bottom = [round(v * d) for v, d in zip(spec['region'], [w, h, w, h])]
    roi = image[y:bottom, x:right]
    best = -1
    for scale in spec['scales']:
        sample = cv2.resize(template, None, fx=scale, fy=scale)
        if sample.shape[0] <= roi.shape[0] and sample.shape[1] <= roi.shape[1]:
            best = max(best, float(cv2.minMaxLoc(cv2.matchTemplate(roi, sample, cv2.TM_CCOEFF_NORMED))[1]))
    return best


def fit_verified(src, dst):
    """Fit on alternating screen cells; verify separate cells before accepting."""
    if len(src) < 40:
        raise ValueError('Too few terrain correspondences')
    held = ((src[:, 0] // 140 + src[:, 1] // 100).astype(int) % 2) == 1
    if min(int(held.sum()), int((~held).sum())) < 15:
        raise ValueError('Insufficient spatial validation support')
    cv2.setRNGSeed(17)
    matrix, inliers = cv2.estimateAffinePartial2D(src[~held], dst[~held], method=cv2.RANSAC,
        ransacReprojThreshold=2, maxIters=10000, confidence=.999)
    if matrix is None or inliers.sum() < 25:
        raise ValueError('Terrain fit rejected')
    residual = np.linalg.norm(src @ matrix[:, :2].T + matrix[:, 2] - dst, axis=1)
    accepted = residual < 3
    validate = residual[held]
    angle = math.degrees(math.atan2(matrix[1, 0], matrix[0, 0]))
    if accepted.mean() < .7 or (validate < 3).mean() < .8 or np.median(validate) > 1 or abs(angle) > 3:
        raise ValueError('Independent terrain cells disagree')
    hull = cv2.convexHull(src[accepted]).reshape(-1, 2)
    if cv2.contourArea(hull) < 30000:
        raise ValueError('Terrain support too concentrated')
    return matrix, accepted, dict(training_matches=int((~held).sum()), validation_matches=int(held.sum()),
        inliers=int(accepted.sum()), matches=len(src), validation_inlier_fraction=float((validate < 3).mean()),
        validation_median_atlas_px=float(np.median(validate) * 2),
        validation_p95_atlas_px=float(np.percentile(validate, 95) * 2), angle_degrees=angle)


def build(root, frames):
    out = root / 'maps/atlas/screenshot-study'
    out.mkdir(parents=True, exist_ok=True)
    metadata = json.loads((root / 'maps/nocturne-world.json').read_text('utf-8'))
    master = root / 'maps' / metadata['image']
    if digest(master) != metadata['sha256']:
        raise ValueError('Nocturne image changed; rebuild assembly first')
    reference = cv2.resize(read(master), (5120, 5120))
    sift = cv2.SIFT_create(nfeatures=60000)
    ka, da = sift.detectAndCompute(cv2.cvtColor(reference, cv2.COLOR_BGR2GRAY), None)
    matcher = cv2.FlannBasedMatcher(dict(algorithm=1, trees=5), dict(checks=150))
    overview = Image.open(master).convert('RGB').resize((2048, 2048))
    overview = Image.blend(overview, Image.new('RGB', overview.size, '#10151f'), .45)
    records, rejected = [], []
    for frame in frames:
        image = read(frame)
        score = header_score(image)
        if score < .9:
            rejected.append(dict(file=str(frame), reason='World Map header absent', header_score=score))
            continue
        h, w = image.shape[:2]
        mask = np.zeros((h, w), np.uint8)
        # Conservative historical 1280x720 viewport, scaled with capture size.
        x1, y1, x2, y2 = [round(v * d) for v, d in zip([85/1280,75/720,1220/1280,700/720], [w,h,w,h])]
        mask[y1:y2, x1:x2] = 255
        kb, db = sift.detectAndCompute(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY), mask)
        if db is None:
            rejected.append(dict(file=str(frame), reason='No terrain descriptors'))
            continue
        pairs = matcher.knnMatch(db, da, k=2)
        # One source per reference keypoint, to avoid repeated decorations voting twice.
        unique = {}
        for m, n in pairs:
            if m.distance < .7*n.distance and (m.trainIdx not in unique or m.distance < unique[m.trainIdx].distance):
                unique[m.trainIdx] = m
        matches = list(unique.values())
        src = np.float32([kb[m.queryIdx].pt for m in matches])
        dst = np.float32([ka[m.trainIdx].pt for m in matches])
        try:
            matrix, ok, stats = fit_verified(src, dst)
        except ValueError as error:
            rejected.append(dict(file=str(frame), reason=str(error)))
            continue
        matrix *= 2  # 5120 reference -> original 10240 atlas
        hull = cv2.convexHull(src[ok]).reshape(-1, 2)
        atlas_hull = hull @ matrix[:, :2].T + matrix[:, 2]
        lo = np.floor(atlas_hull.min(0)).astype(int)
        hi = np.ceil(atlas_hull.max(0)).astype(int)
        if np.any(lo < 0) or np.any(hi > metadata['size']):
            rejected.append(dict(file=str(frame), reason='Support outside atlas'))
            continue
        frame_hash = digest(frame)
        stem = frame_hash[:12]
        (out / (stem + '-source.jpg')).write_bytes(frame.read_bytes())
        source_mask = np.zeros((h, w), np.uint8)
        cv2.fillConvexPoly(source_mask, np.round(hull).astype(np.int32), 255)
        local = matrix.copy()
        local[:, 2] -= lo
        size = tuple((hi-lo).tolist())
        patch = cv2.warpAffine(image, local, size)
        alpha = cv2.warpAffine(source_mask, local, size)
        rgba = cv2.cvtColor(patch, cv2.COLOR_BGR2RGBA)
        rgba[:, :, 3] = alpha
        Image.fromarray(rgba).save(out / (stem + '-patch.png'))
        crop = Image.open(master).crop((*lo.tolist(), *hi.tolist())).convert('RGB')
        crop.save(out / (stem + '-reference.png'))
        comparison = Image.new('RGB', (crop.width*2, crop.height+42), '#10151f')
        comparison.paste(crop, (0,42))
        comparison.paste(Image.fromarray(cv2.cvtColor(patch, cv2.COLOR_BGR2RGB)), (crop.width,42))
        draw = ImageDraw.Draw(comparison)
        draw.text((16,12), 'CLIENT TEXTURE', fill='#62e7bc')
        draw.text((crop.width+16,12), 'REGISTERED ANDROID CAPTURE', fill='#62e7bc')
        comparison.save(out / (stem + '-comparison.jpg'), quality=94)
        small = cv2.warpAffine(image, matrix*.2, (2048,2048))
        small_mask = cv2.warpAffine(source_mask, matrix*.2, (2048,2048))
        overview.paste(Image.fromarray(cv2.cvtColor(small,cv2.COLOR_BGR2RGB)), (0,0), Image.fromarray(small_mask))
        draw = ImageDraw.Draw(overview)
        poly = [tuple(p*.2) for p in atlas_hull]
        draw.line(poly+[poly[0]], fill='#62e7bc', width=4)
        draw.text((int(lo[0]*.2),int(lo[1]*.2)-22), 'Capture '+stem, fill='#ffffff', stroke_width=2, stroke_fill='#10151f')
        records.append(dict(source=str(frame.resolve()), source_sha256=frame_hash, source_size=[w,h],
            source_copy=stem+'-source.jpg', patch=stem+'-patch.png', reference_crop=stem+'-reference.png',
            patch_sha256=digest(out / (stem+'-patch.png')),
            comparison=stem+'-comparison.jpg', patch_origin=lo.tolist(), screenshot_to_atlas=matrix.tolist(),
            support_screen_polygon=hull.tolist(), support_atlas_polygon=atlas_hull.tolist(),
            support_area_fraction=float(cv2.contourArea(atlas_hull.astype(np.float32))/10240**2),
            header_score=score, **stats))
    if not records:
        raise ValueError('No registered map captures; existing results preserved')
    previous = out / 'index.json'
    merged = {}
    if previous.is_file():
        old = json.loads(previous.read_text('utf-8'))
        if old['atlas_sha256'] != metadata['sha256']:
            raise ValueError('Existing captures refer to a changed atlas; use a fresh resource library')
        merged = {r['source_sha256']: r for r in old['frames']}
    merged.update({r['source_sha256']: r for r in records})
    records = list(merged.values())
    overview = Image.open(master).convert('RGB').resize((2048, 2048))
    overview = Image.blend(overview, Image.new('RGB', overview.size, '#10151f'), .45)
    for record in records:
        if not record.get('patch_sha256') or digest(out / record['patch']) != record['patch_sha256']:
            raise ValueError('Existing screenshot patch missing/hash changed; register that source again')
        if digest(out / record['source_copy']) != record['source_sha256']:
            raise ValueError('Stored original screenshot hash changed')
        patch = Image.open(out / record['patch']).convert('RGBA')
        patch.thumbnail((max(1,round(patch.width*.2)),max(1,round(patch.height*.2))))
        origin = tuple(round(v*.2) for v in record['patch_origin'])
        overview.paste(patch, origin, patch)
        draw = ImageDraw.Draw(overview)
        polygon = [tuple(np.array(p)*.2) for p in record['support_atlas_polygon']]
        draw.line(polygon+[polygon[0]],fill='#62e7bc',width=4)
        draw.text((origin[0],origin[1]-22),'Capture '+record['source_sha256'][:12],fill='#ffffff',stroke_width=2,stroke_fill='#10151f')
    overview.save(out / 'coverage.jpg', quality=95)
    report = dict(atlas_image='maps/nocturne-world.png', atlas_sha256=metadata['sha256'], atlas_size=metadata['size'],
        method='SIFT unique terrain matches, RANSAC similarity, separate spatial validation cells; no OCR',
        opencv=cv2.__version__, frames=records, rejected=rejected, world_xy_verified=False, navigation_verified=False,
        limitation='Historical capture-to-texture image relation only; validation cells are from the same capture, not a second device capture.')
    (out / 'index.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(accepted=len(records), rejected=len(rejected), frames=[{k:r[k] for k in ['source','inliers','matches','validation_median_atlas_px','validation_p95_atlas_px','support_area_fraction']} for r in records]),ensure_ascii=False))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frames', type=Path, nargs='+')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    build(args.root,args.frames)
