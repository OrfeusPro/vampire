"""Register a gameplay map screenshot to the extracted Novus atlas (offline only)."""
import json, sys, os
from pathlib import Path
import cv2
import numpy as np

root = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'))
def register(source):
    atlas = cv2.imread(str(root/'maps/novus-world.png'))
    height, width = atlas.shape[:2]
    atlas = cv2.resize(atlas, (4096, round(height*4096/width)))
    shot = cv2.imread(str(source))
    shot = cv2.resize(shot, (1600, round(shot.shape[0]*1600/shot.shape[1])))
    sift = cv2.SIFT_create(nfeatures=18000)
    ka, da = sift.detectAndCompute(cv2.cvtColor(atlas, cv2.COLOR_BGR2GRAY), None)
    kb, db = sift.detectAndCompute(cv2.cvtColor(shot, cv2.COLOR_BGR2GRAY), None)
    pairs = cv2.BFMatcher().knnMatch(db, da, k=2)
    matches = [a for a,b in pairs if a.distance < .68*b.distance]
    if len(matches)<20: raise ValueError('Too few terrain matches')
    src = np.float32([kb[m.queryIdx].pt for m in matches])
    dst = np.float32([ka[m.trainIdx].pt for m in matches])
    matrix, mask = cv2.estimateAffinePartial2D(src, dst, method=cv2.RANSAC, ransacReprojThreshold=3)
    count = int(mask.sum()) if mask is not None else 0
    if count<20: raise ValueError('Too few terrain inliers')
    residual = np.linalg.norm(src@matrix[:,:2].T+matrix[:,2]-dst, axis=1)[mask.ravel()==1]
    # Input coordinates refer to the original 2400x1080 capture, output is normalized atlas.
    matrix[:,:2] *= 1600/cv2.imread(str(source)).shape[1]
    matrix[0] /= atlas.shape[1]; matrix[1] /= atlas.shape[0]
    return dict(source=str(Path(source).resolve()), source_size=list(cv2.imread(str(source)).shape[1::-1]),
                matrix=matrix.tolist(), matches=len(matches), inliers=count,
                median_residual_atlas_px=float(np.median(residual))*width/4096,
                method='SIFT terrain + RANSAC similarity; no OCR', navigation_verified=False)

if __name__=='__main__':
    result=register(sys.argv[1]); print(json.dumps(result,ensure_ascii=False,indent=2))
    if len(sys.argv)>2: Path(sys.argv[2]).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
