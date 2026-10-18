"""Client-checked rotator conversion; does not resolve archetypes or world placement."""
import math


def rotator_to_quaternion(rotation):
    """Pitch/yaw/roll degrees to encoded X/Y/Z/W, checked against client math."""
    if len(rotation) != 3:
        raise ValueError('Expected pitch, yaw, roll')
    values = [float(v) for v in rotation]
    if not all(math.isfinite(v) and abs(v) <= 1e6 for v in values):
        raise ValueError('Rotation outside the verified finite range')
    pitch, yaw, roll = [math.fmod(v, 360.) * (math.pi / 360.) for v in values]
    sp, sy, sr = math.sin(pitch), math.sin(yaw), math.sin(roll)
    cp, cy, cr = math.cos(pitch), math.cos(yaw), math.cos(roll)
    return [cr * sp * sy - sr * cp * cy,
            -cr * sp * cy - sr * cp * sy,
            cr * cp * sy - sr * sp * cy,
            cr * cp * cy + sr * sp * sy]


def transform_point(point, translation, quaternion, scale):
    """Scale, rotate, then translate; checked against the client's bounds consumer."""
    vectors = []
    for values, count in [(point, 3), (translation, 3), (quaternion, 4), (scale, 3)]:
        if len(values) != count:
            raise ValueError('Invalid transform vector length')
        row = [float(v) for v in values]
        if not all(math.isfinite(v) for v in row):
            raise ValueError('Nonfinite transform input')
        vectors.append(row)
    point, translation, quaternion, scale = vectors
    if abs(sum(v * v for v in quaternion) - 1.) > 1e-10:
        raise ValueError('Expected unit quaternion')
    p = [v * s for v, s in zip(point, scale)]
    q, w = quaternion[:3], quaternion[3]

    def cross(a, b):
        return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]
    t = [2. * v for v in cross(q, p)]
    c = cross(q, t)
    result = [position + value + w * delta + extra for position, value, delta, extra in zip(translation, p, t, c)]
    if not all(math.isfinite(v) for v in result):
        raise ValueError('Nonfinite transformed point')
    return result
