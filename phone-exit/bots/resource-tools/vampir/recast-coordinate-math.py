"""Native coordinate basis; does not select active navigation data or routes."""
import math


def vector(value):
    if len(value)!=3 or not all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) for v in value):raise ValueError('Expected a finite 3D coordinate')
    return value


def world_to_nav(value):
    x,y,z=vector(value)
    return [-x,z,-y]


def nav_to_world(value):
    x,y,z=vector(value)
    return [-x,-z,y]
