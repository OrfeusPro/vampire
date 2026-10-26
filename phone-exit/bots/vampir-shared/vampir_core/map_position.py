"""Small read-only world target projection; research tools stay outside runtime."""
from dataclasses import dataclass
import math

from .world_entry_flow import ServerTargetPosition
from .world_move_start import SOURCE_SHA256,CURRENT_PROBE_SOURCE

PROJECTION_SOURCES=frozenset((SOURCE_SHA256,CURRENT_PROBE_SOURCE))


@dataclass(frozen=True,slots=True)
class MapPosition:
    world_id: int
    map_id: str
    x: float
    y: float
    z: float
    pixel_x: float
    pixel_y: float
    inside: bool
    semantics: str = 'server_target_before_engine_correction'


class MapProjection:
    """Explicit current audit input, never guesses a map from XY or nearest point."""
    def __init__(self,manifest,*,source_sha256):
        if source_sha256 not in PROJECTION_SOURCES or manifest.get('source_sha256')!=source_sha256:
            raise ValueError('Map projection source differs')
        self.source_sha256=source_sha256
        self.worlds=dict(manifest['worlds'])
        if not self.worlds or any(not isinstance(k,str) or not k.isdecimal() or v not in ('10','11')
                for k,v in self.worlds.items()):raise ValueError('Unsupported world/map mapping')
        self.size=tuple(manifest['size']);self.center=tuple(manifest['center'])
        self.ground=manifest['ground_distance']
        if len(self.size)!=2 or len(self.center)!=2:raise ValueError('Projection dimensions differ')
        values=(*self.size,*self.center,self.ground)
        if any(type(v) not in (int,float) or not math.isfinite(v) for v in values):
            raise ValueError('Projection values must be finite')
        if min(self.size)<=0 or self.ground<=0:raise ValueError('Projection extent must be positive')

    def project(self,position):
        if not isinstance(position,ServerTargetPosition):raise TypeError('Server target required')
        semantics={'world_move_finish_result':'server_target_before_engine_correction',
            'character_move_notify_xy_retained_z':'server_target_xy_retained_z'}.get(position.source)
        if semantics is None:raise ValueError('Unsupported position semantics')
        if type(position.world_id) is not int:raise ValueError('World ID must be integer')
        map_id=self.worlds.get(str(position.world_id))
        if map_id is None:raise ValueError('No verified projection for this world')
        x,y,z=position.vector.finite_values()
        px=(x-self.center[0])*self.size[0]/self.ground+self.size[0]/2
        py=(y-self.center[1])*self.size[1]/self.ground+self.size[1]/2
        if not all(math.isfinite(v) for v in (px,py)):raise ValueError('Projected point overflow')
        return MapPosition(position.world_id,map_id,x,y,z,px,py,
            0<=px<=self.size[0] and 0<=py<=self.size[1],semantics)
