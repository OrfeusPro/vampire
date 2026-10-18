"""Version-bound metadata rules; no claim of an attached or available route."""
def metadata(flags,side,same_tile):
    if not isinstance(flags,int) or not 0<=flags<=255:raise ValueError('Invalid flags')
    if side not in range(8) and side!=-1:raise ValueError('Invalid tile side')
    direction=0x20 if flags&0x80 else 0
    opposite=0x80 if side==-1 else (side-4)&7
    source=0x80 if side==-1 else side
    mask=255 if same_tile else 127
    return dict(start_to_surface=0xc0|direction|0x10,surface_to_start=0xc0|direction,
                end_to_surface=(opposite|0x40|direction)&mask,
                surface_to_end=((source|0x40|direction)&mask)|(0 if direction else 0x10))

def direction_gate(link_metadata,direction_mode):
    if not isinstance(link_metadata,int) or not 0<=link_metadata<=255:raise ValueError('Invalid link metadata')
    return (link_metadata&0x60)!=0x40 or bool(link_metadata&0x10)==bool(direction_mode)
