"""MultiBot Lord Nine travel plans and coordinates, without OCR or device identity."""
TYRIOSA_DESERT = 'tab3_row4_desert_of_the_screaming_lv_6268'
TYRIOSA_FLOORS = {
    '1F': 'tab3_row5_lower_tomb_of_tyriosa_1f_lv_6570',
    '2F': 'tab3_row6_lower_tomb_of_tyriosa_2f_lv_7482',
    '3F': 'tab3_row7_lower_tomb_of_tyriosa_3f_lv_88102',
}
DEADMANS_BATTLEFIELD = 'tab4_row3_battlefieldof_templar_lv_7688'
DEADMANS_DISTRICTS = {
    '1': 'tab4_row8_deadman_s_land_district_1_lv_87_92',
    '2': 'tab4_row9_deadman_s_land_district_2_lv_95_100',
    '3': 'tab4_row10_deadman_s_land_district_3_lv_105_113',
}


def travel_plan(spot):
    if 'travel_plan' in spot:
        plan = spot['travel_plan']
        return plan if isinstance(plan, dict) and plan.get('enabled', True) else None
    for floor, map_id in TYRIOSA_FLOORS.items():
        if map_id == spot['map_id']:
            return {'type': 'tyriosa_floor_chain', 'target_floor': floor}
    for district, map_id in DEADMANS_DISTRICTS.items():
        if map_id == spot['map_id']:
            return {'type': 'deadmans_district_chain', 'target_district': district}
    return None


def route(spot, destination, current_map=None):
    """Visible current location can skip a completed entrance, never a confirmation."""
    plan = travel_plan(spot)
    legs = []
    if plan and plan['type'] == 'tyriosa_floor_chain':
        target = str(plan.get('target_floor', '')).upper()
        if target not in TYRIOSA_FLOORS:
            raise RuntimeError('farm_invalid_target_floor')
        current = next((f for f, m in TYRIOSA_FLOORS.items() if m == current_map), None)
        if current and int(current[0]) > int(target[0]):
            raise RuntimeError('farm_unsupported_floor_direction')
        if not current:
            legs += [leg(TYRIOSA_DESERT, [.85297, .382], True, TYRIOSA_DESERT),
                     leg(TYRIOSA_DESERT, [.85297, .518], False, TYRIOSA_FLOORS['1F'], transition=True)]
            current = '1F'
        if current != target:
            # MultiBot takes 1F → 3F directly rather than forcing an extra stop at 2F.
            point = [.85297, .246] if current == '2F' else [.85297, .215]
            legs.append(leg(TYRIOSA_FLOORS[target], point, False, TYRIOSA_FLOORS[target], transition=True))
    elif plan and plan['type'] == 'deadmans_district_chain':
        target = str(plan.get('target_district', ''))
        if target not in DEADMANS_DISTRICTS:
            raise RuntimeError('farm_invalid_target_district')
        current = next((d for d, m in DEADMANS_DISTRICTS.items() if m == current_map), None)
        if current and int(current) > int(target):
            raise RuntimeError('farm_unsupported_district_direction')
        if not current:
            legs += [leg(DEADMANS_BATTLEFIELD, [.85297, .254], True, DEADMANS_BATTLEFIELD),
                     leg(DEADMANS_BATTLEFIELD, [.85297, .586], False, DEADMANS_DISTRICTS['1'], transition=True, nudge=True)]
            current = '1'
        if current != target:
            legs.append(leg(DEADMANS_DISTRICTS[target], [.85297, .185], False, DEADMANS_DISTRICTS[target], transition=True))
    elif plan:
        raise RuntimeError('farm_unknown_travel_plan')
    elif spot.get('teleport_point') and current_map != spot['map_id']:
        legs.append(leg(spot['map_id'], spot['teleport_point'], True, spot['map_id']))

    if destination and (not spot.get('teleport_point') or spot.get('run_after_teleport', True) or plan):
        legs.append(leg(spot['map_id'], destination, False, spot['map_id'], marker=True))
    if not legs and not destination and not plan and not spot.get('teleport_point'):
        raise RuntimeError('farm_point_required')
    return legs


def leg(map_id, point, teleport, arrival_map, **extra):
    return {'map_id': map_id, 'point': point, 'teleport': teleport,
            'arrival_map': arrival_map, **extra}


def marker_options(config, map_id):
    vision, timeouts = config['vision'], config['timeouts']
    tyriosa = map_id in TYRIOSA_FLOORS.values()
    deadmans = map_id in DEADMANS_DISTRICTS.values()
    return {
        'timeout': timeouts.get('farm_tyriosa_arrival_timeout_sec' if tyriosa else 'farm_deadmans_arrival_timeout_sec' if deadmans else 'map_navigation_arrival_timeout_sec', 180 if tyriosa or deadmans else 45),
        'progress_timeout': timeouts.get('farm_navigation_no_progress_timeout_sec', 60),
        'max_route': timeouts.get('farm_navigation_max_route_sec', 600),
        'poll': timeouts.get('map_navigation_poll_sec', vision.get('map_navigation_poll_sec', 2)),
        'search_around': vision.get('farm_tyriosa_search_around_target', False) if tyriosa else vision.get('map_navigation_search_around_target', False),
        'search_radius': vision.get('map_navigation_search_radius_px', 120),
        'angles': vision.get('farm_tyriosa_marker_angles' if tyriosa else 'map_navigation_marker_angles', list(range(0, 360, 45))),
        'radius': vision.get('farm_tyriosa_arrival_radius_px' if tyriosa else 'map_navigation_arrival_radius_px', 70 if tyriosa else 40),
        # Farm.attach_cpu_profiler enables strict arrival: stationary confirmation,
        # at least two observations, and no acceptance of a stale near-target marker.
        'checks': max(2, timeouts.get('farm_tyriosa_required_reached_checks', 1) if tyriosa else vision.get('map_navigation_required_reached_checks', 2)),
        'best_distance': 0,
        'stale_attempts': timeouts.get('farm_tyriosa_accept_best_stale_attempts', 2) if tyriosa else vision.get('map_navigation_accept_best_stale_attempts', 0),
        'templates': vision.get('map_navigation_marker_templates') or [vision.get('map_navigation_marker_template', 'map_navigation_marker_template.png')],
        # Original Farm.attach_cpu_profiler excludes party 1P/2P markers.
        'static_templates': [],
    }


def choose_location(candidates, vision):
    groups = {}
    for candidate in candidates:
        groups.setdefault(candidate['map_id'], []).append(candidate)
    values = []
    for group in groups.values():
        catalog = [c for c in group if c['catalog'] and c['found']]
        values.append(max(catalog or group, key=lambda c: c['confidence']))
    values.sort(key=lambda c: c['confidence'], reverse=True)
    if not values or not values[0]['found']:
        return None
    best = values[0]
    margin = vision.get('farm_current_location_template_margin', .008) if best['catalog'] else vision.get('farm_tyriosa_location_template_margin', .04)
    if len(values) > 1 and best['confidence'] - values[1]['confidence'] < margin:
        return None
    return best['map_id']


def find_marker(match, options, vision, item, target, width, height):
    """Original coarse-angle search followed by local angle refinement."""
    region = item.get('navigation_region') or vision.get('map_navigation_marker_search_region') or vision.get('darkwood_world_map_region') or [.22,.16,.78,.84]
    if options['search_around']:
        radius = options['search_radius']
        region = [max(0,target[0]-radius/width), max(0,target[1]-radius/height), min(1,target[0]+radius/width), min(1,target[1]+radius/height)]
    threshold = vision.get('map_navigation_marker_threshold', .55)
    sources = [(path,False) for path in options['templates']] + [(path,True) for path in options['static_templates']]
    best = {'found': False, 'confidence': 0}
    best_static = False
    def probe(path, angle, bounds, suffix, static=False):
        from pathlib import Path
        filename = Path(path).name
        return match('marker_' + filename + '_' + str(angle) + suffix, {'file': filename, 'blackMask': True, 'angle': angle,
            'goldNeighborhood': not static, 'region': bounds, 'threshold': threshold})
    # Only called with a target after Walk has been issued. Check arrival in a
    # small fresh ROI before the expensive whole-map scan, using the SAME
    # sources, coarse/refined angles, mask, gold filter and confidence threshold.
    # A missing/not-near candidate still falls through to full progress search.
    if target is not None and not options['search_around']:
        margin = vision.get('map_navigation_refine_radius_px', 48)
        tx,ty = round(target[0]*width),round(target[1]*height)
        bounds = [max(region[0],(tx-margin)/width),max(region[1],(ty-margin)/height),
                  min(region[2],(tx+margin)/width),min(region[3],(ty+margin)/height)]
        if bounds[2]>bounds[0] and bounds[3]>bounds[1]:
            angles = list(options['angles'])
            if vision.get('map_navigation_refine_angles', True):
                angles += sorted({(a+offset)%360 for a in options['angles'] for offset in (-30,-15,15,30)} - set(angles))
            near = {'found': False, 'confidence': 0}
            for path,static in sources:
                if static: continue
                for angle in angles:
                    value = probe(path,angle,bounds,'_arrival')
                    if value['found'] and value['confidence'] > near['confidence']:
                        near = value
            if near['found'] and sum((near['point'][i]-[tx,ty][i])**2 for i in range(2))**.5 <= min(options['radius'],20*width/1280):
                return near
    for path, static in sources:
        for angle in ([0] if static else options['angles']):
            value = probe(path, angle, region, '', static)
            if value['confidence'] > best['confidence']:
                best, best_static = value, static
    if best_static or best['confidence'] < threshold*.8 or not vision.get('map_navigation_refine_angles', True) or not best.get('rect'):
        return best
    margin = vision.get('map_navigation_refine_radius_px', 48)
    x1,y1,x2,y2 = [round(v*d) for v,d in zip(region,[width,height,width,height])]
    rect = best['rect']
    bounds = [max(x1,rect[0]-margin),max(y1,rect[1]-margin),min(x2,rect[2]+margin),min(y2,rect[3]+margin)]
    target_bounds = None
    if target is not None:
        tx,ty = round(target[0]*width),round(target[1]*height)
        target_bounds = [max(x1,tx-margin),max(y1,ty-margin),min(x2,tx+margin),min(y2,ty+margin)]
    regions = [target_bounds] if options['search_around'] else [bounds]
    if not options['search_around'] and target_bounds is not None and target_bounds != bounds:
        regions.append(target_bounds)
    extra = sorted({(a+offset)%360 for a in options['angles'] for offset in (-30,-15,15,30)} - set(options['angles']))
    for index,bounds in enumerate(regions):
        if bounds[2]<=bounds[0] or bounds[3]<=bounds[1]:
            continue
        normalized = [v/d for v,d in zip(bounds,[width,height,width,height])]
        for path,static in sources:
            if static: continue
            for angle in extra:
                value = probe(path,angle,normalized,'_refine_'+str(index))
                if value['confidence'] > best['confidence']:
                    best = value
    return best
