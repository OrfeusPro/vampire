"""Bounded Novus point navigation. Coordinates come from a fresh local terrain fit."""
import json
import math


def tick(host, settings, state, frame, config, now):
    if not settings.get('farm_enabled'):
        state.pop('route', None)
        return None
    spots = settings.get('farm_map_spots', [])
    spot = next((s for s in spots if s.get('id') == settings.get('active_farm_map_spot_id') and s.get('enabled', True)), None)

    def report(step, error=None):
        out = dict(status='waiting', step=step, activePoint=spot.get('id') if spot else None)
        if error:
            out.update(status='error', error=error, pause=True, retryable=False)
        return out

    if not spot or spot.get('map_id') != 'novus_world_101' or not spot.get('map_points'):
        return report('farm_point_required', 'farm_point_required')
    target = spot['map_points'][0]
    if not isinstance(target, (list, tuple)) or len(target) != 2 or not all(isinstance(v, (float, int)) and math.isfinite(v) and 0 <= v < 1 for v in target):
        return report('farm_point_required', 'invalid_farm_point')
    signature = json.dumps(spot, sort_keys=True)
    route = state.setdefault('route', {})
    if route.get('signature') != signature:
        route.clear()
        route.update(signature=signature, phase='open', since=now, started=now, zooms=0, pans=0)

    def match(name, spec=None):
        return host.call('match', name=name, spec=spec or config['templates'][name])

    def found(name):
        return match(name).get('found', False)

    def variant(name):
        result = match(name)
        if not result.get('found'):
            result = match(name + '_vivo')
        return result

    def action(command, phase, **args):
        host.call(command, width=frame['width'], height=frame['height'], **args)
        route.update(phase=phase, since=now)
        return report(phase)

    def tap(button, phase):
        return action('tap', phase, x=round(button['point'][0]), y=round(button['point'][1]))

    def open_map(next_phase):
        anchor=match('hud_map_anchor')
        if not anchor.get('found'):
            return report('waiting_map_anchor')
        rect=anchor.get('rect')
        if not rect or len(rect)!=4:
            return report('waiting_map_anchor')
        geometry=config['map_open_anchor']
        scale=(rect[2]-rect[0])/geometry['reference_width']
        x=anchor['point'][0]+geometry['offset'][0]*scale
        y=anchor['point'][1]+geometry['offset'][1]*scale
        if not (.02*frame['width']<x<.30*frame['width'] and 0<y<.22*frame['height']):
            return report('waiting_map_anchor','map_anchor_geometry_invalid')
        return action('tap',next_phase,x=round(x),y=round(y))

    # UI settles before another recognition/action. Never retry a transition blindly.
    if now - route['since'] < 1.5:
        return report(route['phase'])
    if found('point_unreachable'):
        return report('point_unreachable', 'farm_point_unreachable')
    if found('sleep_dark') and (found('sleep_title') or found('sleep_title_vivo')):
        route['wake_attempts']=route.get('wake_attempts',0)+1
        if route['wake_attempts']>3:
            return report('wake_power_saving','farm_sleep_not_closed')
        return action('swipe', route['phase'], x1=round(frame['width']*.42), y1=round(frame['height']*.5), x2=round(frame['width']*.7), y2=round(frame['height']*.5), durationMs=600)
    route.pop('wake_attempts',None)
    if found('offline_result'):
        button=match('offline_result_close')
        if button.get('found') and not route.get('closed_offline_result'):
            route['closed_offline_result']=True
            return tap(button,route['phase'])
        return report('offline_result', 'offline_result_not_closed')
    route.pop('closed_offline_result',None)
    if route['phase'] != 'farming' and now-route['started'] > 300:
        return report('verify_arrival', 'farm_arrival_timeout')
    phase = route['phase']
    is_map = found('map_title')
    hud = found('hud_map_anchor') and (found('auto_off') or found('auto_on'))
    if phase == 'open' and not hud and not is_map:
        return None
    phase = route['phase']
    if phase == 'farming':
        if hud and found('auto_on'):
            route['last_hud'] = now
            return dict(status='running', step='farming', activePoint=spot['id'])
        if not hud and now-route.get('last_hud', now) > 20:
            return report('recognizing_screen', 'farm_screen_changed')
        if hud:
            route['last_hud'] = now
            # A death/unknown UI never triggers another route or a blind auto toggle.
            if not found('auto_on'):
                return report('recognizing_screen', 'farm_autobattle_stopped')
        return report('recognizing_screen')
    if phase == 'enable_auto':
        if hud and found('auto_on'):
            route.update(phase='farming', last_hud=now)
            return dict(status='running', step='farming', activePoint=spot['id'])
        if hud and not route.get('auto_clicked'):
            off = match('auto_off')
            if off.get('found'):
                route['auto_clicked'] = True
                return tap(off, 'enable_auto')
    if phase == 'confirm_teleport':
        if variant('point_confirm_title').get('found') and variant('point_coin').get('found'):
            button = variant('point_confirm_button')
            if button.get('found') and not route.get('confirmed'):
                route['confirmed'] = True
                route['travel_at'] = now
                return tap(button, 'travelling')
        # Do not confirm any generic OK / unexpected premium-currency dialog.
    if phase == 'travelling':
        if hud and now-route['travel_at'] >= 3:
            return open_map('arrival_map')
        return report('travelling')
    if is_map and phase in ('open', 'map', 'arrival_map'):
        fit = match('map_position', dict(file='novus-atlas.png', region=[.05,.12,.70,.90], detector=dict(type='atlas_point', target=target)))
        if fit.get('registered'):
            px, py = fit['point']
            # Repeated start at the same spot must not spend another teleport.
            # Check at the enlarged map scale, with the same two-frame proof as arrival.
            if phase == 'arrival_map' or route['zooms'] >= 3:
                if fit.get('found'):
                    radius=22
                    region=[max(.05,(px-radius)/frame['width']),max(.12,(py-radius)/frame['height']),min(.70,(px+radius)/frame['width']),min(.90,(py+radius)/frame['height'])]
                    hits=[]
                    for angle in range(0,360,30):
                        marker=match('arrival_'+str(angle),dict(file='map_player.png',threshold=.88,region=region,angle=angle,scales=[.85,1,1.15]))
                        if marker.get('found') and math.dist(marker['point'],[px,py]) <= 9:
                            hits.append(marker)
                    if hits:
                        route['arrival_checks']=route.get('arrival_checks',0)+1
                        if route['arrival_checks']>=2:
                            return action('back','enable_auto')
                        return report('verify_arrival')
                route['arrival_checks']=0
                if phase == 'arrival_map':
                    return action('back','travelling')
            if not fit.get('found'):
                if route['pans']>=8:
                    return report('map','farm_point_outside_view')
                route['pans']+=1
                cx,cy=frame['width']*.4,frame['height']*.5
                dx=max(-frame['width']*.24,min(frame['width']*.24,cx-px));dy=max(-frame['height']*.22,min(frame['height']*.22,cy-py))
                return action('swipe','map',x1=round(cx),y1=round(cy),x2=round(cx+dx),y2=round(cy+dy),durationMs=700)
            # Two contacts; slight stagger made pinch reliable in the real RU game.
            if route['zooms']<3:
                route['zooms']+=1
                cx=max(frame['width']*.22,min(frame['width']*.52,px));cy=max(frame['height']*.25,min(frame['height']*.72,py))
                delta=frame['width']*.12;gap=frame['width']*.04
                strokes=[]
                for direction,start in [(-1,0),(1,80)]:
                    points=[dict(x=round(cx+direction*gap),y=round(cy))]*2+[dict(x=round(cx+direction*(gap+delta)),y=round(cy))]
                    strokes.append(dict(startMs=start,durationMs=1600-start,points=points))
                return action('gesture','map',strokes=strokes)
            route['selected_at']=[px,py]
            return action('longPress','point_menu',x=round(px),y=round(py),durationMs=900)
    if phase == 'point_menu' and is_map:
        name='map_teleport' if spot.get('travel_mode','walk')=='teleport' else 'map_walk'
        button=match(name)
        if not button.get('found'):
            button=match(name+'_vivo')
        if button.get('found'):
            if spot.get('travel_mode','walk')=='teleport':
                return tap(button,'confirm_teleport')
            route['travel_at']=now
            return tap(button,'travelling')
    if phase == 'open' and hud:
        return open_map('map')
    if now-route['since']>20:
        return report(phase,'farm_'+phase+'_not_recognized')
    return report(phase)
