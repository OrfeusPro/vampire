"""Assemble an offline profile from context-selected reports, never active settings."""
import hashlib
import locale
from pathlib import Path

HERE=Path(__file__).resolve().parent

def assemble(reports):
    """Cross-check independently recorded outputs, without inventing missing cases."""
    def unique(items,label):
        if len(items)!=1:raise ValueError('Missing or ambiguous '+label)
        return items[0]
    default=unique([c['values'] for c in reports['defaults']['cases'] if c['kind']=='settings_prefix' and c['poison']==0],'default case')
    if (default['build_code'],default['sdk_zone'],default['market'])!=(0,1,''):
        raise ValueError('Initial settings differ')
    game=unique([c['actual'] for c in reports['override']['cases'] if c['environment']=='real' and c['nmenv'] is None
                 and c['sdk_present'] and c['sdk_handle']],'production override')
    if (game['build_code'],game['sdk_zone'],game['market'],game['game_code'],game['raw_c8'])!=(0,2,'nmp','thered',0):
        raise ValueError('Production override differs')
    pc=[c for c in reports['platform']['cases'] if c['platform_byte']==3]
    if len(pc)!=4 or any(c['actual']!='PC' or not c['canaries_unchanged'] for c in pc):
        raise ValueError('PC cases missing or different')
    gmc=unique([c['values'] for c in reports['defaults']['cases'] if c['kind']=='gmc_constructor' and c['poison']==0],'GMC constructor')
    start=reports['start']['cases']
    if len({(c['zone'],c['flag']) for c in start})!=512:
        raise ValueError('Incomplete Start matrix')
    for case in start:
        offset={0:'0x150',2:'0x170',3:'0x180'}.get(case['zone'],'0x160')
        if case['source_offset']!=offset or case['destination_offset']!='0x1e8' or case['active_base']!=gmc[offset]:
            raise ValueError('Constructor and Start disagree')
    base={c['active_base'] for c in start if c['zone']==game['sdk_zone']}
    if base!={'https://apis.netmarble.com/gc2'}:raise ValueError('Production base differs')
    version=unique([c['values']['0x0'] for c in reports['defaults']['cases'] if c['kind']=='sdk_version'],'SDK version')
    url=unique([c['actual'] for c in reports['url']['cases'] if (c['base'],c['group'],c['build_code'],c['market'])==
                (next(iter(base)),gmc['0x1c8'],game['build_code'],game['market'])],'production URL')
    capture=unique([c for c in reports['headers']['cases'] if c['inputs']['url']==url and
        c['inputs']['game_code']==game['game_code'] and c['inputs']['service_code']==gmc['0x190'] and
        c['inputs']['build_code']==game['build_code'] and all(c['inputs'][key]=='' for key in
            ('device_key','access_token','player_id','etag'))],'public HTTP capture')
    profile=dict(base=next(iter(base)),group=gmc['0x1c8'],sdk_version=version,build_code=game['build_code'],
                 market=game['market'],game_code=game['game_code'],service_code=gmc['0x190'])
    # Portable code is an additional comparison, never a source for a missing native output.
    import sys
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sdk_config import assemble_gmc2_config_url_ascii
    from vampir_core.gmc2_request import plan_gmc2_get_request
    if url!=assemble_gmc2_config_url_ascii(**{k:profile[k] for k in ('base','group','sdk_version','build_code','market')}):
        raise ValueError('SDK version and native URL disagree')
    plan=plan_gmc2_get_request(**capture['inputs'])
    actual=capture['actual']
    if actual['url']!=url or actual['method']!=plan.method or tuple(map(tuple,actual['headers']))!=plan.headers:
        raise ValueError('Public HTTP capture disagrees')
    return dict(public_gmc2=dict(profile=profile,request=actual),nid=dict(profile=dict(
        game_code=game['game_code'],client_id=game['client_id'],build_code=game['build_code'],os_type='PC',
        raw_webview_type=0,country_code='',language='en',os_version='')))


def resolve(index, workflow, args, contract, outcomes, sha):
    """Validate mutable inputs before consulting a prepared-profile stage cache."""
    source=args.install/'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    if index.digest(source)!=sha:raise ValueError('Installed source differs from context')
    for name in ('sdk-gmc2',contract['id']):
        outcome=outcomes[name]
        if outcome['state']!='passed' or not outcome.get('checks'):raise ValueError('Unverified profile prerequisite: '+name)
        for check in outcome['checks']:
            if check['state']!='passed' or 'report' not in check:raise ValueError('Profile check has no proof report')
            path=Path(check['report'])
            proof=workflow.checked_manifest(index,path)
            if (index.digest(path)!=check['sha256'] or proof.get('definition',{}).get('source_sha256')!=sha or
                proof.get('state')!='passed' or proof.get('definition',{}).get('check',{}).get('id')!=check['id']):
                raise ValueError('Profile check source/hash differs')
    reports={};evidence={}
    for role,definition in contract['profile_reports'].items():
        pattern=definition['pattern']
        if not pattern.startswith('code-clues/') or '..' in pattern or not pattern.endswith('/*/manifest.json'):
            raise ValueError('Profile report pattern outside public native reports')
        valid=[];stale=[]
        for path in sorted(args.root.glob(pattern)):
            report=workflow.checked_manifest(index,path)
            if report.get('source_sha256')!=sha:continue
            if not isinstance(report.get('cases'),list) or len(report['cases'])<definition['min_cases']:
                stale.append(str(path));continue
            current=True
            if not report.get('dependencies'):raise ValueError('Profile report has no dependencies')
            for filename,digest in report['dependencies'].items():
                dependency=(HERE/filename).resolve()
                if not dependency.is_relative_to(HERE.resolve()):raise ValueError('Profile dependency outside tools')
                if index.digest(dependency)!=digest:current=False
            if not current:stale.append(str(path));continue
            for artifact in report.get('evidence',[]):
                ap=Path(artifact['path']).resolve()
                if not ap.is_relative_to((args.root/'ghidra').resolve()) or index.digest(ap)!=artifact['sha256']:
                    raise ValueError('Profile report export changed')
            if not report.get('evidence') or not report.get('limits'):raise ValueError('Incomplete profile evidence')
            if role in ('url','headers'):
                helper='sdk_config.py' if role=='url' else 'gmc2_request.py'
                if index.digest(HERE.parents[1]/'vampir-shared/vampir_core'/helper)!=report.get('portable_helper_sha256'):
                    raise ValueError('Profile portable comparison changed')
            valid.append((path,report))
        if len(valid)!=1:raise ValueError('Missing or ambiguous current profile report: '+role+'; stale='+str(len(stale)))
        path,report=valid[0];reports[role]=report
        evidence[role]=dict(path=str(path),sha256=index.digest(path),cases=len(report['cases']),limits=report['limits'])
    helpers=reports['nid_helpers']
    if helpers.get('native_primitives') is not True:raise ValueError('Actual NID primitives are not verified')
    crt=helpers['primitive_evidence']['crt']
    runtime=workflow.system_runtime_files(['ucrtbase.dll'])[0]
    if Path(crt['path']).resolve()!=runtime.resolve() or index.digest(runtime)!=crt['sha256'] or locale.setlocale(locale.LC_ALL)!=crt['locale']:
        raise ValueError('Profile CRT environment changed')
    return dict(reports=reports,evidence=evidence,runtime=crt,source=str(source))


def inputs(index, workflow, args, contract, outcomes, sha):
    selected=resolve(index,workflow,args,contract,outcomes,sha)
    return dict(reports=selected['evidence'],runtime=selected['runtime'],source_sha256=sha)


def build(index, workflow, args, contract, outcomes, sha, contexts):
    """Only declared report families; new source reports do not require Python constants."""
    selected=resolve(index,workflow,args,contract,outcomes,sha)
    reports,evidence,source=selected['reports'],selected['evidence'],selected['source']
    assembled=assemble(reports)
    profile=dict(schema=1,name='prepared-release',source=str(source),source_sha256=sha,**assembled,
        evidence=evidence,runtime_scope='sdk-launcher-auth',supported_auth_flows=['launcher'],
        direct_sdk_operations_verified=False,active_runtime_settings_verified=False,
        network_ready=False,game_protocol_verified=False,
        local_choices=['Real environment; NMENV absent; PC / raw WebView 0 / English; runtime identity/country/OS remain fresh inputs.'])
    package=dict(schema=1,source_sha256=sha,profile=profile,contexts=contexts,
        checks={n:r['checks'] for n,r in outcomes.items() if r['state']=='passed'},
        state='prepared_offline',live_verified=False,activated=False)
    expected=dict(reports=evidence,runtime=selected['runtime'],source_sha256=sha)
    if inputs(index,workflow,args,contract,outcomes,sha)!=expected:
        raise ValueError('Profile inputs changed during preparation')
    target=workflow.snapshot(args.root,'prepared-profiles',package)
    return dict(profile=str(target),source_sha256=sha,activated=False,live_verified=False)
