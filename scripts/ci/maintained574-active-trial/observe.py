#!/usr/bin/env python3
"""Native optional-owner normal/cancellation trial with independent daemon reads."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s

PHASES = ('root-import','build-create','build-copy','active-build','commit','probe-create','active-probe','completed')
ACTIVE_TOOLS = {'pacman','pacman-key','gpg','gpg-agent','ldconfig'}


def image_list(values):
    s.need(type(values) is list and len(values)<=64 and len(set(values))==len(values) and
           all(type(v) is str and s.IMAGE.fullmatch(v) for v in values),'invalid_image_membership')
    return values


def resource_rows(rows, token, containers):
    s.need(type(rows) is list and len(rows)<=2,'resource_count')
    output=[]
    for row in rows:
        if containers:
            s.need(s.CID.fullmatch(row['cid']) and s.IMAGE.fullmatch(row['image']) and
                   row['name'] in ['cachy-asahi-574-active-'+token+'-'+k for k in ('build','probe')],'container_identity_shape')
            value={k:row[k] for k in ('cid','name','image')}
        else:
            s.need(s.IMAGE.fullmatch(row['id']) and row['tag'] in
                   ['cachy-asahi-574-active:'+token+'-'+k for k in ('root','result')],'image_identity_shape')
            value={k:row[k] for k in ('id','tag')}
        if 'absence_verified' in row:
            s.need(type(row['absence_verified']) is bool,'absence_boolean'); value['absence_verified']=row['absence_verified']
        output.append(value)
    key='cid' if containers else 'id'
    s.need(len({r[key] for r in output})==len(output),'duplicate_resource')
    return output


def project_owner(value):
    token=value['token']; s.need(type(token) is str and s.TOKEN.fullmatch(token),'owner_token')
    s.need(value['status'] in ('PASS','FAIL') and value['phase'] in PHASES and
           type(value['cancelled']) is bool and value['helper_sha256']==s.PINS['maintained_desktop574.py'] and
           value['inputs_sha256']==s.PINS['maintained-desktop574-inputs.json'],'owner_contract')
    result={k:value[k] for k in ('status','phase','cancelled','token','helper_sha256','inputs_sha256')}
    result['initial_image_ids']=image_list(value['initial_image_ids'])
    for key in ('packages','inventory_sha256'):
        if key in value:
            s.need(value[key]==(574 if key=='packages' else 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'),'owner_inventory')
            result[key]=value[key]
    if 'error_kind' in value:
        s.need(type(value['error_kind']) is str and re.fullmatch('[A-Za-z0-9_]{1,64}',value['error_kind']),'owner_error_kind')
        result['error_kind']=value['error_kind']
    if 'build_failure' in value:
        failure=value['build_failure']
        s.need(value['phase']=='active-build' and value['status']=='FAIL' and
               type(failure) is dict and set(failure)=={'returncode','log_bytes','tail_bytes','tail_sha256','tail_base64'},
               'build_diagnostic_shape')
        s.need(type(failure['returncode']) is int and failure['returncode']!=0 and
               type(failure['log_bytes']) is int and failure['log_bytes']>=0 and
               type(failure['tail_bytes']) is int and 0<=failure['tail_bytes']<=4096 and
               type(failure['tail_base64']) is str and len(failure['tail_base64'])<=5464,
               'build_diagnostic_bound')
        raw=base64.b64decode(failure['tail_base64'],validate=True)
        s.need(len(raw)==failure['tail_bytes']==min(failure['log_bytes'],4096) and
               s.sha(raw)==failure['tail_sha256'],'build_diagnostic_join')
        result['build_failure']=dict(failure)
    cleanup=value['cleanup']
    s.need(cleanup['status'] in ('PASS','FAIL') and type(cleanup['client_fenced']) is bool and
           type(cleanup['initial_image_ids_preserved']) is bool,'cleanup_contract')
    projected={k:cleanup[k] for k in ('status','client_fenced','initial_image_ids_preserved')}
    projected['initial_image_ids']=image_list(cleanup['initial_image_ids'])
    if 'after_image_ids' in cleanup: projected['after_image_ids']=image_list(cleanup['after_image_ids'])
    for key in ('containers','captured_containers','images','captured_images'):
        projected[key]=resource_rows(cleanup[key],token,'containers' in key)
    s.need(projected['initial_image_ids']==result['initial_image_ids'],'baseline_receipt_join')
    result['cleanup']=projected
    return result


def active(docker, receipt, transaction, label):
    """Running held shell + observed transaction child, then a second running read."""
    if receipt.get('phase')!='active-build': return None
    token=receipt['token']; s.need(s.TOKEN.fullmatch(token),'observer_token')
    identity=resource_rows([receipt['active_executor']],token,True)[0]
    s.need(identity['name']=='cachy-asahi-574-active-'+token+'-build','observer_build_name')
    def inspect():
        rows=json.loads(docker.run('container','inspect',identity['cid']))
        s.need(len(rows)==1,'observer_inspect_count'); row=rows[0]
        config,host,state=row['Config'],row['HostConfig'],row['State']
        s.need(row['Id']==identity['cid'] and row['Name']=='/'+identity['name'] and row['Image']==identity['image'] and
               (config.get('Labels') or {}).get(label)==token and config.get('Entrypoint')==['/bin/sh'] and
               config.get('Cmd')==['-ec',transaction],'observer_exact_transaction_identity')
        s.need(host['NetworkMode']=='none' and host['Privileged'] is False and not host.get('CapAdd') and
               not host.get('Binds') and not host.get('Devices'),'observer_executor_policy')
        s.need(type(state['Running']) is bool,'observer_running_boolean')
        return state
    state=inspect()
    if not state['Running']: return None
    s.need(type(state['Pid']) is int and state['Pid']>0,'observer_running_pid')
    top=docker.run('container','top',identity['cid'],'-eo','pid,comm')
    s.need(len(top.encode())<=8192 and len(top.splitlines())<=128,'observer_process_bound')
    tools=[]
    for line in top.splitlines()[1:]:
        fields=line.split()
        s.need(len(fields)==2 and fields[0].isdigit() and re.fullmatch('[A-Za-z0-9_.+-]{1,32}',fields[1]),'observer_process_shape')
        if fields[1] in ACTIVE_TOOLS: tools.append(fields[1])
    if not tools: return None
    state2=inspect()
    if not state2['Running']: return None
    return dict(identity,token=token,running=True,transaction_sha256=s.sha(transaction.encode()),
                observed_transaction_tools=sorted(set(tools)),running_inspections=2)


def absent(docker, owner, baseline, observed=None):
    cleanup=owner['cleanup']; token=owner['token']
    s.need(cleanup['status']=='PASS' and cleanup['client_fenced'] and cleanup['initial_image_ids_preserved'],'owner_cleanup_not_passed')
    s.need(owner['initial_image_ids']==baseline,'independent_baseline_join')
    for kind in ('containers','images'):
        captured=cleanup['captured_'+kind]; retired=cleanup[kind]
        s.need(captured and [{k:v for k,v in row.items() if k!='absence_verified'} for row in retired]==list(reversed(captured)) and
               all(row.get('absence_verified') is True for row in retired),'cleanup_membership_join')
    s.need({row['image'] for row in cleanup['captured_containers']} <=
           {row['id'] for row in cleanup['captured_images']},'captured_container_image_join')
    if observed:
        s.need(observed['token']==token and
               any(row['cid']==observed['cid'] and row['name']==observed['name'] and row['image']==observed['image']
                   for row in cleanup['captured_containers']),'observed_executor_cleanup_join')
    for row in cleanup['captured_containers']:
        s.need(not docker.run('container','ls','-a','--no-trunc','--filter','id='+row['cid'],'--format','{{.ID}}'),'independent_CID_remains')
    for kind in ('build','probe'):
        name='cachy-asahi-574-active-'+token+'-'+kind
        s.need(not docker.run('container','ls','-a','--filter','name=^/'+name+'$','--format','{{.ID}}'),'independent_name_remains')
    after=s.images(docker)
    for row in cleanup['captured_images']:
        s.need(row['id'] not in baseline and row['id'] not in after and
               not docker.run('image','ls','-a','--filter','reference='+row['tag'],'-q'),'independent_image_or_tag_remains')
    label='org.cachy-asahi.bootstrap574.active-job='+token
    s.need(not docker.run('container','ls','-a','--filter','label='+label,'--format','{{.ID}}') and
           not docker.run('image','ls','-a','--filter','label='+label,'-q'),'independent_label_remains')
    s.need(set(baseline)<=set(after),'independent_initial_image_lost')
    return {'status':'PASS','initial_image_ids_preserved':True,'after_image_ids':after,
            'containers_absent':len(cleanup['captured_containers']),'images_absent':len(cleanup['captured_images'])}


def wait_active(proc, docker, path, transaction, label, deadline):
    while proc.poll() is None:
        s.need(time.monotonic()<deadline,'active_observation_deadline')
        if path.is_file():
            value,_=s.read(path)
            try:
                observed=active(docker,value,transaction,label)
            except Exception:
                # A completed normal owner may already have removed its CID.
                latest,_=s.read(path)
                if proc.poll() is not None or latest.get('phase')=='completed': return None
                raise
            if observed: return observed
        time.sleep(0.1)
    return None


def stop(proc):
    forced=False
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try: proc.wait(timeout=600)
        except subprocess.TimeoutExpired:
            forced=True
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5)
    else: proc.wait(timeout=5)
    try: os.killpg(proc.pid,0)
    except ProcessLookupError: group_absent=True
    else: group_absent=False
    return {'reaped':proc.returncode is not None,'exit_code':proc.returncode,
            'forced_kill':forced,'owner_session_absent':group_absent}


def case(mode, module, ci, prepared, out, transaction):
    out.mkdir(mode=0o700); queries=out/'queries'; queries.mkdir(mode=0o700)
    docker=module.Docker(queries); baseline=image_list(s.images(docker))
    result={'mode':mode,'status':'FAIL','running_transaction_observed':False,'TERM_sent':False,
            'initial_image_ids':baseline,'hardware':'NOT RUN'}
    child=None; observed=None; failure=None
    try:
        with (out/'owner-child.log').open('xb') as log:
            child=subprocess.Popen([sys.executable,'-I','-B',str(ci/'maintained574_active_owner.py'),
                '--source-ci',str(ci),'--prepared-context',str(prepared),'--output',str(out/'owner')],
                env=dict(s.ENV,HOME=str(out)),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            if mode=='normal':
                child.wait(timeout=3600)
            else:
                observed=wait_active(child,docker,out/'owner/result.json',transaction,module.LABEL,time.monotonic()+3000)
                if observed:
                    result.update(running_transaction_observed=True,observation=observed)
                    # Recheck our unreaped child immediately before signalling it.
                    s.need(child.poll() is None,'owner_finished_before_TERM')
                    child.send_signal(signal.SIGTERM); result['TERM_sent']=True
                child.wait(timeout=600)
    except BaseException as error:
        failure=error; result['error']=s.error(error)
    finally:
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            if child is not None:
                try: result['owner_process']=stop(child)
                except Exception as error:
                    if failure is None: failure=error; result['error']=s.error(error)
                    result['owner_process']={'reaped':False,'forced_kill':True,'owner_session_absent':False,'exit_code':child.returncode}
            path=out/'owner/result.json'
            if path.is_file():
                try:
                    owner,identity=s.read(path); owner=project_owner(owner)
                    result.update(owner=owner,owner_receipt=identity)
                    result['independent_absence']=absent(docker,owner,baseline,observed)
                    process=result['owner_process']
                    s.need(process['reaped'] and process['owner_session_absent'] and not process['forced_kill'],'owner_reaping_not_established')
                    if failure is None:
                        if mode=='normal':
                            s.need(owner['status']=='PASS' and not owner['cancelled'] and owner['phase']=='completed' and
                                   owner.get('packages')==574 and process['exit_code']==0,'normal_optional_owner_not_passed')
                            result['status']='PASS_NORMAL_OPTIONAL_574'
                        elif observed is None:
                            s.need(owner['status']=='PASS' and not owner['cancelled'] and process['exit_code']==0,'owner_failed_before_observation')
                            result['status']='NOT_ESTABLISHED'
                        else:
                            s.need(result['TERM_sent'] and owner['status']=='FAIL' and owner['cancelled'] and
                                   owner['phase']=='active-build' and process['exit_code']!=0,'cancellation_contract_not_met')
                            result['status']='PASS_ACTIVE_TRANSACTION_CANCELLATION'
                except BaseException as error:
                    if failure is None: failure=error; result['error']=s.error(error)
        finally:
            if signal.sigpending() & {signal.SIGTERM,signal.SIGINT}: result['status']='FAIL'
            s.save(out/'case.json',result)
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    if isinstance(failure,KeyboardInterrupt): raise failure
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-ci','prepared-context','output','public-output'): parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--mode',choices=('normal','cancel','both'),default='both')
    args=parser.parse_args(); os.umask(0o077)
    s.need(not any(k.startswith(('CACHY_','DOCKER_')) for k in os.environ),'clean_trial_environment_required')
    s.need(re.fullmatch('[0-9a-f]{40}',args.source_commit),'explicit_source_required')
    ci,prepared,out=args.source_ci.absolute(),args.prepared_context.absolute(),args.output.absolute()
    module=s.load(ci,'maintained574_active_owner.py'); module.private(prepared)
    s.need(not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)) and
           not out.is_relative_to(prepared) and not prepared.is_relative_to(out),'fresh_trial_output_required')
    out.mkdir(mode=0o700); queries=out/'guard'; queries.mkdir(mode=0o700)
    result={'status':'FAIL','scope':'NATIVE_OPTIONAL_574_ACTIVE_CANCELLATION_TRIAL','source_commit':args.source_commit,
            'source_pins':s.PINS,'cases':[],'hardware':'NOT RUN','performance':'NOT RUN','legacy_docker_build':'NOT RUN'}
    old={}
    try:
        s.need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and
               os.getuid()==os.geteuid()>0,'ordinary_native_ARM_required')
        docker=module.Docker(queries)
        s.need(docker.run('context','show')=='default','default_context_required')
        context=json.loads(docker.run('context','inspect','default'))
        s.need(len(context)==1 and context[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local_daemon_required')
        arch=docker.run('info','--format','{{.Architecture}}'); s.need(arch in ('aarch64','arm64'),'native_daemon_required')
        result['runner']={'machine':platform.machine(),'page_size':os.sysconf('SC_PAGE_SIZE'),'uid':os.getuid(),'gid':os.getgid(),
                          'daemon_arch':arch,'endpoint':'unix:///var/run/docker.sock','server_version':docker.run('version','--format','{{.Server.Version}}')}
        s.need(re.fullmatch('[0-9A-Za-z.+_-]{1,64}',result['runner']['server_version']),'server_version_shape')
        held=s.load(ci,'maintained_desktop574.py')
        transaction=held.DOCKERFILE.split('\nRUN ',1)[1].replace('\\\n','').strip()
        def cancel(*_): raise KeyboardInterrupt()
        for sig in (signal.SIGINT,signal.SIGTERM): old[sig]=signal.signal(sig,cancel)
        s.save(args.public_output,result)
        for mode in (('normal','cancel') if args.mode=='both' else (args.mode,)):
            result['active_mode']=mode; s.save(args.public_output,result)
            try: row=case(mode,module,ci,prepared,out/mode,transaction)
            except BaseException:
                if (out/mode/'case.json').is_file():
                    row,_=s.read(out/mode/'case.json'); result['cases'].append(row)
                raise
            result['cases'].append(row)
            s.save(args.public_output,result)
            s.need(row['status'] in ('PASS_NORMAL_OPTIONAL_574','PASS_ACTIVE_TRANSACTION_CANCELLATION'),'case_not_established')
        result['status']='PASS'
        result.pop('active_mode',None)
    except BaseException as error:
        result['error']=s.error(error)
        raise
    finally:
        for sig,handler in old.items(): signal.signal(sig,handler)
        s.save(args.public_output,result)
    return 0


if __name__=='__main__': raise SystemExit(main())
