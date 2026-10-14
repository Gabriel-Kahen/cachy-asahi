"""Integrated pair-v2 configuration/result schema; never a baseline8 receipt."""
import math
import re

INPUTS='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
INVENTORY='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
EPOCH=1791748800
LABELS = ('topmem-1', 'topmem-2', 'fish-1', 'fish-2', 'zsh-1', 'zsh-2')
GATES=('bytes_equal','installed_contents_equal','pkginfo_equal','buildinfo_equal')
MECHANICS=('process_owner','container_owner','custody','input_audit')
KEYS={'schema','lane','source_commit','workflow_commit','run_id','run_attempt','nonce',
      'original_entry','workflow_end','uid','gid','source_root','source_rows','mechanics',
      'cache','work_root','inputs_path','inventory_path','tools','tool_closure','helper_bundle',
      'daemon_id','socket_identity'}


def need(value,code):
    if not value:raise ValueError(code)


def digest(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None
def absolute(value):return(type(value)is str and value.startswith('/')and value!='/'and len(value)<=4096 and
                           all(part not in {'','.','..'}for part in value[1:].split('/'))and
                           not any(c in value for c in ('\0','\n','\r',',')))


def selection(value,environment,now,recipe_rows):
    need(type(value)is dict and set(value)==KEYS and type(value['schema'])is int and value['schema']==1 and
         value['lane']=='native-topmem-fish-zsh-integrated-pairs-v3','pair-selection-schema')
    for key,pattern in [('source_commit','[0-9a-f]{40}'),('workflow_commit','[0-9a-f]{40}'),
                        ('run_id','[1-9][0-9]{0,19}'),('run_attempt','[1-9][0-9]{0,9}'),('nonce','[0-9a-f]{32}')]:
        need(type(value[key])is str and re.fullmatch(pattern,value[key]),'pair-job-field')
    need(environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and
         value['source_commit']==value['workflow_commit']==environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA')and
         value['run_id']==environment.get('GITHUB_RUN_ID')and value['run_attempt']==environment.get('GITHUB_RUN_ATTEMPT'),'pair-job-binding')
    entry,end=value['original_entry'],value['workflow_end']
    need(all(type(x)in(int,float)and math.isfinite(x)and x>0 for x in(entry,end,now))and
         entry<=now<end and end==entry+7200,'pair-original-clock')
    need(type(value['uid'])is int and type(value['gid'])is int and 0<value['uid']<2**31 and 0<value['gid']<2**31,'pair-uid-gid')
    need(all(absolute(value[key])for key in('source_root','cache','work_root','inputs_path','inventory_path')),'pair-path')
    need(type(value['mechanics'])is dict and set(value['mechanics'])==set(MECHANICS)and
         all(type(row)is dict and set(row)=={'path','sha256'}and absolute(row['path'])and digest(row['sha256'])for row in value['mechanics'].values()),'pair-mechanics-pins')
    need(type(value['source_rows'])is dict and len(value['source_rows'])==31,'pair-recipe19')
    need(value['source_rows']==recipe_rows,'pair-exact-recipe-source')
    for name,row in value['source_rows'].items():
        need(type(name)is str and not name.startswith('/')and '\\'not in name and
             all(part not in {'','.','..'}for part in name.split('/'))and
             type(row)is dict and set(row)=={'sha256','bytes','mode'}and digest(row['sha256'])and
             type(row['bytes'])is int and 0<=row['bytes']<=8*1024**2 and
             type(row['mode'])is int and row['mode']in(0o644,0o755),'pair-source-row')
    helper=value['helper_bundle']
    need(type(helper)is dict and set(helper)=={'path','sha256','api'}and absolute(helper['path'])and
         digest(helper['sha256'])and helper['api']=='integrated-pairs-v3','pair-helper-pin-required')
    need(type(value['tools'])is dict and set(value['tools'])=={'docker','gpg'}and all(digest(pin)for pin in value['tools'].values()),'pair-tool-pins')
    need(type(value['tool_closure'])is dict and 0<len(value['tool_closure'])<=64 and
         all(absolute(path)and digest(pin)for path,pin in value['tool_closure'].items()),'pair-linked-tool-closure')
    need(type(value['daemon_id'])is str and re.fullmatch('[A-Za-z0-9:_-]{1,128}',value['daemon_id'])and
         type(value['socket_identity'])is list and len(value['socket_identity'])==6 and
         all(type(x)is int and x>=0 for x in value['socket_identity']),'pair-daemon-socket')
    return {'work_end':end-360,'cleanup_end':end-180,'publication_end':end}


def job_binding(selection,recipe_rows_sha256):
    return {key:selection[key]for key in('source_commit','workflow_commit','run_id','run_attempt','nonce',
            'original_entry','workflow_end','uid','gid','daemon_id','tools','tool_closure','helper_bundle')}|{
            'recipe_rows_sha256':recipe_rows_sha256,'mechanics':selection['mechanics']}


def validate_result(result,expected_job):
    need(type(result)is dict and set(result)=={'schema','lane','job','inputs','image','builds','comparisons',
         'cleanup','first_failure','native_build','signing','lifecycle','hardware'},'pair-result-schema')
    need(type(result['schema'])is int and result['schema']==1 and result['lane']=='native-topmem-fish-zsh-integrated-pairs-v3','pair-result-version')
    need(type(expected_job)is dict and len(expected_job)>=14 and result['job']==expected_job,'pair-result-job-provenance')
    inputs=result['inputs']
    need(inputs['sha256']==INPUTS and inputs['inventory_sha256']==INVENTORY and
         type(inputs['objects'])is int and inputs['objects']==501 and type(inputs['signatures'])is int and
         inputs['signatures']==249 and inputs['source_date_epoch']==EPOCH,'pair-input-result')
    image=result['image'];need(type(image['id'])is str and re.fullmatch('sha256:[0-9a-f]{64}',image['id'])and
         image['inventory_sha256']==INVENTORY and image['platform']=='linux/arm64'and
         digest(image['context_sha256'])and digest(image['provision_sha256'])and
         image['daemon_id']==expected_job['daemon_id'],'pair-image-result')
    builds=result['builds'];need(type(builds)is dict and set(builds)==set(LABELS),'pair-four-builds')
    ids=[]
    for label,row in builds.items():
        need(row['label']==label and row['image_id']==image['id']and row['source_date_epoch']==EPOCH and
             row['status']=='built-package-static-pass'and type(row['container_id'])is str and
             re.fullmatch('[0-9a-f]{64}',row['container_id'])and type(row['exit_code'])is int and row['exit_code']==0,'pair-build-result')
        ids.append(row['container_id'])
        if label.startswith('zsh-'):
            need('zsh-native-fixtures.log' in row['evidence'] and
                 row['evidence']['zsh-native-fixtures.log']['bytes'] <= 262144, 'zsh-fixture-evidence')
            zsh_fixtures(row['zsh_fixture_report'])
        need(digest(row['recipe_rows_sha256'])and row['recipe_rows_sha256']==expected_job['recipe_rows_sha256']and
             row['helper_sha256']==expected_job['helper_bundle']['sha256']and
             row['inventory_sha256']==INVENTORY and type(row['evidence'])is dict and
             {'packages.lock','environment.txt','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO','container.log'}<=set(row['evidence'])and
             any(name.endswith('.pkg.tar.zst')for name in row['evidence']),'pair-build-retained-evidence')
        for name,info in row['evidence'].items():
            need(type(name)is str and '/'not in name and name not in{'','.','..'}and
                 type(info)is dict and set(info)=={'sha256','bytes','mode'}and digest(info['sha256'])and
                 type(info['bytes'])is int and 0<=info['bytes']<=64*1024**2 and
                 type(info['mode'])is int and info['mode']in(0o600,0o644,0o755),'pair-evidence-row')
    need(len(set(ids))==6,'pair-distinct-container-ids')
    need(set(result['comparisons'])=={'topmem','fish','zsh'},'pair-two-comparisons')
    for family,labels in(('topmem',LABELS[:2]),('fish',LABELS[2:4]),('zsh',LABELS[4:])):
        row=result['comparisons'][family]
        need(row['labels']==list(labels)and row['errors']==[]and type(row['packages'])is dict and len(row['packages'])==1 and
             all(type(data)is dict and all(data.get(key)is True for key in GATES)for data in row['packages'].values()),'pair-strict-four-gates')
    need(result['cleanup']['status']=='PASS'and result['cleanup']['errors']==[]and result['cleanup']['cause']is None and
         result['first_failure']is None and result['native_build']=='PASS','pair-cleanup-cause')
    need(result['signing']==result['lifecycle']==result['hardware']=='NOT RUN','pair-not-baseline-or-lifecycle')
    return result


def zsh_fixtures(report):
    need(type(report) is dict and report.get('status') == 'PASS-host-fixtures' and
         report.get('architecture') in ('aarch64','arm64') and
         report.get('wrapper_sha256') == '692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768' and
         report.get('module_sha256') == 'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a', 'zsh-fixture-binding')
    tests=report.get('tests')
    names=('noninteractive-noop','real-zle-suggest-accept-edit-coexist-repeat','preloaded-module-preserved',
           'sigint-owned-fixture-cleanup','absent-package-removal-guard')
    need(type(tests) is list and len(tests)==5 and all(type(row) is dict for row in tests) and
         tuple(row.get('name') for row in tests)==names and all(row.get('status')=='PASS' for row in tests),
         'zsh-five-fixture-results')
    need(all(report.get(key)=='NOT RUN' for key in ('native_arm','target_installation','page16k','m2_hardware')),
         'zsh-fixture-scope')
    return report
