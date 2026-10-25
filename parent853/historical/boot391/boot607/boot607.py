# SPDX-License-Identifier: MIT
"""Accepted Boot pair inside genuine signed native606; synthetic fixtures only."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import time
import accepted_inputs as A
import native_contract as N
import package_graph as G

PHASES=('install607','same-version607','remove606','reinstall607','final606')

def exercise(g,context):
    C=g['C'];need=C.need;home=context['home'];base=context['expected']
    N.native_scope('/',home,'/out/boot607-native.log')
    need(len(base)==606 and g['inventory']()==base and A.NAME not in base and
         hashlib.sha256(Path('/runner/expected606.lock').read_bytes()).hexdigest()==
         '3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1', 'exact original current606 boundary')
    context['preservation'](base)
    plan=C.read(Path('/tools606/boot607/input-plan.json'))
    need(plan['status']=='READY_ACCEPTED_BOOT_PAIR_FRESH_ORIGINAL_TEST_SIGNATURE' and
         plan['authority_scope']=='INPUTS_ONLY_NO_NEW_NATIVE606_OR607_ACCEPTANCE' and
         plan['accepted_source']==A.SOURCE and plan['accepted_run']==A.RUN and plan['accepted_index']==A.INDEX and
         plan['name']==A.NAME and plan['version']==A.VERSION and
         {k:plan[k] for k in ('bytes','sha256')}==A.ARCHIVE and
         all(plan[k] is None for k in ('actual_source','actual_ref','actual_run')), 'source-pinned accepted input-only plan')
    need(plan['signer_roles']==context['s']['original']['preparation']['signer_roles'] and
         plan['signer']==plan['signer_roles']['ephemeral_TEST'], 'same original producer TEST authority')
    archive=Path('/tools606/boot607')/plan['archive'];signature=archive.with_name(archive.name+'.sig')
    need(archive.parent==Path('/tools606/boot607') and A.pin(A.read(archive))==A.ARCHIVE and
         plan['signature']['path']==signature.name and A.pin(A.read(signature,65536))==
         {k:plan['signature'][k] for k in ('bytes','sha256')}, 'exact retained archive/new original TEST signature')
    g['verify_signature'](['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'],archive,signature,plan['signer'])
    meta=g['metadata'](archive)
    need(meta['pkgname']==[A.NAME] and meta['pkgver']==[A.VERSION] and meta['arch']==['any'] and
         meta['depend']==['python>=3.11','systemd>=251'] and
         not any(meta.get(k) for k in ('conflict','replaces','backup','install')), 'exact script-only metadata and installed dependency operands')
    need(set(plan['payload'])==set(A.PAYLOAD) and all(not os.path.lexists('/'+n) for n in G.SELECTED_FILES|G.SELECTED_DIRS), 'Boot absent before baseline606')
    old=context['L'];driver=context['driver'];I=context['I'];audio=context['audio'];adapter=context['adapter'];audio_rows=context['audio_rows']
    B=C.load('boot607_whole_boot79_lifecycle',Path('/runner/boot607/accepted-lifecycle.py'))
    F=C.load('boot_fixture',Path('/runner/boot607/boot_fixture.py'))
    fixture=Path('/runner/boot607/boot-fixture');fixture_before=F.snapshot(fixture)
    need(F.pin(fixture/'system.journal')['sha256']=='77c326d908442852de51e66c660153d4c6051390b14466e48fa9c037cc1c573e', 'whole accepted real synthetic journal DATA')
    account=pwd.getpwnam('alarm');homes=[];receipts={};events=[];aux=[]
    def private_snapshot(root):
        values={}
        for p in (root,*sorted(root.rglob('*'))):
            s=p.lstat();need(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode),'ordinary private user/report nodes')
            values[str(p.relative_to(root))]=dict(identity=G.key(s),value=os.readlink(p) if stat.S_ISLNK(s.st_mode) else hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(s.st_mode) else None)
        return values
    for kind in ('fresh','existing'):
        h=Path('/tmp')/('boot607-home-'+kind);h.mkdir(mode=0o700)
        if kind=='existing':
            (h/'.config').mkdir();(h/'.config/user-sentinel').write_text('preserve existing boot606 user settings\n');(h/'.config/alias').symlink_to('user-sentinel')
        for p in (h,*h.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((h,private_snapshot(h)))
    def users():
        need(F.snapshot(fixture)==fixture_before,'whole readonly synthetic fixture DATA changed')
        for h,before in homes:need(private_snapshot(h)==before,'private existing/fresh user state changed')
        for p,before in receipts.items():need(private_snapshot(p)==before,'previous private report bytes/metadata changed')
    phase='baseline606'
    def mark(operation):
        data=dict(schema_version=1,status='NATIVE_BOOT_COMPONENT_PROGRESS_DATA_ONLY',phase=phase,operation=operation,source_owned_nonce=plan['nonce'],nonce_authority=plan['nonce_authority'],clock='GUEST_MONOTONIC_NOT_INDEPENDENT_ROOT_AUTHORITY',monotonic=time.monotonic(),acceptance='NOT_GRANTED')
        (g['OUT']/'boot607-progress.json').write_bytes(C.encoded(data))
    # Original caller/owner imposes1800/6600; this inner deadline never extends it.
    deadline=time.monotonic()+1800
    def capture(want):
        mark('complete-package-graph-capture')
        need(g['inventory']()==want,'exact native606/607 inventory')
        rows=driver.database(Path('/'),max_packages=607)
        need({r['name']:r['version'] for r in rows}==want,'independent complete raw database inventory')
        users()
        return G.capture(Path('/'),rows,deadline=deadline)
    previous=capture(base);baseline_sha=hashlib.sha256(C.encoded(previous)).hexdigest()
    previous_ld,previous_aux=context['previous_ld'],context['previous_aux']
    def auxiliary(label):
        nonlocal previous_ld,previous_aux
        state=audio.ld_state(adapter,audio_rows);data,_,_=audio.ld_aux_read(state)
        transition=audio.aux_order.compare(previous_aux,data)
        # No post-prepare exec can run ldconfig. Require exact raw bytes AND the
        # entire original helper/config/alias/scan/target/cache state, freshly.
        need(data==previous_aux and state==previous_ld,'complete original raw auxiliary state changed')
        raw=C.encoded(state);(g['OUT']/('boot607-ld-'+label+'.json')).write_bytes(raw);(g['OUT']/('boot607-aux-'+label+'.bin')).write_bytes(data)
        aux.append(dict(phase=label,state_sha256=hashlib.sha256(raw).hexdigest(),aux_sha256=hashlib.sha256(data).hexdigest(),transition=transition,helper_exit='NOT_OBSERVED'))
        previous_ld,previous_aux=state,data
    auxiliary('baseline606')
    archive_operand=dict(path=str(archive),**A.ARCHIVE,signature=dict(path=str(signature),**{k:plan['signature'][k] for k in ('bytes','sha256')}),signer=plan['signer'],version=A.VERSION)
    supervised=C.scoped_load('boot607_held_supervisor',Path('/runner/boot607/copyworker/scripts/ci/current606-apps7-copy/supervised.py'),{'contract':N})
    def step(label,want):
        nonlocal previous,phase
        phase=label
        mark('signed-transaction-and-retirement')
        operand=archive_operand if A.NAME in want else None
        value=dict(root='/',before={r['name']:r['version'] for r in previous['packages']},after=want,archive=operand,keys=str(home),log='/out/boot607-alpm.log')
        path=g['OUT']/('boot607-step-'+label+'.json');need(not path.exists(),'fresh owned transaction plan')
        path.write_bytes(C.encoded(value));path.chmod(0o600)
        result=supervised.run(['/usr/bin/python3','-I','-B','/runner/boot607/step_entry.py',str(path)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','CACHY_ASAHI_EXPANDED604':os.environ['CACHY_ASAHI_EXPANDED604']},cwd='/',timeout=min(90,max(0.001,deadline-time.monotonic())),output_limit=128*1024,grace=1)
        need(result['returncode']==0 and result['termination'] is None and result['direct_child_reaped'] is True and result['group_retired'] is True,'native signed Boot step/retirement failed')
        transaction=A.decode(result['stdout'])
        need(transaction['status']=='COMMITTED_SELECTED_BOOT_REQUIRES_FULL_NATIVE_READBACK','exact signed selected Boot transaction receipt')
        current=capture(want)
        proof=G.protected(previous,current,lock_witness=transaction['lock_parent'])
        previous=current
        observations=[]
        if A.NAME in want:
            selected_rows=[r for r in current['packages'] if r['name']==A.NAME]
            need(len(selected_rows)==1 and selected_rows[0]['version']==A.VERSION and selected_rows[0]['arch']=='any' and
                 set(selected_rows[0]['files'])==G.SELECTED_FILES and selected_rows[0]['depend']==['python>=3.11','systemd>=251'] and
                 selected_rows[0]['provides']==selected_rows[0]['conflict']==[], 'complete actual selected ALPM ownership/dependency record')
            for name,expected in plan['payload'].items():
                node=current['nodes'][name];identity=node['identity']
                need(node['kind']=='file' and identity[3]==identity[4]==0 and stat.S_IMODE(identity[2])==expected['mode'] and
                     identity[5]==1 and node['sha256']==expected['sha256'] and node['capability'] is None, 'exact selected installed regular single-link source/license bytes and no capabilities')
            for name in G.SELECTED_DIRS:
                node=current['nodes'][name];identity=node['identity']
                leaves=sorted(n.rsplit('/',1)[-1] for n in G.SELECTED_FILES if n.rpartition('/')[0]==name)
                need(node['kind']=='directory' and identity[3]==identity[4]==0 and stat.S_IMODE(identity[2])==0o755 and
                     node['capability'] is None and node['children']==leaves, 'exact selected private directory modes/ownership/children/capabilities')
            I.payloads(old,{A.NAME:plan})
            for h,_ in homes:
                mark('installed-original15-fixture-'+h.name)
                root=Path('/tmp')/('boot607-'+h.name+'-'+label);root.mkdir(mode=0o700);os.chown(root,account.pw_uid,account.pw_gid)
                argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','HOME='+str(h),'/usr/bin/python3','-I','-B','/runner/boot607/installed_fixture.py','--root',str(root),'--home',str(h),'--fixture',str(fixture),'--output',str(root/'receipt.json')]
                B.command(argv,timeout=100);row=json.loads((root/'receipt.json').read_bytes());F.validate(row,F.pin(fixture/'system.journal')['sha256'])
                need(all(p.lstat().st_uid==account.pw_uid for p in (root/'report').iterdir()),'ordinary report file ownership')
                receipts[root/'report']=private_snapshot(root/'report');observations.append(dict(home=h.name,boot=row))
        else:
            need(all(not os.path.lexists('/'+name) for name in G.SELECTED_FILES|G.SELECTED_DIRS),'selected Boot payload remains after removal')
            context['preservation'](base)
        users()
        # The installed real CLI must also leave the observed complete606 graph
        # unchanged, independently of its15 private input/report assertions.
        after_fixture=capture(want)
        need(after_fixture==current,'native installed CLI changed observed606/607 package/user/config graph')
        mark('independent-raw-auxiliary-readback')
        auxiliary(label)
        g['run'](context['pacman']+['-Dk']);deps=sorted({d for r in current['packages'] for d in r['depend']});g['run'](context['pacman']+['-T',*deps])
        events.append(dict(phase=label,count=len(want),other606=proof,signature='REQUIRED_ORIGINAL_EPHEMERAL_TEST',transaction=transaction,observations=observations,graph_sha256=hashlib.sha256(C.encoded(current)).hexdigest(),fixture_graph_unchanged=True,user_config_preserved=True,prior_reports_preserved=True))
    target=base|{A.NAME:A.VERSION}
    for label,want in zip(PHASES,(target,target,base,target,base)):step(label,want)
    context['preservation'](base)
    mark('restored606-before-original-native-continuation')
    result=dict(status='PASS_NATIVE606_TO607_ACCEPTED_BOOT_SYNTHETIC_LIFECYCLE_REQUIRES_REPLAY',source_owned_nonce=plan['nonce'],nonce_authority=plan['nonce_authority'],scope=previous['scope'],base_count=606,installed_count=607,restored_count=606,baseline_graph_sha256=baseline_sha,events=events,ldconfig=aux,new_boot_builds='NOT_RUN_ACCEPTED_PAIR_REUSED',chroot_copy607='NOT_ISSUED',hardware='NOT_RUN',GUI='NOT_RUN',real_journal='NOT_READ',live_pstore='NOT_READ',release='NOT_ADMITTED')
    (g['OUT']/'boot607.json').write_bytes(C.encoded(result));context['s']['report']['boot607']=result
    return previous_ld,previous_aux
