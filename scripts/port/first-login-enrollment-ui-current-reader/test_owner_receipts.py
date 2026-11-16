# SPDX-License-Identifier: MIT
"""Independent fictional retained receipts; import Reader only, never a producer."""
import copy
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in (
            'os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('owner receipt DATA controls forbid '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('independent_owner_receipt_reader',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
LABEL='org.cachy-asahi.current-onboarding'
CAPS=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID']


def token(ad):
    return hashlib.sha256(R.encoded(dict(binding=ad['binding'],selector=ad['selector'],stage=ad['stage']))).hexdigest()[:24]


def natural():
    return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                timeout=False,signals=[],error=None,exit=0,seconds=0.1)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fiction-current-receipts-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.signer='A'*40
        self.status=('[GNUPG:] VALIDSIG '+self.signer+' 2026-11-15 1 0 4 0 1 10 00 '+self.signer+
                     '\n[GNUPG:] TRUST_ULTIMATE\n').encode()
        self.output=self.root/'output';self.output.mkdir()
        self.cap=dict(build_seconds=180,total_seconds=600,command_rows=512)

    def keep(self,path,body):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(body);return dict(path=str(path),**R.pin(body))

    def signature(self):
        a=self.keep(self.root/'inputs/FICTION.archive',b'FICTION NOT A PACKAGE')
        s=self.keep(self.root/'inputs/FICTION.signature',b'FICTION NOT A SIGNATURE')
        public=self.keep(self.root/'inputs/FICTION-public.asc',b'FICTION NOT A PUBLIC KEY')
        key=dict(trust_scope='TEST_ONLY',fingerprint=self.signer,**{k:public[k] for k in ('bytes','sha256')})
        proof=dict(schema=1,Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,
            trust_scope='TEST_ONLY',archive={k:a[k] for k in ('bytes','sha256')},
            signature={k:s[k] for k in ('bytes','sha256')},public_test_key=key,
            actual_verified_utc='2026-11-15T12:00:00+00:00')
        p=self.keep(self.root/'inputs/Root-verification.json',R.encoded(proof))
        decision=dict(schema=1,issuer='Root',status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY',
            accepted=True,holds_preserved=True,trust_scope='TEST_ONLY',
            archive=dict(package='cachy-asahi-setup',version='0.3.0-1',arch='any',**R.pin(b'FICTION NOT A PACKAGE')),
            signature=R.pin(b'FICTION NOT A SIGNATURE'),signature_file=s['path'],
            verification_proof_sha256=p['sha256'],public_test_key=key,public_test_key_file=public['path'],
            issued_at='2026-11-15T12:01:00+00:00')
        d=self.keep(self.root/'inputs/Root-decision.json',R.encoded(decision))
        issued=datetime.datetime.fromisoformat('2026-11-16T12:00:00+00:00').timestamp()
        ad=dict(schema=1,issuer='Root',approved=True,selector='FICTION-stage-selector',operation=R.OP,stage='backend',
            binding=dict(source='b'*40,ref='refs/heads/codex/FICTION',run='1',job='2',attempt=1,
                         source_lock=R.pin(b'FICTION SOURCE LOCK')),
            issued_at_unix=issued,expires_at_unix=issued+300,resources=self.cap,
            owner=dict(test_fingerprint=self.signer,test_public_key=public))
        value=dict(archive=a,signature=s,current_TEST_signature_verification=dict(Root_decision=d,Root_verification=p))
        recipe=dict(archive_pin=R.pin(b'FICTION NOT A PACKAGE'))
        return value,recipe,ad,decision,proof

    def save_selection(self,value,decision,proof):
        row=value['current_TEST_signature_verification']
        row['Root_verification']=self.keep(row['Root_verification']['path'],R.encoded(proof))
        decision['verification_proof_sha256']=row['Root_verification']['sha256']
        row['Root_decision']=self.keep(row['Root_decision']['path'],R.encoded(decision))

    def command(self,step,argv,raw,where=None,rows=None):
        where=self.output if where is None else where;rows=[] if rows is None else rows
        log='%03d-%s.log'%(len(rows),step);self.keep(where/'commands'/log,raw)
        row=dict(step=step,argv=argv,cwd=str(where),expected=0,success=True,log=log,log_pin=R.pin(raw),
            supervision=natural(),channels='stdout+stderr combined in pipe order')
        rows.append(row);return row

    def test_historical_root_decision_selects_exact_public_test_key_without_fresh_claim(self):
        value,recipe,ad,_,_=self.signature()
        selection=R.signature_inputs(value,recipe,ad,R.Reads())
        self.assertEqual(selection['kind'],'ROOT_RETAINED_TEST_SIGNATURE_DECISION')
        self.assertEqual(selection['archive'],value['archive']);self.assertEqual(selection['signature'],value['signature'])
        self.assertEqual(selection['fingerprint'],self.signer)
        self.assertEqual(selection['public_key'],ad['owner']['test_public_key'])
        self.assertEqual(selection['trust_scope'],'TEST_ONLY')

    def test_root_decision_and_verification_semantic_mutations_refuse(self):
        value,recipe,ad,decision,proof=self.signature()
        changes=[('accepted',lambda d,p:d.update(accepted=False)),
            ('holds',lambda d,p:d.update(holds_preserved=False)),
            ('scope',lambda d,p:d.update(trust_scope='SYSTEM')),
            ('version',lambda d,p:d['archive'].update(version='0.3.0-2')),
            ('architecture',lambda d,p:d['archive'].update(arch='aarch64')),
            ('signature-path',lambda d,p:d.update(signature_file='/FICTION/other.sig')),
            ('verification',lambda d,p:p.update(verified=False)),
            ('signer',lambda d,p:p['public_test_key'].update(fingerprint='B'*40)),
            ('ordering',lambda d,p:p.update(actual_verified_utc='2026-11-15T12:02:00+00:00')),
            ('timezone',lambda d,p:d.update(issued_at='2026-11-15T12:01:00'))]
        for label,mutate in changes:
            v,d,p=copy.deepcopy(value),copy.deepcopy(decision),copy.deepcopy(proof);mutate(d,p)
            self.save_selection(v,d,p)
            with self.subTest(label=label),self.assertRaises((ValueError,KeyError)):
                R.signature_inputs(v,recipe,ad,R.Reads())

    def test_archive_key_and_proof_whole_pin_drift_refuse(self):
        value,recipe,ad,_,_=self.signature()
        for field in ('archive','signature'):
            v=copy.deepcopy(value);v[field]['sha256']='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):R.signature_inputs(v,recipe,ad,R.Reads())
        ad['owner']['test_public_key']['sha256']='0'*64
        with self.assertRaises(ValueError):R.signature_inputs(value,recipe,ad,R.Reads())

    def test_recorded_signature_requires_strict_trust_and_natural_pinned_command(self):
        argv=['/usr/bin/gpg','--homedir','/tmp/build-tools-test-FICTION/trust','--batch',
              '--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',
              '/FICTION/package.sig','/FICTION/package']
        row=self.command('owner-current-signature-setup8',argv,self.status)
        index=R.command_index([row],self.output,R.Reads(),self.cap)
        R.strict_signature(index[row['step']][2],self.signer)
        for bad in (self.status+b'[GNUPG:] KEYEXPIRED 1\n',self.status.replace(b'TRUST_ULTIMATE',b'TRUST_UNDEFINED'),
                    self.status+self.status,self.status.replace(self.signer.encode(),b'B'*40)):
            with self.subTest(status=bad),self.assertRaises(ValueError):R.strict_signature(bad,self.signer)
        for mutation in ({'signals':[15]},{'timeout':True},{'emergency_retirement':True},{'ownership':'UNKNOWN'}):
            bad=copy.deepcopy(row);bad['supervision'].update(mutation)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                R.command_index([bad],self.output,R.Reads(),self.cap)
        (self.output/'commands'/row['log']).write_bytes(b'FICTION CHANGED LOG')
        with self.assertRaises(ValueError):R.command_index([row],self.output,R.Reads(),self.cap)

    def stage(self,stage='backend'):
        value,_,ad,_,_=self.signature();ad['stage']=stage
        inputs={'setup8':value};rows=[]
        admin=self.output/('owner-admin/commands' if stage=='lifecycle' else 'owner-state/admission')
        work='/tmp/build-tools-test-FICTION';trust=work+'/trust'
        verifier=['/usr/bin/gpg','--homedir',trust,'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
        def emit(step,argv,body=b''):
            log='%03d-%s.log'%(len(rows),step);self.keep(admin/log,body)
            row=dict(step=step,argv=argv,cwd=str(admin.parent),expected=0,success=True,log=log,log_pin=R.pin(body),
                supervision=natural(),channels='stdout+stderr combined in pipe order')
            rows.append(row);return row
        if stage!='lifecycle':
            emit('fresh-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token(ad)])
            emit('native-daemon',DOCKER+['info','--format','{{json .}}'],R.encoded(dict(OSType='linux',Architecture='aarch64',
                CgroupVersion='2',MemoryLimit=True,SwapLimit=True,CpuCfsQuota=True,PidsLimit=True,SecurityOptions=[])))
        emit('import-root-test-public',verifier+['--import',work+'/public.asc'])
        emit('current-primary',verifier+['--with-colons','--list-keys'],('fpr:::::::::'+self.signer+':\n').encode())
        emit('trust-current-test-primary',verifier+['--import-ownertrust',work+'/ownertrust'])
        row=emit('owner-current-signature-setup8',verifier+['--status-fd=1','--verify',value['signature']['path'],value['archive']['path']],self.status)
        stage_proof=dict(status='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION',operation=R.OP,stage=stage,
            binding=ad['binding'],scope='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION',verified={
                'setup8':dict(archive={k:value['archive'][k] for k in ('bytes','sha256')},
                    signature={k:value['signature'][k] for k in ('bytes','sha256')},
                    public_test_key={k:ad['owner']['test_public_key'][k] for k in ('bytes','sha256')},
                    fingerprint=self.signer,status_text=self.status.decode(),command=copy.deepcopy(row))})
        for i,name in enumerate(('trust','home')):
            home=work+'/'+name
            emit('retire-private-'+str(i),['/usr/bin/gpgconf','--homedir',home,'--kill','all'])
            emit('no-agent-private-'+str(i),['/usr/bin/gpg-connect-agent','--homedir',home,'--no-autostart','/bye'],
                 b'gpg-connect-agent: no gpg-agent running in this session\n')
        self.keep(admin/'commands.json',R.encoded(rows))
        report=dict(stage_signature_verification=stage_proof)
        return inputs,ad,report,admin,rows

    def test_stage_recorded_gpg_joins_root_selection_and_private_trust_retirement(self):
        inputs,ad,report,_,_=self.stage()
        R.stage_verification(self.output,inputs,ad,report,R.Reads(),'backend')

    def test_stage_receipt_cannot_substitute_root_claim_or_command_bytes(self):
        inputs,ad,report,admin,rows=self.stage()
        for field,value in (('scope','ROOT_VERIFIED_CURRENT_GPG'),('stage','ui'),('binding',{'FICTION':'other'})):
            bad=copy.deepcopy(report);bad['stage_signature_verification'][field]=value
            with self.subTest(field=field),self.assertRaises((ValueError,KeyError)):
                R.stage_verification(self.output,inputs,ad,bad,R.Reads(),'backend')
        bad=copy.deepcopy(report);bad['stage_signature_verification']['verified']['setup8']['command']['argv'][-1]='/FICTION/other.archive'
        with self.assertRaises((ValueError,KeyError)):R.stage_verification(self.output,inputs,ad,bad,R.Reads(),'backend')
        sig=next(row for row in rows if row['step']=='owner-current-signature-setup8')
        (admin/sig['log']).write_bytes(self.status+b'[GNUPG:] BADSIG A\n')
        with self.assertRaises(ValueError):R.stage_verification(self.output,inputs,ad,report,R.Reads(),'backend')

    def test_stage_missing_trust_preparation_or_agent_retirement_refuses(self):
        inputs,ad,report,admin,rows=self.stage()
        for step in ('import-root-test-public','current-primary','trust-current-test-primary','retire-private-1','no-agent-private-0'):
            # Renumber the entire remaining stream, so refusal cannot rely on an
            # incidental missing log number instead of the omitted obligation.
            changed=[]
            for original in rows:
                if original['step']==step:continue
                row=copy.deepcopy(original);body=(admin/original['log']).read_bytes()
                row['log']='%03d-%s.log'%(len(changed),row['step']);self.keep(admin/row['log'],body);changed.append(row)
            self.keep(admin/'commands.json',R.encoded(changed))
            changed_report=copy.deepcopy(report)
            changed_report['stage_signature_verification']['verified']['setup8']['command']=next(
                row for row in changed if row['step']=='owner-current-signature-setup8')
            with self.subTest(step=step),self.assertRaises((ValueError,KeyError)):
                R.stage_verification(self.output,inputs,ad,changed_report,R.Reads(),'backend')
        self.keep(admin/'commands.json',R.encoded(rows))

    def outer(self):
        _,_,ad,_,_=self.signature();ad['stage']='lifecycle'
        self.output=self.root/'outer-result-parent'/'output';self.output.mkdir(parents=True)
        source=self.root/'FICTION-Source';retained=self.output/'outer-owner';retained.mkdir()
        state=Path('/tmp/current-onboarding-owner-FICTION1234');manifest_path=state/'inside.json'
        inputs={'source_date_epoch':17};inp=self.keep(self.root/'inputs/owner-inputs.json',R.encoded(inputs))
        admission=self.root/'Root-admission.json';code={}
        for i,(name,expected) in enumerate(R.CODE.items()):
            # Read as inert DATA only. No producer module is imported, compiled,
            # called, or used to construct expected policy/receipts.
            body=(HERE.parents[2]/name).read_bytes()
            self.assertEqual(R.pin(body),{k:expected[k] for k in ('bytes','sha256')})
            self.keep(source/name,body);self.keep(retained/('code-'+str(i)),body)
            code[str(source/name)]=dict(path=str(state/('code-'+str(i))),**R.pin(body))
        ad.update(source_root=str(source),output=str(self.output),images={'lifecycle':dict(id='sha256:'+'c'*64)},
            signed={key:dict(archive=str(self.root/'signed'/(key+'.archive')),signature=str(self.root/'signed'/(key+'.sig')))
                    for key in ('setup8',*R.KINDS)})
        ad['owner'].update(api='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2',
            code=dict(path=str(source/R.OWNER),**{k:R.CODE[R.OWNER][k] for k in ('bytes','sha256')}),
            inputs=inp,admission_path=str(admission),launch_manifest=str(manifest_path),
            lifecycle_capabilities=list(CAPS),input_references=[])
        admission_ref=self.keep(admission,R.encoded(ad))
        manifest=dict(admission=admission_ref,inputs=inp,grant_sha256=R.pin(R.encoded(ad))['sha256'],
                      host_uid=12345,host_gid=12346,deadline=500.0)
        m=self.keep(retained/'inside.json',R.encoded(manifest))
        code[str(manifest_path)]=dict(path=str(manifest_path),**{k:m[k] for k in ('bytes','sha256')})
        mounts={str(source):(str(source),False),str(self.output.parent):(str(self.output.parent),True),
                str(admission):(str(admission),False),inp['path']:(inp['path'],False)}
        def references(value):
            if type(value)is dict:
                if set(value)=={'path','bytes','sha256'}:yield value
                else:
                    for item in value.values():yield from references(item)
            elif type(value)is list:
                for item in value:yield from references(item)
        for row in references(ad):mounts[row['path']]=(row['path'],False)
        for dst,row in code.items():mounts[dst]=(row['path'],False)
        for row in ad['signed'].values():
            for field in ('archive','signature'):mounts[row[field]]=(row[field],False)
        label={LABEL:token(ad),LABEL+'.operation':R.OP,LABEL+'.stage':'lifecycle',LABEL+'.source':ad['binding']['source']}
        name='cachy-asahi-current-'+token(ad)+'-lifecycle';image=ad['images']['lifecycle']['id']
        cmd=['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-onboarding',
             ad['owner']['code']['path'],'--inside-lifecycle',str(manifest_path)]
        argv=DOCKER+['create','--name',name,'--pull=never','--platform','linux/arm64','--user','0:0',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit','512','--memory','4g','--memory-swap=4g',
            '--cpus','4','--network','none','--init=false']
        for capability in CAPS:argv+=['--cap-add',capability]
        for key,value in label.items():argv+=['--label',key+'='+value]
        for dst,(src,rw) in sorted(mounts.items()):argv+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
        argv+=['--entrypoint','/bin/bash',image,*cmd]
        intent=dict(name=name,image=image,user='0:0',mounts=[[d,s,rw] for d,(s,rw) in sorted(mounts.items())],
            entrypoint=['/bin/bash'],cmd=cmd,labels=label,readonly=False,capadd=list(CAPS),tmpfs={},create_argv=argv)
        created=dict(Id='d'*64,Name='/'+name,Image=image,
            Config=dict(User='0:0',Entrypoint=['/bin/bash'],Cmd=cmd,Labels=label),
            HostConfig=dict(NetworkMode='none',ReadonlyRootfs=False,Privileged=False,CapDrop=['ALL'],CapAdd=list(CAPS),
                SecurityOpt=['no-new-privileges'],VolumesFrom=None,Tmpfs={},PidMode='',IpcMode='private',UTSMode='',
                Devices=[],DeviceRequests=None,Memory=4*1024**3,MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,Init=False,AutoRemove=False),
            Mounts=[dict(Type='bind',Destination=d,Source=s,RW=rw) for d,s,rw in intent['mounts']],
            State=dict(Running=False,ExitCode=0,OOMKilled=False))
        terminal=copy.deepcopy(created);retirement=dict(status='REMOVED_AND_ABSENT',name=name,cid=created['Id'],inspection=copy.deepcopy(terminal))
        receipt=dict(status='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT',operation=R.OP,stage='lifecycle',binding=ad['binding'],
                     intent=intent,code_refs=code,created=created,terminal=terminal,retirement=retirement,commands=[])
        daemon=dict(OSType='linux',Architecture='aarch64',CgroupVersion='2',MemoryLimit=True,SwapLimit=True,CpuCfsQuota=True,PidsLimit=True,SecurityOptions=[])
        query=DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}']
        rows=receipt['commands'];cid=created['Id']
        for step,command,body in [('fresh-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token(ad)],b''),
            ('native-daemon',DOCKER+['info','--format','{{json .}}'],R.encoded(daemon)),('fresh-name',query,b''),
            ('create',argv,(cid+'\n').encode()),('inspect-created',DOCKER+['container','inspect',cid],R.encoded([created])),
            ('start-attached',DOCKER+['container','start','--attach',cid],b'FICTION ACTOR OUTPUT\n'),
            ('inspect-terminal',DOCKER+['container','inspect',cid],R.encoded([terminal])),
            ('retire-query',query,(cid+' '+name+'\n').encode()),
            ('retire-inspect',DOCKER+['container','inspect',name],R.encoded([retirement['inspection']])),
            ('retire-remove',DOCKER+['container','rm','--force',cid],(cid+'\n').encode()),('retire-after',query,b'')]:
            self.command(step,command,body,where=retained,rows=rows)
        local=dict(operation=R.OP,stage='lifecycle',binding=ad['binding'],status='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT',
            body_success=True,protected_state_unchanged=True,failures=[],private_retirement=dict(homes_retired=True,no_sockets=True,
                private_directory_absent=True,registered=2,retired=2,failures=[]))
        self.keep(self.output/'owner-local.json',R.encoded(local))
        self.save_outer(receipt)
        return source,inputs,ad,dict(outer_retirement=receipt)

    def save_outer(self,receipt):
        root=self.output/'outer-owner'
        self.keep(root/'receipt.final.json',R.encoded(receipt));self.keep(root/'intent.json',R.encoded(receipt['intent']))
        self.keep(root/'commands/commands.json',R.encoded(receipt['commands']))

    def test_outer_retirement_reconstructs_launch_and_retained_code_without_producer_import(self):
        source,inputs,ad,report=self.outer()
        result=R.outer_lifecycle(self.output,source,inputs,ad,report,R.Reads())
        self.assertEqual(result['actual_owned_cid'],'d'*64);self.assertTrue(result['natural_retirement'])
        self.assertTrue(result['retained_absence_observation']);self.assertEqual(result['private_homes'],2)

    def test_outer_coherent_launch_or_namespace_substitution_refuses(self):
        source,inputs,ad,report=self.outer();original=copy.deepcopy(report['outer_retirement'])
        for mutation in ('bash','capability','socket','mount','cid'):
            receipt=copy.deepcopy(original);intent=receipt['intent']
            if mutation=='bash':
                intent['entrypoint']=['/bin/sh'];intent['create_argv'][intent['create_argv'].index('--entrypoint')+1]='/bin/sh'
            if mutation=='capability':intent['capadd'].append('SYS_ADMIN')
            if mutation=='socket':intent['mounts'].append(['/run/docker.sock','/run/docker.sock',True])
            if mutation=='mount':intent['mounts'][0][2]=not intent['mounts'][0][2]
            for observed in (receipt['created'],receipt['terminal'],receipt['retirement']['inspection']):
                observed['Config']['Entrypoint']=intent['entrypoint'];observed['HostConfig']['CapAdd']=intent['capadd']
                observed['Mounts']=[dict(Type='bind',Destination=d,Source=s,RW=rw) for d,s,rw in intent['mounts']]
                if mutation=='cid':observed['Id']='e'*64
            receipt['commands'][3]['argv']=intent['create_argv']
            self.save_outer(receipt);changed=dict(outer_retirement=receipt)
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,KeyError)):
                R.outer_lifecycle(self.output,source,inputs,ad,changed,R.Reads())
        self.save_outer(original)

    def test_outer_nonnatural_absence_query_log_and_private_cleanup_drift_refuse(self):
        source,inputs,ad,report=self.outer();original=copy.deepcopy(report['outer_retirement'])
        for mutation in ('signal','failed-query','nonempty-absence','log-drift','carrier-drift','private-cleanup'):
            receipt=copy.deepcopy(original);root=self.output/'outer-owner'
            if mutation=='signal':receipt['commands'][5]['supervision']['signals']=[15]
            if mutation=='failed-query':receipt['commands'][-1]['success']=False
            if mutation=='nonempty-absence':
                row=receipt['commands'][-1];self.keep(root/'commands'/row['log'],b'FICTION surviving container\n');row['log_pin']=R.pin(b'FICTION surviving container\n')
            if mutation=='log-drift':self.keep(root/'commands'/receipt['commands'][4]['log'],b'FICTION CHANGED INSPECTION\n')
            if mutation=='carrier-drift':self.keep(root/'code-0',b'FICTION CHANGED CARRIER')
            if mutation=='private-cleanup':
                local=R.decode((self.output/'owner-local.json').read_bytes());local['private_retirement']['retired']=1
                self.keep(self.output/'owner-local.json',R.encoded(local))
            self.save_outer(receipt)
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,KeyError)):
                R.outer_lifecycle(self.output,source,inputs,ad,dict(outer_retirement=receipt),R.Reads())
            # Restore all DATA before the next independent mutation.
            if mutation=='carrier-drift':self.keep(root/'code-0',(source/next(iter(R.CODE))).read_bytes())
            if mutation=='private-cleanup':
                local['private_retirement']['retired']=2;self.keep(self.output/'owner-local.json',R.encoded(local))
            for step in ('retire-after','inspect-created'):
                row=next(r for r in original['commands'] if r['step']==step)
                body=b'' if step=='retire-after' else R.encoded([original['created']])
                self.keep(root/'commands'/row['log'],body)
        self.save_outer(original)

    def backend_retirement(self):
        _,_,ad,_,_=self.signature();source=self.root/'FICTION-build-source';source.mkdir()
        ad['images']={'backend':{'id':'sha256:'+'c'*64}}
        state=self.output/'owner-state';(state/'intents').mkdir(parents=True)
        label={LABEL:token(ad),LABEL+'.operation':R.OP,LABEL+'.stage':'backend',LABEL+'.source':ad['binding']['source']}
        def stream(root,entries):
            rows=[]
            for step,argv,body in entries:
                log='%03d-%s.log'%(len(rows),step);self.keep(root/log,body)
                rows.append(dict(step=step,argv=argv,cwd=str(root.parent),expected=0,success=True,log=log,
                    log_pin=R.pin(body),supervision=natural(),channels='stdout+stderr combined in pipe order'))
            self.keep(root/'commands.json',R.encoded(rows));return rows
        paths=[];names=[]
        for number,(kind,suffix) in enumerate(((k,s) for k in ('enrollment','first-login') for s in ('a','b')),1):
            name='cachy-asahi-%016x'%number;names.append(name);slot=self.output/'builds'/(kind+'-'+suffix)
            image=ad['images']['backend']['id'];user='12345:12346';cid='%064x'%number
            mounts=[['/inputs',str(slot/'inputs'),False],['/out',str(slot/'artifacts'),True],
                ['/builder-entry.sh',str(source/'scripts/build/container-entry.sh'),False],
                ['/expected-packages.lock',str(slot/'expected-packages.lock'),False]]
            declared=['docker','run','--rm','--name',name,'--pull=never','--platform','linux/arm64','--user',user,
                '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','512','--memory','4g','--cpus','4',
                '--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1',
                '--env','SOURCE_DATE_EPOCH=17']
            for dst,src,rw in mounts:declared+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
            declared+=['--entrypoint','/bin/bash',image,'/builder-entry.sh'];self.assertEqual(len(declared),39)
            self.keep(slot/'provenance.json',R.encoded(dict(command=declared,clean_environment_id=name)))
            create=DOCKER+['create',*declared[3:-4],'--memory-swap=4g']
            for key,value in label.items():create+=['--label',key+'='+value]
            create+=declared[-4:]
            intent=dict(name=name,image=image,user=user,mounts=mounts,entrypoint=['/bin/bash'],cmd=['/builder-entry.sh'],
                labels=label,readonly=True,create_argv=create,declared_argv=declared,slot=str(slot),capadd=[],
                tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})
            observed=dict(Id=cid,Name='/'+name,Image=image,
                Config=dict(User=user,Entrypoint=['/bin/bash'],Cmd=['/builder-entry.sh'],Labels=label),
                HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=[],
                    SecurityOpt=['no-new-privileges'],VolumesFrom=None,Tmpfs=intent['tmpfs'],PidMode='',IpcMode='private',UTSMode='',
                    Devices=[],DeviceRequests=None,Memory=4*1024**3,MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,Init=False,AutoRemove=False),
                Mounts=[dict(Type='bind',Destination=d,Source=s,RW=rw) for d,s,rw in mounts],
                State=dict(Running=False,ExitCode=0,OOMKilled=False))
            retirement=dict(status='REMOVED_AND_ABSENT',name=name,cid=cid,inspection=observed)
            result=dict(status='PASS_OWNED_GENERIC_BUILD_PROXY',name=name,created=observed,terminal=observed,retirement=retirement)
            self.keep(state/'intents'/(name+'.json'),R.encoded(intent));result_path=state/'intents'/(name+'.result')
            self.keep(result_path,R.encoded(result))
            image_dir=state/('proxy-%02d-image'%number)/'commands'
            stream(image_dir,[('image-inspect',DOCKER+['image','inspect',image],R.encoded([dict(Id=image,Architecture='arm64',Os='linux')]))])
            native_dir=state/('proxy-%02d-native'%number)/'commands'
            stream(native_dir,[('native-architecture',DOCKER+['info','--format','{{.Architecture}}'],b'aarch64\n')])
            container_dir=state/('proxy-%02d-container'%number)/'commands'
            query=DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}']
            rows=stream(container_dir,[('fresh-name',query,b''),('create',create,(cid+'\n').encode()),
                ('inspect-created',DOCKER+['container','inspect',cid],R.encoded([observed])),
                ('start-attached',DOCKER+['container','start','--attach',cid],b'FICTION BUILD OUTPUT\n'),
                ('inspect-terminal',DOCKER+['container','inspect',cid],R.encoded([observed])),
                ('proxy-final-query',query,(cid+' '+name+'\n').encode()),
                ('proxy-final-inspect',DOCKER+['container','inspect',name],R.encoded([observed])),
                ('proxy-final-remove',DOCKER+['container','rm','--force',cid],(cid+'\n').encode()),
                ('proxy-final-after',query,b'')])
            paths.append((result_path,container_dir,rows,result))
        daemon=dict(OSType='linux',Architecture='aarch64',CgroupVersion='2',MemoryLimit=True,SwapLimit=True,CpuCfsQuota=True,PidsLimit=True,SecurityOptions=[])
        stream(state/'admission',[('fresh-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token(ad)],b''),
            ('native-daemon',DOCKER+['info','--format','{{json .}}'],R.encoded(daemon))])
        final=[('retire-'+str(i)+'-query',DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'],b'')
               for i,name in enumerate(sorted(names))]
        final.append(('final-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token(ad)],b''))
        stream(state/'retirement',final)
        self.keep(state/'cleanup.json',R.encoded(dict(stage='backend',binding=ad['binding'],failures=[],
            retired=[dict(status='ABSENT',name=name) for name in sorted(names)])))
        self.keep(state/'proxy.json',R.encoded(dict(grant=ad,source=str(source),output=str(self.output),uid=12345,gid=12346,deadline=500.0)))
        return source,dict(source_date_epoch=17),ad,{}, {},paths

    def test_build_retirement_complete_four_backend_containers_and_twelve_proxies(self):
        source,inputs,ad,report,commands,_=self.backend_retirement()
        result=R.build_retirement(self.output,source,inputs,ad,report,commands,R.Reads(),'backend')
        self.assertEqual(result['owned_build_containers'],4)
        self.assertTrue(result['actual_created_terminal_inspections']);self.assertTrue(result['retained_exact_absence_queries'])

    def test_build_retirement_changed_result_absence_nonnatural_and_log_drift_refuse(self):
        source,inputs,ad,report,commands,paths=self.backend_retirement()
        result_path,root,original_rows,original_result=paths[0]
        for mutation in ('coherent-result','nonempty-absence','nonnatural','log-drift'):
            rows=copy.deepcopy(original_rows);result=copy.deepcopy(original_result)
            if mutation=='coherent-result':
                for observed in (result['created'],result['terminal'],result['retirement']['inspection']):observed['State']['OOMKilled']=True
                for step in ('inspect-created','inspect-terminal','proxy-final-inspect'):
                    row=next(r for r in rows if r['step']==step);body=R.encoded([result['created']])
                    self.keep(root/row['log'],body);row['log_pin']=R.pin(body)
            if mutation=='nonempty-absence':
                row=rows[-1];body=b'FICTION surviving owned CID\n';self.keep(root/row['log'],body);row['log_pin']=R.pin(body)
            if mutation=='nonnatural':rows[3]['supervision']['signals']=[15]
            if mutation=='log-drift':self.keep(root/rows[2]['log'],b'FICTION CHANGED RAW INSPECTION\n')
            self.keep(result_path,R.encoded(result));self.keep(root/'commands.json',R.encoded(rows))
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,KeyError)):
                R.build_retirement(self.output,source,inputs,ad,report,commands,R.Reads(),'backend')
            for row in original_rows:
                if row['step'] in ('inspect-created','inspect-terminal','proxy-final-inspect'):
                    self.keep(root/row['log'],R.encoded([original_result['created']]))
                if row['step']=='proxy-final-after':self.keep(root/row['log'],b'')
            self.keep(root/'commands.json',R.encoded(original_rows));self.keep(result_path,R.encoded(original_result))


if __name__=='__main__':unittest.main()
