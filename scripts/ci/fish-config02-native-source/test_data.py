# SPDX-License-Identifier: MIT
"""Actor-fenced Source/contract and modeled native workflow controls only."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=module('fish_contract_controls',HERE/'contract.py');P=module('fish_prepare_controls',HERE/'prepare.py');E=module('fish_entry_controls',HERE/'entry.py');F=module('fish_finish_controls',HERE/'finish_pair.py')
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('Fish02 DATA controls prohibit actual actors: '+event)
sys.addaudithook(fence)


def authority(profile,kind):
    return dict(kind=kind,issued_by='Root',accepted=True,source='a'*40,ref='refs/heads/MODELED-FISH02',source_map_sha256='b'*64,nonce='c'*32,created_utc=99,expires_utc=200,resources=profile['resources'])

def context():return dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='123456',GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/MODELED-FISH02')

def selected():
    p=C.load(HERE/'profile.json');a=authority(p,'ROOT_FISH02_HOSTED_ADMISSION_V1');r=authority(p,'ROOT_FISH02_HOSTED_RUNTIME_V1');r.update(bootstrap_resource_domain=dict(sha256='d'*64),external_supervision=dict(sha256='e'*64));return p,a,r



def read_with_drift(reader, field=None, content=False):
    with tempfile.TemporaryDirectory(prefix='fish-read-stability-DATA-') as temporary:
        path=Path(temporary)/'leaf';path.write_bytes(b'PAYLOAD')
        initial=path.stat();original_stat=Path.lstat;original_read=Path.read_bytes;done=False
        fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_atime','st_atime_ns','st_mtime','st_ctime')
        def observed(p,*args,**kwargs):
            value=original_stat(p,*args,**kwargs)
            if p!=path or content:return value
            values={name:getattr(value,name) for name in fields}
            if done:values[field]+=1
            return types.SimpleNamespace(**values)
        def consume(p,*args,**kwargs):
            nonlocal done
            raw=original_read(p,*args,**kwargs)
            if p==path:
                done=True
                if content:
                    path.write_bytes(b'MUTATED')
                    os.utime(path,ns=(initial.st_atime_ns,initial.st_mtime_ns+1))
            return raw
        with patch.object(Path,'lstat',observed),patch.object(Path,'read_bytes',consume):
            return reader(path)

class Controls(unittest.TestCase):
    def test_read_atime_only_change_is_allowed(self):
        self.assertEqual(read_with_drift(C.read,'st_atime_ns'),b'PAYLOAD')
        self.assertEqual(read_with_drift(C.read,'st_atime'),b'PAYLOAD')
        def prior_whole_stat_read(path):
            before=path.lstat();raw=path.read_bytes()
            if path.lstat()!=before:raise ValueError('prior atime false HOLD')
            return raw
        with self.assertRaisesRegex(ValueError,'atime false HOLD'):
            read_with_drift(prior_whole_stat_read,'st_atime_ns')

    def test_read_content_and_each_security_metadata_change_refuse(self):
        for field in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'):
            with self.subTest(field=field),self.assertRaises(ValueError):read_with_drift(C.read,field)
        with self.assertRaises(ValueError):read_with_drift(C.read,content=True)

    def test_constructor_exact_current_Main_recipe_runtime_and_null_actuals(self):
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary)/'Source';report=P.construct(ROOT,out)
            self.assertEqual(report['files'],32);self.assertLess(report['bytes'],1024**2);self.assertTrue(all(v is None for v in report['actual'].values()))
            manifest=C.verify_source(out,report['source_map']['sha256'])
            base=out/C.PREFIX
            self.assertEqual(len(list((base/'recipe').iterdir())),6)
            profile=C.load(HERE/'profile.json')
            for name,row in profile['held_inputs'].items():self.assertEqual((base/name).read_bytes(),(ROOT/row['source_path']).read_bytes())
            self.assertEqual((base/'finish_pair.py').read_bytes(),(HERE/'finish_pair.py').read_bytes())
            self.assertEqual(len((base/'expected349.lock').read_text().splitlines()),349)
            for line in ('fish 4.9.3-1','coreutils 9.12-2','python 3.14.8-1'):self.assertIn(line,(base/'expected349.lock').read_text().splitlines())
            self.assertIn(C.WORKFLOW,manifest['files'])

    def test_constructor_tamper_missing_alias_and_reuse_refusals(self):
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary)/'Source';report=P.construct(ROOT,out);path=out/C.PREFIX/'recipe/config.fish';original=path.read_bytes()
            path.write_bytes(original+b'changed')
            with self.assertRaises(ValueError):C.verify_source(out,report['source_map']['sha256'])
            path.write_bytes(original);path.unlink()
            with self.assertRaisesRegex(ValueError,'closed Source namespace'):C.verify_source(out,report['source_map']['sha256'])
            path.symlink_to(HERE/'profile.json')
            with self.assertRaises(ValueError):C.verify_source(out,report['source_map']['sha256'])
            path.unlink();path.write_bytes(original);path.chmod(0o755)
            with self.assertRaises(ValueError):C.verify_source(out,report['source_map']['sha256'])
            path.chmod(0o644);(out/'foreign.py').write_text('# never executed')
            with self.assertRaises(ValueError):C.verify_source(out,report['source_map']['sha256'])
            (out/'foreign.py').unlink()
            with self.assertRaises(ValueError):P.construct(ROOT,out)

    def test_three_exact_builder_edits_inverse_and_unmodified_normal_entry(self):
        original=(ROOT/'scripts/build/build_v2.py').read_bytes();changed=C.projected_build(original);inverse=changed.decode()
        for before,after in reversed(C.BUILD_EDITS):inverse=inverse.replace(after,before)
        self.assertEqual(inverse.encode(),original);self.assertIn("'--memory-swap', '4g'",changed.decode())
        with self.assertRaises(ValueError):C.projected_build(original.replace(b"'--memory', '4g'",b"'--memory', '8g'"))
        entry=(ROOT/'scripts/build/container-entry-v2.sh').read_text();self.assertIn('makepkg --verifysource --noconfirm',entry);self.assertIn('makepkg --cleanbuild --clean --force --log --noconfirm',entry)
        self.assertNotIn('--nodeps',entry);self.assertNotIn('--nocheck',entry)

    def test_serial_metadata_audit_projection_preserves_whole_original_audit(self):
        raw=(ROOT/'scripts/ci/native_arm.py').read_bytes();namespace=types.SimpleNamespace();projected=C.audit_adapter(namespace,raw)
        tree=ast.parse(raw);node,=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='audit'];original=ast.get_source_segment(raw.decode(),node)
        before="    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:\n        values = list(pool.map(lambda item: inspect_package(cache / item['filename'], item), inputs['packages']))"
        after="    values = [inspect_package(cache / item['filename'], item) for item in inputs['packages']]"
        self.assertEqual(projected.replace(after,before),original);self.assertTrue(callable(namespace.audit));self.assertIn('valid_signature(result.stdout',projected);self.assertIn('acquire(items, cache, out)',projected)
        with self.assertRaises(ValueError):C.audit_adapter(namespace,raw.replace(b'max_workers=4',b'max_workers=3'))

    def test_closed_plans_two_fresh_outputs_normal_offline_native_comparator(self):
        builds,compare=C.plans(Path('/Source'),Path('/Output'),'sha256:'+'1'*64)
        self.assertEqual(len(builds),2);self.assertNotEqual(builds[0][-1],builds[1][-1]);self.assertEqual(compare[-1],'--require-bytes')
        for argv in builds:
            self.assertEqual(argv[:3],['/usr/bin/python3','-I','-B'])
            for flag,value in (('--mode','native'),('--network','none'),('--timeout','300'),('--source-date-epoch','1791748800')):self.assertEqual(argv[argv.index(flag)+1],value)
            self.assertNotIn('--nodeps',argv);self.assertNotIn('--nocheck',argv);self.assertFalse(any('nested-seccomp'in v for v in argv))
        with self.assertRaises(ValueError):C.plans(Path('/S'),Path('/O'),'floating:tag')
        tree=ast.parse((HERE/'entry.py').read_text());call,=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='build']
        self.assertIsInstance(call.args[-1],ast.Dict);self.assertEqual(call.args[-1].keys,[])

    def test_Root_templates_refuse_and_live_tuple_expiry_runtime_constraints(self):
        p,a,r=selected();env=context();self.assertEqual(C.admitted(a,r,'b'*64,env,p,now=100),'c'*32)
        for bad in ('template','issuer','source','ref','map','nonce','expiry','resources','attempt','event','repository','runtime'):
            q,s,e=copy.deepcopy(a),copy.deepcopy(r),dict(env)
            if bad=='template':q=C.load(HERE/'admission.TEMPLATE.json')
            if bad=='issuer':q['issued_by']='not Root'
            if bad=='source':q['source']='f'*40
            if bad=='ref':e['GITHUB_REF']='refs/heads/other'
            if bad=='map':q['source_map_sha256']='0'*64
            if bad=='nonce':s['nonce']='e'*32
            if bad=='expiry':q['expires_utc']=100
            if bad=='resources':q['resources']['build_seconds']=301
            if bad=='attempt':e['GITHUB_RUN_ATTEMPT']='2'
            if bad=='event':e['GITHUB_EVENT_NAME']='push'
            if bad=='repository':e['GITHUB_REPOSITORY']='other/repo'
            if bad=='runtime':s['bootstrap_resource_domain']=None
            with self.subTest(bad=bad),self.assertRaises((ValueError,KeyError,AttributeError)):C.admitted(q,s,'b'*64,e,p,now=100)

    def test_unadmitted_operation_refuses_before_resources_output_or_seed(self):
        with tempfile.TemporaryDirectory()as temporary:
            source=Path(temporary)/'Source';x=P.construct(ROOT,source);out=Path(temporary)/'never-created'
            with patch.object(E,'resource_observation')as observe,self.assertRaises(ValueError):
                E.execute(source,out,x['source_map']['sha256'],C.load(HERE/'admission.TEMPLATE.json'),C.load(HERE/'runtime.TEMPLATE.json'))
            observe.assert_not_called();self.assertFalse(out.exists())

    def test_finisher_exact_two_semantic_checks_complete_comparison_and_refusals(self):
        image='sha256:'+'1'*64
        for bad in (None,'same-identity','missing-check','duplicate-marker','old-marker','BUILDINFO','archive','mode','image','inputs','inventory'):
            with self.subTest(bad=bad),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);first=root/'one';second=root/'two';review=C.load(HERE/'reviewed-inputs.json');lock=C.pin(C.read(HERE/'expected349.lock'))['sha256']
                for i,out in enumerate((first,second)):
                    (out/'artifacts').mkdir(parents=True);record=dict(status='built-package-static-pass',exit_code=0,mode='native',image_id=image,recipe_inputs=review,expected_packages_sha256=lock,clean_environment_id='one'if bad=='same-identity'else str(i))
                    if i==1:
                        if bad=='mode':record['mode']='emulated'
                        if bad=='image':record['image_id']='sha256:'+'2'*64
                        if bad=='inputs':record['recipe_inputs']={}
                        if bad=='inventory':record['expected_packages_sha256']='0'*64
                    (out/'provenance.json').write_text(json.dumps(record))
                    if not(bad=='missing-check'and i==1):(out/'artifacts/cachy-asahi-fish-config-0.1.0-2-any-check.log').write_bytes(b'OLD_CHECK'if bad=='old-marker'and i==1 else F.MARKER*(2 if bad=='duplicate-marker'and i==1 else 1))
                values=dict(installed_contents_equal=True,pkginfo_equal=True,buildinfo_equal=bad!='BUILDINFO',bytes_equal=bad!='archive');comparison=root/'compare.json';comparison.write_text(json.dumps(dict(status='contents-reproduced',errors=[],packages={'cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.zst':values})))
                if bad:
                    with self.assertRaises(ValueError):F.finish(first,second,comparison,image)
                else:self.assertEqual(F.finish(first,second,comparison,image)['status'],'FISH02_NATIVE_PAIR_AND_CHECK_POSTCONDITIONS_PASSED')

    def test_natural_outcome_refuses_signals_timeouts_group_or_output_uncertainty(self):
        row=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0,passed=True)
        E.natural(row)
        for key,value in [('signals',['SIGTERM']),('timeout',True),('group_census','UNKNOWN'),('output_complete',False),('exit',-9),('passed',False)]:
            with self.subTest(key=key),self.assertRaises(ValueError):E.natural(dict(row,**{key:value}))

    def test_retention_fixed_exclusions_complete_data_and_no_partial_success_folder(self):
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary);(out/'bootstrap/context').mkdir(parents=True);(out/'bootstrap/gpg').mkdir();(out/'bootstrap/context/private').write_bytes(b'NOT_PUBLIC');(out/'bootstrap/gpg/private').write_bytes(b'NOT_PUBLIC');(out/'report.json').write_text('{}');(out/'cleanup.json').write_text('{}');(out/'commands').mkdir();(out/'commands/000.stderr').write_bytes(b'')
            E.retain(out);manifest=C.load(out/'evidence/evidence-manifest.json');self.assertEqual(set(manifest),{'report.json','cleanup.json','commands/000.stderr'});self.assertEqual(manifest['commands/000.stderr'],C.pin(b''));self.assertFalse((out/'evidence/bootstrap/context').exists())
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary);(out/'report.json').write_text('{}');(out/'commands').mkdir();(out/'commands/unsafe').symlink_to(out/'report.json')
            with self.assertRaises(ValueError):E.retain(out)
            self.assertFalse((out/'evidence').exists())

    def test_command_supervision_clean_environment_and_private_complete_captures(self):
        events=[];child=types.SimpleNamespace(returncode=None,_child_created=True)
        def spawn(argv,**kw):
            events.append('launch');self.assertEqual(kw['env']['PATH'],'/usr/bin:/bin');self.assertNotIn('ROOT_FISH02_ADMISSION_JSON',kw['env']);self.assertTrue(kw['start_new_session'])
            with patch.object(E.resource,'setrlimit')as limits:kw['preexec_fn']()
            self.assertIn(((E.resource.RLIMIT_AS,(2*1024**3,2*1024**3)),),[(a.args,)for a in limits.call_args_list])
            kw['stdout'].write(b'COMPLETE_MODEL');return child
        def supervise(p,**kw):
            events.append('supervise');self.assertTrue(0<=kw['grace']<kw['retirement']<kw['cap']);child.returncode=0;self.assertEqual(kw['streams'],());self.assertIsNone(kw['log_fd']);return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0,passed=True)
        O=types.SimpleNamespace(prepare=lambda:events.append('prepare'),supervise=supervise)
        with tempfile.TemporaryDirectory()as temporary,patch.object(E.subprocess,'Popen',side_effect=spawn):
            out=Path(temporary);runner=E.Commands(O,out,time.monotonic()+10,time.monotonic()+90,types.SimpleNamespace(pending=[],cleaning=False));result=runner(['/MODEL/never-executed'],3)
            self.assertEqual(result.stdout,b'COMPLETE_MODEL');self.assertEqual(events,['prepare','launch','supervise']);self.assertEqual((out/'000.stdout').stat().st_mode&0o777,0o600);self.assertEqual(len(runner.rows),1)

    def test_supervisor_first_failure_reraised_with_owned_fallback_receipt(self):
        child=types.SimpleNamespace(returncode=None,_child_created=True);calls=[]
        def supervise(*args,**kwargs):
            calls.append(kwargs);self.assertTrue(0<=kwargs['grace']<kwargs['retirement']<kwargs['cap'])
            if len(calls)==1:raise ValueError('MODELED_FIRST_FAILURE')
            child.returncode=0;return dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output=b'')
        O=types.SimpleNamespace(prepare=lambda:None,supervise=supervise)
        with tempfile.TemporaryDirectory()as temporary,patch.object(E.subprocess,'Popen',return_value=child):
            out=Path(temporary);runner=E.Commands(O,out,time.monotonic()+10,time.monotonic()+90,types.SimpleNamespace(pending=[],cleaning=False))
            with self.assertRaisesRegex(ValueError,'MODELED_FIRST_FAILURE'):runner(['/MODEL/never-executed'],3)
            self.assertEqual(len(calls),2);record=C.load(out/'000.json');self.assertIsNone(record['retirement']);self.assertTrue(record['fallback_retirement']['reaped']);self.assertEqual(record['failure']['message'],'MODELED_FIRST_FAILURE')

    def test_exact_owned_builder_identity_mount_resource_and_forced_cleanup_boundaries(self):
        nonce='c'*32;name='cachy-fish02-'+nonce+'-1';image='sha256:'+'1'*64;labels={E.LABEL:nonce};out=Path('/MODEL/build-1')
        row=dict(Name='/'+name,Image=image,Config=dict(Labels=labels,User=str(os.getuid())+':'+str(os.getgid()),Entrypoint=['/bin/bash'],Cmd=['/builder-entry.sh']),HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],Privileged=False,Devices=[],DeviceRequests=None,Init=False,PidMode='',SecurityOpt=['no-new-privileges'],Memory=4*1024**3,MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'}),Mounts=[dict(Type='bind',Source=str(source),Destination=destination,RW=rw)for source,destination,rw in((out/'inputs','/inputs',False),(out/'artifacts','/out',True),(E.HERE/'runtime/scripts/build/container-entry-v2.sh','/builder-entry.sh',False),(out/'expected-packages.lock','/expected-packages.lock',False))])
        E.container_identity(row,name,image,labels,'build',out)
        for bad in('image','name','labels','root','entry','swap','RAM','CPU','PID','cap','network','mount'):
            changed=copy.deepcopy(row)
            if bad=='image':changed['Image']='sha256:'+'2'*64
            if bad=='name':changed['Name']='/foreign'
            if bad=='labels':changed['Config']['Labels']={}
            if bad=='root':changed['Config']['User']='0:0'
            if bad=='entry':changed['Config']['Cmd']=['other']
            if bad in('swap','RAM','CPU','PID'):changed['HostConfig'][{'swap':'MemorySwap','RAM':'Memory','CPU':'NanoCpus','PID':'PidsLimit'}[bad]]=0
            if bad=='cap':changed['HostConfig']['CapAdd']=['SYS_ADMIN']
            if bad=='network':changed['HostConfig']['NetworkMode']='bridge'
            if bad=='mount':changed['Mounts'][0]['RW']=True
            with self.subTest(bad=bad),self.assertRaises(ValueError):E.container_identity(changed,name,image,labels,'build',out)
        B=module('fish_scope_model',ROOT/'scripts/integration/arm16k_systemd_tcg_guest/frozen/reference_controller.py');scope=E.new_scope(B,lambda *a,**k:subprocess.CompletedProcess([],0,b'',b''),name,image,labels,'build',out)
        self.assertFalse(scope.forced_cleanup);scope.call(['docker','container','rm','--force','MODEL_CID'],time.monotonic()+8);self.assertTrue(scope.forced_cleanup)

    def test_composed_Source_models_keep_primary_failures_cleanup_and_full_check_gate(self):
        B=module('fish_model_owned_container',ROOT/'scripts/integration/arm16k_systemd_tcg_guest/frozen/reference_controller.py')
        for bad in (None,'audit','build','check-disabled','unequal-BUILDINFO','foreign-image'):
            with self.subTest(bad=bad),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);source=root/'Source';assembled=P.construct(ROOT,source);here=source/C.PREFIX;out=root/'operation';profile,a,r=selected();a['source_map_sha256']=r['source_map_sha256']=assembled['source_map']['sha256'];a['created_utc']=r['created_utc']=int(time.time())-1;a['expires_utc']=r['expires_utc']=int(time.time())+600
                image='sha256:'+'1'*64;nonce=a['nonce'];state={'image':False,'builds':0,'audit':False};calls=[]
                def image_row(cleaning=False):return dict(Id=image,Architecture='arm64',Os='linux',RepoTags=['cachy-fish02-bootstrap:'+nonce],RepoDigests=[],Config=dict(Labels={E.LABEL:'wrong'if cleaning and bad=='foreign-image'else nonce}))
                class Runner:
                    def __init__(self,O,directory,end,cleanup_end,cancellation):self.rows=[];self.cleanup_end=cleanup_end;self.state=cancellation
                    def __call__(self,argv,seconds=60,check=True,env=None):
                        calls.append(list(argv));stdout=b''
                        if argv[:2]==['/usr/bin/docker','build']:state['image']=True
                        elif argv[:3]==['/usr/bin/docker','image','inspect']:stdout=json.dumps([image_row(self.state.cleaning)]).encode()
                        elif argv[:2]==['/usr/bin/docker','run']:stdout=(here/'expected349.lock').read_bytes()
                        elif argv[:3]==['/usr/bin/docker','image','ls']:stdout=(image+'\n').encode()if state['image']else b''
                        elif argv[:3]==['/usr/bin/docker','image','rm']:state['image']=False
                        elif argv[0]=='/usr/bin/python3'and argv[3].endswith('build_fish02.py'):
                            state['builds']+=1
                            if bad=='build':raise ValueError('MODELED_BUILD_FAILURE')
                            target=Path(argv[-1]);(target/'artifacts').mkdir(parents=True)
                            record=dict(status='built-package-static-pass',exit_code=0,mode='native',image_id=image,recipe_inputs=C.load(here/'reviewed-inputs.json'),expected_packages_sha256=C.pin(C.read(here/'expected349.lock'))['sha256'],clean_environment_id='cachy-fish02-'+nonce+'-'+str(state['builds']))
                            (target/'provenance.json').write_text(json.dumps(record));(target/'artifacts/cachy-asahi-fish-config-0.1.0-2-any-check.log').write_bytes(b'check disabled'if bad=='check-disabled'else F.MARKER)
                            self_assert=env==dict(CACHY_FISH02_NONCE=nonce,CACHY_FISH02_ATTEMPT=str(state['builds']));C.need(self_assert,'modeled fixed per-attempt environment')
                        elif argv[0]=='/usr/bin/python3'and argv[3].endswith('compare_v2.py'):
                            stdout=json.dumps(dict(status='contents-reproduced',errors=[],packages={'cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.zst':dict(installed_contents_equal=True,pkginfo_equal=True,buildinfo_equal=bad!='unequal-BUILDINFO',bytes_equal=True)})).encode()
                        elif argv[:3]!=['/usr/bin/docker','container','ls']:raise AssertionError('unexpected modeled command '+str(argv))
                        self.rows.append(dict(argv=list(argv),retirement='MODEL_ONLY'));return subprocess.CompletedProcess(argv,0,stdout,b'')
                native=types.SimpleNamespace()
                def audit(inputs,cache,output):
                    state['audit']=True
                    if bad=='audit':raise ValueError('MODELED_SIGNATURE_AUDIT_FAILURE')
                def build(inputs,cache,output,reviews):
                    self.assertEqual(reviews,{});self.assertTrue(state['audit'])
                    command=['docker','build','--network=none','--pull=false','--platform=linux/arm64','--iidfile',str(output/'image-id'),str(output/'context')]
                    native.run(command,output/'bootstrap.log',1800);native.run(['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',image,'/builder-packages.lock'],timeout=60)
                    (output/'packages.lock').write_bytes((here/'expected349.lock').read_bytes());(output/'bootstrap.json').write_text(json.dumps(dict(command=command,status='image-provisioned',image_id=image)));return image
                native.audit=audit;native.build=build
                original=E.C.module
                def selected_module(path,name):
                    if name=='fish02_owned':return types.SimpleNamespace()
                    if name=='fish02_container':return B
                    if name=='fish02_seed':return types.SimpleNamespace(seed_current_build_cache=lambda *args:None)
                    if name=='fish02_native':return native
                    return original(path,name)
                previous=os.umask(0o077)
                try:
                    with patch.object(E,'HERE',here),patch.object(E.C,'module',side_effect=selected_module),patch.object(E,'Commands',Runner),patch.object(E.C,'audit_adapter'),patch.object(E,'resource_observation',return_value={'MODEL_ONLY':True}),patch.object(E.signal,'signal'),patch.object(E.signal,'setitimer'),patch.dict(os.environ,context()):
                        report=E.execute(source,out,assembled['source_map']['sha256'],a,r)
                finally:os.umask(previous)
                self.assertTrue((out/'consumed.json').is_file());self.assertTrue((out/'evidence/evidence-manifest.json').is_file(),report);self.assertTrue(all(v['owned_container_absence_verified']for v in report['cleanup']['containers']))
                if bad is None:self.assertEqual(report['status'],'PASS_CURRENT_FISH02_NATIVE_PAIR_ONLY');self.assertEqual(state['builds'],2)
                else:self.assertTrue(report['status'].startswith('HOLD'))
                if bad in('audit','build'):self.assertIn('MODELED_',report['failure']['message']);self.assertEqual(state['builds'],0 if bad=='audit'else 1)
                if bad=='foreign-image':self.assertEqual(report['natural_outcome'],'PASS_CURRENT_FISH02_NATIVE_PAIR_AND_CHECKS');self.assertTrue(state['image']);self.assertTrue(report['cleanup']['errors'])
                else:self.assertFalse(state['image'])
                self.assertIsNone(report['Root_acceptance'])

    def test_workflow_only_exact_dispatch_ordinary_host_and_inherited_secret_names(self):
        text=(ROOT/C.WORKFLOW).read_text();self.assertIn('runs-on: ubuntu-24.04-arm',text);self.assertIn('cancel-in-progress: false',text);self.assertIn('persist-credentials: false',text);self.assertIn('if: always()',text)
        self.assertEqual(text.count('secrets.CACHY_'),22);self.assertNotIn('--nodeps',text);self.assertNotIn('--nocheck',text);self.assertNotIn('sudo ',text)
        ast.parse((HERE/'entry.py').read_text());ast.parse((HERE/'prepare.py').read_text())


if __name__=='__main__':unittest.main(verbosity=2)
