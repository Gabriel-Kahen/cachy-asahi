#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA controls; no constructor, probe or full Reader invocation."""
import ast
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
NATIVE = HERE / 'payload/native'
PROFILE = json.loads((HERE / 'profile.json').read_bytes())
OPERATION = 'native-build-namespace-preflight-v1'
CASES = ('bwrap-user-mount-net','unshare-mapped-root')
MAP = 'a' * 64
TOKEN = 'b' * 24
FRAME = b'NATIVE_BUILD_NAMESPACE_V1 '
SOURCE = Path('/opt/native-' + OPERATION + '/source')
PASS = 'PASS_NAMESPACE_PREFLIGHT_NATIVE_DIAGNOSTIC'


def fence(event, args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')):
        raise AssertionError('actor denied by DATA fence: ' + event)
sys.addaudithook(fence)


def need(value, message):
    if not value: raise ValueError(message)


def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def functions(name, names, **extra):
    raw = (NATIVE / name).read_text()
    nodes = [n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in names]
    need({n.name for n in nodes} == set(names), 'all exact requested pure DATA functions')
    namespace = dict(need=need,pin=pin,data_pin=pin,Path=Path,re=re,json=json,hashlib=hashlib,math=math,
                     OPERATION=OPERATION,CASES=CASES,FRAME=FRAME,SOURCE=SOURCE,PASS=PASS)
    namespace.update(extra)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(NATIVE / name),'exec'),namespace)
    return SimpleNamespace(**namespace)


PURE = {'encoded','arguments','wrapper','namespace_context','namespace_outcome'}


def context(inner=False, case=CASES[0]):
    root = inner and case == CASES[1]
    ns = {name:name + ':[' + str(10 + i) + ']' for i,name in enumerate(('user','mnt','net','pid'))}
    if inner:
        ns['user'] = 'user:[99]'
        if not root: ns.update(mnt='mnt:[98]',net='net:[97]')
    return dict(uid=0 if root else 1000,euid=0 if root else 1000,gid=0 if root else 1000,egid=0 if root else 1000,
                groups=[1000],group_count=1,groups_complete=True,namespaces=ns,
                maps=dict(uid_map=[[0,1000,1]] if root else [[0,0,4294967295]],
                          gid_map=[[0,1000,1]] if root else [[0,0,4294967295]]),
                status={key:'0' for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters')},
                cwd='/tmp',architecture='aarch64',page_bytes=4096)


def frames(f, case, inside=True, tail=b'', change=None):
    outer = dict(schema=1,phase='exec',operation=OPERATION,case=case,source_map_sha256=MAP,token=TOKEN,
                 context=context(),argv=f.arguments(case,MAP,TOKEN),executable=dict(bytes=123,sha256='c'*64,mode=493,uid=0,gid=0))
    inner = dict(schema=1,phase='inner',operation=OPERATION,case=case,source_map_sha256=MAP,token=TOKEN,context=context(True,case))
    if change: change(outer,inner)
    return FRAME + f.encoded(outer) + (FRAME + f.encoded(inner) if inside else b'') + tail


def command(f, case, index, raw, code=0):
    return dict(step=case,argv=f.wrapper(case,MAP,TOKEN),cwd='/tmp',expected=0,success=code == 0,
                log='%03d-%s.log' % (index,case),log_pin=pin(raw),channels='stdout+stderr combined in pipe order',
                supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                                 timeout=False,signals=[],error=None,exit=code,seconds=0.2))


class View:
    def __init__(self, values):
        self.values = values
    def read(self,name): return self.values[name]
    def load(self,name): return json.loads(self.read(name))


class PreflightDataTests(unittest.TestCase):
    def setUp(self):
        self.producer = functions('build_tools_tools_v2.py',PURE)
        self.reader = functions('build_tools_reader_v2.py',PURE)

    def test_all_python_syntax_and_no_actor_imports_in_controls(self):
        for path in HERE.rglob('*.py'): ast.parse(path.read_bytes(),filename=str(path))
        for name in ('build_tools_tools_v2.py','build_tools_alpm_v2.py'):
            raw = (NATIVE/name).read_text()
            self.assertNotIn('import build_tools_reader',raw)
            self.assertNotIn('subprocess',raw)
            self.assertNotIn('ctypes',raw)

    def test_complete_reviewed_overlay_profile_and_actual_null(self):
        overlay = {p.relative_to(HERE/'payload').as_posix():dict(**pin(p.read_bytes()),mode=p.stat().st_mode & 0o777)
                   for p in (HERE/'payload').rglob('*') if p.is_file()}
        self.assertEqual(overlay,PROFILE['overlay']); self.assertEqual(len(overlay),10)
        self.assertEqual(len(PROFILE['parent_files']),200)
        self.assertEqual(PROFILE['actual'],dict(source=None,ref=None,run=None,job=None,artifact=None))
        self.assertEqual(PROFILE['operation'],OPERATION)
        raw = (HERE/'parent.raw').read_bytes()
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),PROFILE['parent'])
        self.assertEqual(raw.splitlines()[0],('tree '+PROFILE['parent_tree']).encode())

    def test_virtual_map_complete_inverse_and_git_tree(self):
        rows = {**PROFILE['parent_files'],**PROFILE['overlay']}
        mapping = json.loads((HERE/'parent-map.json').read_bytes())
        mapping['namespace_preflight_operation'] = OPERATION
        mapping['files'] = {n:r for n,r in rows.items() if n != 'native/source-map.json'}
        raw = (json.dumps(mapping,sort_keys=True,indent=2)+'\n').encode()
        self.assertEqual(pin(raw)['sha256'],PROFILE['map_sha256']); self.assertEqual(len(mapping['files']),199)
        blobs = dict(PROFILE['parent_blobs'])
        for name in PROFILE['overlay']:
            body = (HERE/'payload'/name).read_bytes()
            blobs[name] = hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
        blobs['native/source-map.json'] = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        tree = {}
        for name,row in rows.items():
            node = tree
            for part in name.split('/')[:-1]: node = node.setdefault(part,{})
            node[name.split('/')[-1]] = (row['mode'],bytes.fromhex(blobs[name]))
        def git_tree(node):
            raw = b''
            for name,value in sorted(node.items(),key=lambda r:r[0].encode()+(b'/' if type(r[1]) is dict else b'')):
                raw += (b'40000' if type(value) is dict else b'100755' if value[0] == 493 else b'100644')+b' '+name.encode()+b'\0'+(git_tree(value) if type(value) is dict else value[1])
            return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
        self.assertEqual(git_tree(tree).hex(),PROFILE['prospective_tree'])
        inverse = dict(rows)
        for name in {*PROFILE['overlay'],'native/source-map.json'}: inverse[name] = PROFILE['parent_files'][name]
        self.assertEqual(inverse,PROFILE['parent_files'])

    def test_constructor_requires_external_profile_and_does_not_run(self):
        raw = (HERE/'prepare.py').read_text();tree = ast.parse(raw)
        allowed = next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ALLOWED' for t in n.targets))
        names = ast.literal_eval(allowed.value.args[0]);self.assertEqual(set(names),set(PROFILE['overlay']))
        namespace = dict(need=need,pin=pin,re=re,decode=json.loads,MAX_FILE=64*1024**2,MAX_TOTAL=128*1024**2,
                         PARENT=PROFILE['parent'],PARENT_TREE=PROFILE['parent_tree'],OPERATION=OPERATION,
                         ALLOWED=frozenset(names),MAP='native/source-map.json',relative=lambda n:Path(n))
        node = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='profile')
        exec(compile(ast.Module(body=[node],type_ignores=[]),'profile DATA','exec'),namespace)
        body = (HERE/'profile.json').read_bytes()
        self.assertEqual(namespace['profile'](body,pin(body)['sha256']),PROFILE)
        with self.assertRaises(ValueError): namespace['profile'](body,'0'*64)
        self.assertNotIn('setup8',raw.lower())

    def test_owner_security_cleanup_and_workflow_inverse_held(self):
        prior = HERE.parent/'first-login-enrollment-native-source/payload'
        old = (prior/'native/owner.py').read_text()
        expected = old.replace('first-login-enrollment-alpm-v1',OPERATION).replace('PASS_FIRST_LOGIN_ENROLLMENT_NATIVE_ALPM_COMPONENT',PASS)
        expected = expected.replace('prepare(root,context,args.map_sha256);dockerfile=release_dockerfile(dockerfile,args.map_sha256)',
                                    'prepare(root,context,args.map_sha256,own);dockerfile=release_dockerfile(dockerfile,args.map_sha256,own)')
        self.assertEqual((NATIVE/'owner.py').read_text(),expected)
        for name in ('native-arm-build.yml','native-arm-developer-workflows.yml'):
            self.assertEqual((HERE/'payload/.github/workflows'/name).read_text(),
                             (prior/'.github/workflows'/name).read_text().replace('first-login-enrollment-alpm-v1',OPERATION))
        invocation = json.loads((NATIVE/'invocation.json').read_bytes())
        self.assertEqual(invocation['resource_class'],'HEAVY_NON_KERNEL')
        self.assertEqual(invocation['concurrency_group'],'native-arm-build')

    def test_exact_normal_image_run_dockerfile_independent_join(self):
        reader = functions('build_tools_reader_v2.py',{'namespace_dockerfile'})
        expected = reader.namespace_dockerfile('native-developer-base:'+TOKEN,MAP,TOKEN)
        start = expected.index(b'COPY '+OPERATION.encode()+b'/source/')
        base = expected[:start].decode()+'USER alarm\nWORKDIR /tmp\n'
        producer = functions('build_tools_alpm_v2.py',{'dockerfile'},T=self.producer,STORE=SOURCE.parent/'evidence')
        self.assertEqual(producer.dockerfile(base,MAP,dict(token=TOKEN)).encode(),expected)
        run = expected.split(b'USER alarm\nWORKDIR /tmp\n')[1]
        self.assertTrue(run.startswith(b'RUN ["/usr/bin/bash", "--noprofile", "--norc", "-p"'))
        self.assertNotIn(b'USER root',run);self.assertNotIn(b'pacman',run)
        with self.assertRaises(ValueError): producer.dockerfile(base+'RUN injected\n',MAP,dict(token=TOKEN))

    def test_both_exact_supported_effects_independently_recomputed(self):
        for case in CASES:
            raw = frames(self.producer,case)
            actual = self.producer.namespace_outcome(raw,0,case,MAP,TOKEN)
            self.assertEqual(actual,self.reader.namespace_outcome(raw,0,case,MAP,TOKEN))
            self.assertEqual(actual['outcome'],'SUPPORTED')
            self.assertEqual(actual['policy_cause'],'UNKNOWN')

    def test_denied_exit_is_valid_data_and_does_not_infer_errno(self):
        for case,tail in zip(CASES,(b'bwrap: No permissions to create a new namespace\n',b'unshare: unshare failed: Operation not permitted\n')):
            raw = frames(self.producer,case,False,tail)
            result = self.reader.namespace_outcome(raw,1,case,MAP,TOKEN)
            self.assertEqual(result['outcome'],'DENIED');self.assertEqual(result['namespace_errno'],'UNKNOWN')
            self.assertEqual(result,self.producer.namespace_outcome(raw,1,case,MAP,TOKEN))

    def test_unrecognized_nonzero_and_absent_frames_stay_unknown(self):
        for raw in (b'not a namespace result\n',frames(self.producer,CASES[0],False,b'bwrap: other failure\n')):
            self.assertEqual(self.reader.namespace_outcome(raw,1,CASES[0],MAP,TOKEN)['outcome'],'UNKNOWN')

    def test_zero_without_inner_or_extra_output_cannot_establish_support(self):
        for raw in (frames(self.producer,CASES[0],False),frames(self.producer,CASES[0],True,b'extra output\n')):
            self.assertEqual(self.reader.namespace_outcome(raw,0,CASES[0],MAP,TOKEN)['outcome'],'UNKNOWN')

    def test_missing_metadata_is_unknown_not_disabled_or_supported(self):
        raw = frames(self.producer,CASES[0],change=lambda a,b:b['context']['namespaces'].update(net=None))
        self.assertEqual(self.reader.namespace_outcome(raw,0,CASES[0],MAP,TOKEN)['outcome'],'UNKNOWN')

    def test_wrong_namespace_effects_and_mapped_root_refuse_support(self):
        changes = (lambda a,b:b['context']['namespaces'].update(user=a['context']['namespaces']['user']),
                   lambda a,b:b['context']['maps'].update(uid_map=[[0,2000,1]]),
                   lambda a,b:b['context'].update(euid=1000))
        for change in changes:
            raw = frames(self.producer,CASES[1],change=change)
            self.assertEqual(self.reader.namespace_outcome(raw,0,CASES[1],MAP,TOKEN)['outcome'],'UNKNOWN')

    def test_wrong_nonce_map_or_argv_is_refused(self):
        for change in (lambda a,b:a.update(token='d'*24),lambda a,b:b.update(source_map_sha256='d'*64),
                       lambda a,b:a['argv'].append('--privileged')):
            with self.assertRaises(ValueError):
                self.reader.namespace_outcome(frames(self.producer,CASES[0],change=change),0,CASES[0],MAP,TOKEN)

    def test_noncanonical_duplicate_and_bool_context_is_refused(self):
        raw = frames(self.producer,CASES[0])
        for broken in (raw.replace(b'"schema":1',b'"schema":1,"schema":1',1),
                       raw.replace(b'"schema":1',b'"schema": 1',1),
                       frames(self.producer,CASES[0],change=lambda a,b:b['context'].update(uid=True))):
            with self.assertRaises(ValueError): self.reader.namespace_outcome(broken,0,CASES[0],MAP,TOKEN)

    def test_unknown_or_setuid_binary_never_establishes_support(self):
        for change in (lambda a,b:a.update(executable=None),lambda a,b:a['executable'].update(mode=2541)):
            raw = frames(self.producer,CASES[0],change=change)
            self.assertEqual(self.reader.namespace_outcome(raw,0,CASES[0],MAP,TOKEN)['outcome'],'UNKNOWN')

    def test_exec_failure_permission_is_unknown_not_namespace_denial(self):
        raw = frames(self.producer,CASES[0],False)
        raw += FRAME+self.producer.encoded(dict(schema=1,phase='exec-error',case=CASES[0],source_map_sha256=MAP,token=TOKEN,errno=13))
        self.assertEqual(self.reader.namespace_outcome(raw,126,CASES[0],MAP,TOKEN)['reason'],'EXEC_FAILED_NOT_NAMESPACE_RESULT')

    def modeled_commands(self):
        raws = [frames(self.producer,CASES[0],False,b'bwrap: No permissions to create a new namespace\n'),frames(self.producer,CASES[1])]
        rows = [command(self.producer,case,index,raw,1 if index == 0 else 0) for index,(case,raw) in enumerate(zip(CASES,raws))]
        prefix = 'journey/'+OPERATION+'/'
        values = {prefix+r['log']:raw for r,raw in zip(rows,raws)}
        values[prefix+'commands.json'] = json.dumps(rows).encode()
        files = {n:dict(kind='file',**pin(raw)) for n,raw in values.items()}
        f = functions('build_tools_reader_v2.py',PURE|{'namespace_commands'})
        return f,rows,View(values),files

    def test_complete_denied_command_has_real_false_success_and_retirement(self):
        f,rows,view,files = self.modeled_commands()
        result = f.namespace_commands(view,files,dict(commands=rows),MAP,TOKEN,True)
        self.assertEqual([result[x]['outcome'] for x in CASES],['DENIED','SUPPORTED'])

    def test_unreaped_timeout_partial_or_bad_clock_never_becomes_denied(self):
        for key,value in (('reaped',False),('group_census','UNKNOWN'),('output_complete',False),('timeout',True),('seconds',float('nan')),('seconds',20)):
            f,rows,view,files = self.modeled_commands();rows[0]['supervision'][key] = value
            view.values['journey/'+OPERATION+'/commands.json'] = json.dumps(rows).encode()
            with self.assertRaises(ValueError): f.namespace_commands(view,files,dict(commands=rows),MAP,TOKEN,True)

    def test_changed_command_or_log_body_or_success_is_refused(self):
        for change in (lambda r:r[0]['argv'].append('injected'),lambda r:r[0].update(success=True),lambda r:r[0].update(expected='nonzero')):
            f,rows,view,files = self.modeled_commands();change(rows)
            view.values['journey/'+OPERATION+'/commands.json'] = json.dumps(rows).encode()
            with self.assertRaises(ValueError): f.namespace_commands(view,files,dict(commands=rows),MAP,TOKEN,True)
        f,rows,view,files = self.modeled_commands();view.values['journey/'+OPERATION+'/'+rows[0]['log']] += b'tampered'
        with self.assertRaises(ValueError): f.namespace_commands(view,files,dict(commands=rows),MAP,TOKEN,True)

    def test_held_privacy_predicate_exact_and_no_archive_exception(self):
        old = HERE.parent/'first-login-enrollment-native-source/payload/native'
        def marker(path):
            tree = ast.parse(path.read_bytes())
            return ast.dump(next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PRIVATE_MARKER' for t in n.targets)))
        self.assertEqual(marker(NATIVE/'build_tools_projection_v2.py'),marker(old/'build_tools_projection_v2.py'))
        source = (NATIVE/'build_tools_projection_v2.py').read_text()
        self.assertNotIn('def archive_custody',source)
        self.assertIn('if PRIVATE_MARKER.search(raw):',source)

    def component_data(self):
        f,rows,view,files = self.modeled_commands()
        outcomes = f.namespace_commands(view,files,dict(commands=rows),MAP,TOKEN,True)
        baseline = dict(bytes=6800,sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
        report = dict(schema_version=1,operation=OPERATION,status=PASS,source_map_sha256=MAP,token=TOKEN,
                      baseline=baseline,execution='NORMAL_DOCKER_IMAGE_BUILD_RUN_USER_ALARM',commands=rows,outcomes=outcomes,
                      process_layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=7,python_ppid=1,
                                          status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'),first_failure=None,cleanup=dict(home_absent=True),
                      package_build='NOT_RUN',package_install='NOT_RUN',services='NOT_RUN',GUI='NOT_RUN',physical_M2='NOT_RUN',
                      namespace_policy_cause='UNKNOWN',Doc315='NOT_ESTABLISHED',native_acceptance='NOT_ADMITTED',release='NOT_ADMITTED')
        guest = dict(status=PASS,packages=baseline,build_tools_alpm=report)
        binding = dict(source='1'*40,ref='refs/heads/codex/MODELED',run='123',attempt=1,token=TOKEN)
        g = functions('build_tools_reader_v2.py',PURE|{'namespace_commands','namespace_dockerfile','retained_build_tools_alpm',
                                                     'build_tools_positive_state','build_tools_process_layout'})
        dockerfile = g.namespace_dockerfile('native-developer-base:'+TOKEN,MAP,TOKEN)
        argv = ['/usr/bin/docker','--host=unix:///var/run/docker.sock','build','--quiet','--network=none','--pull=false','--no-cache',
                '--platform=linux/arm64','--tag','native-developer-tools:'+TOKEN,'--label','org.cachy-asahi.native-developer='+TOKEN,
                '--label','org.cachy-asahi.native-developer.source='+binding['source'],'--iidfile','/MODELED/overlay/image-id','/MODELED/overlay/context']
        view.values.update({'journey/'+OPERATION+'/result.json':json.dumps(report).encode(),
                            'bootstrap-proof/overlay-Dockerfile':dockerfile,
                            'cleanup.json':json.dumps(dict(build_operations=[dict(role='tools',terminal=True,actor=dict(argv=argv))])).encode(),
                            'receipt.json':json.dumps(dict(output_root='/MODELED/public')).encode()})
        return g,report,guest,binding,view,files

    def test_independent_component_joins_denied_data_not_native_acceptance(self):
        f,report,guest,binding,view,files = self.component_data()
        result = f.retained_build_tools_alpm(view,files,guest,MAP,binding)
        self.assertFalse(result['requested_effects_observed'])
        self.assertEqual(result['outcomes'][CASES[0]]['outcome'],'DENIED')
        self.assertEqual(result['Doc315'],'NOT_ESTABLISHED')
        self.assertEqual(result['native'],'NOT_ADMITTED')

    def test_component_refuses_claimed_support_cleanup_or_different_run_context(self):
        for change in (lambda r:r['outcomes'][CASES[0]].update(outcome='SUPPORTED'),
                       lambda r:r.update(cleanup=dict(home_absent=False)),lambda r:r.update(token='c'*24),
                       lambda r:r.update(execution='CONSUMER_CONTAINER'),lambda r:r.update(package_install='PASS'),
                       lambda r:r.update(Doc315='PASS')):
            f,report,guest,binding,view,files = self.component_data();change(report)
            view.values['journey/'+OPERATION+'/result.json'] = json.dumps(report).encode()
            with self.assertRaises(ValueError): f.retained_build_tools_alpm(view,files,guest,MAP,binding)

    def test_component_refuses_changed_dockerfile_and_security_option(self):
        f,report,guest,binding,view,files = self.component_data()
        view.values['bootstrap-proof/overlay-Dockerfile'] = view.values['bootstrap-proof/overlay-Dockerfile'].replace(b'USER alarm',b'USER root')
        with self.assertRaises(ValueError): f.retained_build_tools_alpm(view,files,guest,MAP,binding)
        f,report,guest,binding,view,files = self.component_data()
        cleanup = view.load('cleanup.json');cleanup['build_operations'][0]['actor']['argv'].insert(4,'--security-opt=seccomp=unconfined')
        view.values['cleanup.json'] = json.dumps(cleanup).encode()
        with self.assertRaises(ValueError): f.retained_build_tools_alpm(view,files,guest,MAP,binding)

    def projection_data(self):
        f,report,guest,binding,view,files = self.component_data()
        prefix = 'journey/'+OPERATION+'/'
        values = {name:raw for name,raw in view.values.items() if name.startswith(prefix)}
        values['journey/result.json'] = json.dumps(guest).encode()
        values['receipt.json'] = json.dumps(dict(binding=binding,source_map_sha256=MAP)).encode()
        selected = {name:dict(kind='file',mode=384,source_mode=420,**pin(raw)) for name,raw in values.items()}
        producers = {name:row['sha256'] for name,row in PROFILE['overlay'].items() if name in
                     {'native/build_tools_alpm_v2.py','native/build_tools_tools_v2.py','native/build_tools_guest_v2.py','native/build-tools-contract-v2.json'}}
        projection = dict(schema=1,status='PASS_FINITE_NAMESPACE_PREFLIGHT_PUBLIC_DATA_PROJECTION',binding=binding,
                          source_map_sha256=MAP,source_producers=producers,selected=selected,
                          omitted_private_scopes=[prefix+'home'],original_output_unchanged=True,omitted_private_trees_walked=False,
                          privacy='Ordinary DATA marker refusal; no binary or archive exceptions',archive_custody={},
                          scope='Fixed native-build-namespace-preflight-v1 result, commands and raw referenced logs only; private home trees not retained')
        values['public-projection.json'] = json.dumps(projection).encode()
        files = {name:dict(kind='file',mode=384,**pin(raw)) for name,raw in values.items()}
        f = functions('build_tools_reader_v2.py',{'retained_public_projection'},PRODUCERS=producers)
        return f,View(values),files,projection,binding

    def test_projection_independently_joins_every_original_namespace_log(self):
        f,view,files,projection,binding = self.projection_data()
        result = f.retained_public_projection(view,files,binding,MAP)
        self.assertEqual(result['selected'],len(files)-1)
        name = 'journey/'+OPERATION+'/000-'+CASES[0]+'.log'
        view.values[name] += b'extra'
        with self.assertRaises(ValueError): f.retained_public_projection(view,files,binding,MAP)

    def test_projection_refuses_extra_leaf_private_bytes_and_walked_home(self):
        for mode in ('extra','private','walked'):
            f,view,files,p,binding = self.projection_data()
            if mode == 'walked': p['omitted_private_trees_walked'] = True
            else:
                name = 'unknown-root.json' if mode == 'extra' else 'receipt.json'
                raw = b'{}' if mode == 'extra' else b'PRIVATE_KEY=modeled'
                view.values[name] = raw;files[name] = dict(kind='file',mode=384,**pin(raw))
                p['selected'][name] = dict(kind='file',mode=384,source_mode=420,**pin(raw))
            view.values['public-projection.json'] = json.dumps(p).encode()
            files['public-projection.json'] = dict(kind='file',mode=384,**pin(view.values['public-projection.json']))
            with self.assertRaises(ValueError): f.retained_public_projection(view,files,binding,MAP)

    def test_role_specific_held_source36_quiet_image_argv(self):
        source = (NATIVE/'build_tools_reader_v2.py').read_text()
        node = next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='retained_image_lifecycle')
        raw = ast.get_source_segment(source,node)
        self.assertIn("len(argv) == (16 if role == 'base' else 17)",raw)
        self.assertIn("docker + ['build', '--quiet', '--network=none'",raw)

    def test_null_reader_ingress_refuses_before_capsule_or_source_access(self):
        called = []
        def forbidden(*args,**kwargs): called.append(args);raise AssertionError('forbidden ingress')
        f = functions('build_tools_reader_v2.py',{'validate'},build_tools_local_binding=forbidden,open_capsule=forbidden)
        with self.assertRaises(ValueError): f.validate(Path('/DOES-NOT-EXIST'),dict(source=None,ref=None,run=None,map_sha256=None))
        self.assertEqual(called,[])


if __name__ == '__main__': unittest.main()
