#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-denied constructor, package and passive-reader DATA controls."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import sys
import tarfile
import unittest

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
N=HERE/'payload/native'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(path):return json.loads(Path(path).read_bytes())
def need(ok,why):
    if not ok:raise ValueError(why)
def function(path,name,extra=None):
    tree=ast.parse(Path(path).read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
    scope=dict(need=need,re=re,json=json,Path=Path,pin=pin,**(extra or {}));exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),scope);return scope[name]
B=runpy.run_path(str(HERE/'data_helpers.py'))
P=runpy.run_path(str(HERE/'prepare.py'))
T=runpy.run_path(str(N/'developer_tools_tools_v1.py'))
D=runpy.run_path(str(N/'developer_tools_probe_v1.py'))
CONTRACT=load(N/'developer-tools-contract-v1.json')
PROFILE=load(HERE/'profile.json')
CHECK=function(N/'developer_tools_alpm_v1.py','check_result')
READCHECK=function(N/'developer_tools_reader_v1.py','developer_tools_check_result')
BLOCKED=('subprocess.Popen','os.system','os.exec','os.spawn','os.fork','os.posix_spawn','socket.connect','socket.bind','ctypes.dlopen','ctypes.dlsym')
def audit(event,args):
    if any(event==p or event.startswith(p+'.')for p in BLOCKED):raise AssertionError('Actor denied by DATA control: '+event)
sys.addaudithook(audit)

def modeled_check(names=None):
    names=names or CONTRACT['recipe']['expected_tests']
    return ('==> Starting check()\n'+''.join(n+' (__main__.PackageTests.'+n+') ... ok\n'for n in names)+'\n----------------------------------------------------------------------\nRan 13 tests in 0.123s\n\nOK\n').encode()

def object_tree(rows):
    nodes={}
    for name,row in rows.items():
        target=nodes
        for part in Path(name).parts[:-1]:target=target.setdefault(part,{})
        target[Path(name).name]=(row['mode'],row['blob'])
    def branch(node):
        body=b''
        for name,value in sorted(node.items(),key=lambda r:r[0].encode()+(b'/'if type(r[1])is dict else b'')):
            mode,digest=(b'40000',branch(value))if type(value)is dict else(b'100755'if value[0]==0o755 else b'100644',bytes.fromhex(value[1]))
            body+=mode+b' '+name.encode()+b'\0'+digest
        return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).digest()
    return branch(nodes).hex()

class DataTests(unittest.TestCase):
    def test01_original_package_bytes_and_thirteen_controls_held(self):
        package=REPO/'packages/tools/cachy-asahi-developer-tools';source=package/'cachy-asahi-developer-tools-0.1.0'
        for name,row in CONTRACT['recipe']['source_files'].items():self.assertEqual(pin((package/name).read_bytes()),{k:row[k]for k in('bytes','sha256')})
        self.assertEqual(CONTRACT['package_origin']['source_archive'],dict(bytes=42901,sha256='767ac7a1e98b35f212247ed906434c11c197ad5640ad3a13601d433c84d756c2'))
        tests=sorted(n.name for n in ast.walk(ast.parse((source/'test_package.py').read_bytes()))if isinstance(n,ast.FunctionDef)and n.name.startswith('test_'))
        self.assertEqual(tests,CONTRACT['recipe']['expected_tests']);self.assertEqual(len(tests),13)
    def test02_exact_source_bundle_and_tamper_refusal(self):
        members=T['recipe_members'](HERE/'payload',CONTRACT);self.assertEqual(len(members),2)
        with tarfile.open(fileobj=io.BytesIO((N/'developer-tools-sources-v1.tar').read_bytes()),mode='r:')as a:self.assertEqual(sorted(a.getnames()),sorted(members))
        bad=copy.deepcopy(CONTRACT);bad['bundle']['sha256']='0'*64
        with self.assertRaises(ValueError):T['recipe_members'](HERE/'payload',bad)
    def test03_all34_payloads_and_owned_runtime_held(self):
        p=REPO/'packages/tools/cachy-asahi-developer-tools/cachy-asahi-developer-tools-0.1.0/payload'
        rows=CONTRACT['recipe']['payload_files'];self.assertEqual(len(rows),34)
        for name,row in rows.items():self.assertEqual(pin((p/name.removeprefix('usr/')).read_bytes()),{k:row[k]for k in('bytes','sha256')})
        self.assertIn('usr/lib/cachy-asahi-developer-tools/0.1.0/scripts/virtual/owned_process.py',rows)
    def test04_closed200_map_and_complete_overlay(self):
        overlay=B['snapshot'](HERE/'payload');self.assertEqual(B['descriptors'](overlay),PROFILE['overlay'])
        manifest=load(N/'source-map.json');self.assertEqual(len(manifest['files']),199);self.assertNotIn('native/source-map.json',manifest['files']);self.assertEqual(manifest['actual'],dict(source=None,ref=None,run=None))
        for name,(raw,mode)in overlay.items():
            if name!='native/source-map.json':self.assertEqual(manifest['files'][name],dict(pin(raw),mode=mode))
        self.assertEqual(pin((N/'source-map.json').read_bytes()),PROFILE['source_map'])
    def test05_virtual_git_parent_and_final_tree(self):
        rows=load(HERE/'parent-git-objects.json');self.assertEqual(len(rows),200);self.assertEqual(object_tree(rows),PROFILE['parent_tree'])
        original=dict(rows)
        for name in PROFILE['removed']:rows.pop(name)
        for name,(body,mode)in B['snapshot'](HERE/'payload').items():rows[name]=dict(mode=mode,blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest())
        self.assertEqual(len(rows),200);self.assertEqual(object_tree(rows),PROFILE['source_tree'])
        for name in set(rows)-original.keys():rows.pop(name)
        for name in PROFILE['overlay'].keys()&original.keys()|set(PROFILE['removed']):rows[name]=original[name]
        self.assertEqual(rows,original)
    def test06_profile_nulls_checksum_and_raw_parent(self):
        raw=(HERE/'profile.json').read_bytes();self.assertEqual(P['policy'](raw,pin(raw)['sha256']),PROFILE)
        for key in('source','run','ref'):
            bad=copy.deepcopy(PROFILE);bad['actual'][key]='not-null';body=json.dumps(bad).encode()
            with self.assertRaises(ValueError):P['policy'](body,pin(body)['sha256'])
        with self.assertRaises(ValueError):P['policy'](raw,'0'*64)
        commit=(HERE/'parent.raw-commit').read_bytes();self.assertEqual(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest(),PROFILE['parent_source'])
    def test07_five_git_rows_are_exact_frozen574(self):
        frozen=load(REPO/'scripts/ci/maintained-desktop574-inputs.json');rows=CONTRACT['git_delta']['rows'];names={r['name']for r in rows}
        self.assertEqual(names,{'git','perl-error','perl-mailtools','perl-timedate','zlib-ng'})
        self.assertEqual(rows,sorted([r for r in frozen['packages']if r['name']in names],key=lambda r:r['name']))
        for r in rows:
            self.assertRegex(r['sha256'],'^[0-9a-f]{64}$');self.assertRegex(r['signature_sha256'],'^[0-9a-f]{64}$');self.assertEqual(r['signature_size'],566);self.assertTrue(r['url'].endswith(r['filename']))
    def test08_explicit354_preserves_all349_versions_and_arches(self):
        old=load(REPO/'scripts/ci/build-tools-v2-native-source/overlay/native/build-tools-contract-v2.json')['buildinfo_installed'];new=CONTRACT['buildinfo_installed']
        self.assertEqual(len(old),349);self.assertEqual(len(new),354);self.assertLessEqual(set(old),set(new))
        rows=load(N/'input-profile.json')['additions']['rows'];self.assertEqual(len(rows),13)
        baseline=dict(l.split(' ',1)for l in(N/'expected354.lock').read_text().splitlines());self.assertEqual(len(baseline),354)
        self.assertEqual(CONTRACT['invocation']['inventory_counts'],[354,355,354]);self.assertEqual(CONTRACT['git_delta']['original_count'],349)
        for edge in CONTRACT['git_delta']['edges']:self.assertEqual(baseline[edge['provider']],edge['version']);self.assertEqual(edge['kind'],'EXACT_NAME_UNVERSIONED')
    def test09_normal_signed_alpm_solver_and13_signature_additions(self):
        owner=(N/'owner.py').read_text();self.assertIn("native.audit(combined, args.cache, overlay) == 261",owner)
        install=owner[owner.index("dockerfile = ("):owner.index("if operation==",owner.index("dockerfile = ("))]
        self.assertIn('pacman -U --noconfirm --noscriptlet',install)
        self.assertNotIn("'--nodeps'",(N/'developer_tools_alpm_v1.py').read_text());self.assertNotIn("'--nocheck'",(N/'developer_tools_alpm_v1.py').read_text())
        for flag in('--nodeps','--assume-installed','--overwrite'):self.assertNotIn(flag,install)
        provision=(N/'provision.py').read_text();self.assertIn('len(rows) == 26',provision);self.assertIn('PASS_THIRTEEN_INPUT_CACHE_DATA_ONLY',provision)
        bootstrap=(N/'bootstrap_inputs.py').read_text();self.assertIn('len(package_rows) == 522',bootstrap)
    def test10_exact13_check_log_producer_and_reader_agree(self):
        raw=modeled_check();self.assertEqual(CHECK(raw),READCHECK(raw));self.assertEqual(CHECK(raw)['tests'],13)
        for bad in(raw.replace(b'Ran 13 tests',b'Ran 12 tests'),raw.replace(b'OK',b'FAILED (errors=1)'),raw.replace(b'... ok',b'... skipped',1),raw+raw,raw.replace(b'Starting check()',b'check disabled'),raw.replace(b'\n',b'\\n')):
            with self.assertRaises(ValueError):CHECK(bad)
            with self.assertRaises(ValueError):READCHECK(bad)
    def test11_pid1_layout_and_unknown_daemon_policy_held(self):
        docker=function(N/'developer_tools_alpm_v1.py','dockerfile');body=docker('FROM example\nUSER alarm\nWORKDIR /tmp\n','f'*64)
        self.assertIn('"/usr/bin/bash", "--noprofile", "--norc", "-p", "-c"',body);self.assertIn('BASHPID',body);self.assertIn('wait \\"$developer_tools_owner\\"',body)
        fn=function(N/'developer_tools_reader_v1.py','developer_tools_process_layout')
        good=dict(process_layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=2,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'))
        fn(good)
        bad=copy.deepcopy(good);bad['process_layout']['python_pid']=1
        with self.assertRaises(ValueError):fn(bad)
        self.assertEqual(CONTRACT['journey_policy']['daemon_build_policy'],'UNKNOWN')
    def test12_fixed_seven_cli_requests_and_frozen_uv(self):
        rows=D['requests']('/usr/bin/cachy-asahi-developer-tools',Path('/private/system'),CONTRACT);self.assertEqual([k for k,a in rows],list(D['STEPS']))
        self.assertEqual(len(rows),7);self.assertEqual(rows[-1][1][-4:],['--python','/usr/bin/python3','--uv','/opt/native-developer-tools/uv'])
        self.assertNotIn('--uv',rows[-2][1]);self.assertEqual(CONTRACT['journey_policy']['uv_pin']['sha256'],'b9f74e398b6b15826a4b68b5a83d039036d47df64013e7faf1a9974ec199c144')
    def test13_nested_supervision_missing_raw_logs_and_unknown_retirement_refuse(self):
        raw=b'observed';row=dict(argv=['/tool'],expected=0,success=True,log='000-example.log',log_pin=pin(raw),supervision=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[]))
        self.assertEqual(D['supervision'](row,{'000-example.log':raw}),raw)
        for field,value in(('reaped',False),('ownership','UNKNOWN'),('group_census','EMPTY_ONCE'),('output_complete',False),('timeout',True),('signals',[15])):
            bad=copy.deepcopy(row);bad['supervision'][field]=value
            with self.assertRaises(ValueError):D['supervision'](bad,{'000-example.log':raw})
        with self.assertRaises(ValueError):D['supervision'](row,{})
    def test14_reader_binding_precedes_ingress_and_probe_import(self):
        s=(N/'developer_tools_reader_v1.py').read_text();tree=ast.parse(s);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');body=ast.get_source_segment(s,fn)
        self.assertLess(body.index('developer_tools_local_binding'),body.index('open_capsule'))
        local=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='developer_tools_local_binding');self.assertIn('matching reader self',ast.get_source_segment(s,local))
        self.assertFalse(any(isinstance(n,ast.Import)and any(a.name=='developer_tools_probe_v1'for a in n.names)for n in tree.body))
    def test15_raw_nested_evidence_is_projected_and_exported(self):
        producer=(N/'developer_tools_alpm_v1.py').read_text();projection=(N/'developer_tools_projection_v1.py').read_text();reader=(N/'developer_tools_reader_v1.py').read_text()
        self.assertIn("for row in report.get('journey_logs',[])",producer);self.assertIn("commands+report.get('journey_logs',[])",projection);self.assertIn("commands+report.get('journey_logs',[])",reader)
        self.assertIn("B.validate_journey(key,result,decoded,contract)",reader)
    def test16_exact_producer_pins_and_all_source_python_parse(self):
        tree=ast.parse((N/'developer_tools_reader_v1.py').read_bytes());value=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRODUCERS'for t in n.targets))
        for name,digest in value.items():self.assertEqual(pin((HERE/'payload'/name).read_bytes())['sha256'],digest)
        for p in HERE.rglob('*.py'):ast.parse(p.read_bytes())
    def test17_consumer_probe_and_command_caps_held(self):
        r=CONTRACT['resources'];self.assertEqual(r['consumer']['cpu'],2);self.assertEqual(r['consumer']['memory_bytes'],4*1024**3);self.assertEqual(r['consumer']['pids'],256)
        self.assertEqual(r['commands']['one_seconds'],180);self.assertEqual(r['commands']['windows_seconds'],[450,450,450]);self.assertEqual(r['commands']['allocation_including_cleanup_seconds'],1440);self.assertEqual(r['commands']['cleanup_whole_seconds'],90);self.assertEqual(r['commands']['overall_monotonic_seconds'],1440)
        producer=(N/'developer_tools_alpm_v1.py').read_text();self.assertIn('operation_deadline=operation_started+1440',producer);self.assertIn('replacement.deadline=min(replacement.deadline,operation_deadline-90)',producer);self.assertIn('cleanup_commands.deadline=min(cleanup_commands.deadline,operation_deadline)',producer)
        workflow=(HERE/'payload/.github/workflows/native-arm-build.yml').read_text();self.assertIn('group: native-arm-build\n  cancel-in-progress: false\n  queue: max',workflow);self.assertIn('ubuntu-24.04-arm',workflow);self.assertIn('timeout-minutes: 135',workflow)

if __name__=='__main__':unittest.main(verbosity=2)
