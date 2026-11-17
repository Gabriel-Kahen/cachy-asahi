# SPDX-License-Identifier: MIT
"""Fenced DATA-only Source50 construction, inverse and runtime admission controls."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import ModuleType
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name):
    path=HERE/(name+'.py');m=ModuleType(name);m.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m

C=load('prepare');D=load('data');X=load('host_context');BASE=None

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.fork','os.exec','os.posix_spawn','fcntl.flock'):
        raise AssertionError('FENCED no actors, network, host repair or custody entry')
sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='FENCED-fish50-DATA-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)

    def build(self):
        output=self.root/'source';receipt=C.construct(BASE,output)
        return output,receipt

    def policy(self):return D.decode((HERE/'policy.json').read_bytes())

    def environment(self):
        return dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',
                    GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='12345',GITHUB_SHA='a'*40,
                    GITHUB_REF='refs/heads/codex/fish02-no-host-apt-v4-source-fenced',GITHUB_JOB='pair')

    def limits(self,p):
        return {'memory.max':str(p['memory_bytes']),'memory.swap.max':'0','pids.max':str(p['pids']),
                'cpu.max':str(p['cpus']*100000)+' 100000'}

    def host(self):
        context=X.context(self.environment(),'aarch64',b'ID=ubuntu\nVERSION_ID="24.04"\n',0)
        return dict(status='PASS_EXISTING_HOST_TOOLS_ONLY',declaration=self.policy()['host_tools'],commands=[],
                    package_manager_invocations=0,host_package_mutations=0,tools=sorted(D.HOST_NAMES),context=context)

    def repin(self,root):
        """Re-seal changed test DATA so negative controls reach semantic validation."""
        source=D.decode((root/'source-map.json').read_bytes());program_name=D.PREFIX+'owner-program.json'
        program=D.decode((root/program_name).read_bytes())
        for name in program['files']:program['files'][name]=C.row((root/name).read_bytes())
        (root/program_name).write_bytes(C.encode(program))
        for name in source['files']:source['files'][name]=C.row((root/name).read_bytes())
        raw=C.encode(source);(root/'source-map.json').write_bytes(raw)
        return C.pin(raw)['sha256']

    def documents(self,root,receipt,kind=None):
        now=int(time.time());policy=self.policy();env=self.environment()
        common=dict(issued_by='Root',accepted=True,created_utc=now-1,expires_utc=now+120,nonce='b'*32,
                    source=env['GITHUB_SHA'],ref=env['GITHUB_REF'],source_map_sha256=receipt['source_map']['sha256'],
                    resources=D.decode((root/'held-source32'/D.BASE_PREFIX/'profile.json').read_bytes())['resources'])
        a=dict(common,kind=kind or 'ROOT_FISH02_NO_HOST_APT_ADMISSION_V4')
        r=dict(common,kind='ROOT_FISH02_NO_HOST_APT_RUNTIME_V4',host_tools=policy['host_tools'],
               external_supervision=receipt['owner_program'],bootstrap_resource_domain=receipt['policy'])
        return a,r,env,now

    def admit(self,root,receipt,a,r,env,now):
        ar,rr=C.encode(a),C.encode(r)
        return D.admission(root,receipt['source_map']['sha256'],ar,rr,C.pin(ar)['sha256'],C.pin(rr)['sha256'],env,now)

    def test_deterministic_complete50_derived33_and_full48_inverse(self):
        first=C.construct(BASE,self.root/'a');second=C.construct(BASE,self.root/'b')
        self.assertEqual(first,second);self.assertEqual(first['files'],50);self.assertEqual(first['derived_base_files'],33)
        self.assertTrue(first['original_source48_reconstructed']);self.assertLess(first['bytes'],2*1024**2)
        for name in C.namespace(self.root/'a'):
            self.assertEqual((self.root/'a'/name).read_bytes(),(self.root/'b'/name).read_bytes())
        for value in ('actual_source','actual_grants','actual_run','Root_acceptance'):self.assertIsNone(first[value])
        self.assertFalse((self.root/'a'/(C.PREFIX+'host_prerequisites.py')).exists())
        self.assertFalse((self.root/'a'/(C.PREFIX+'trust_diagnostic.py')).exists())
        self.assertTrue((self.root/'a'/C.NEW_WF).is_file())

    def test_bytecode_enabled_caller_never_changes_predecessor(self):
        base=self.root/'base';shutil.copytree(BASE,base);names=C.namespace(base)
        pins={n:C.pin((base/n).read_bytes()) for n in names}
        with patch.object(sys,'dont_write_bytecode',False):C.construct(base,self.root/'output')
        self.assertEqual(C.namespace(base),names)
        self.assertEqual({n:C.pin((base/n).read_bytes()) for n in names},pins)
        self.assertFalse(any(p.name=='__pycache__'for p in base.rglob('*')))

    def test_changed_predecessor_and_existing_nested_outputs_refuse(self):
        base=self.root/'bad';shutil.copytree(BASE,base)
        (base/'LICENSE').write_bytes(b'changed')
        for origin,target in ((base,self.root/'output'),(BASE,BASE/'NEVER_CREATE')):
            with self.assertRaises(ValueError):C.construct(origin,target)
            self.assertFalse(target.exists())
        target=self.root/'exists';target.mkdir();(target/'KEEP').write_bytes(b'keep')
        with self.assertRaises(ValueError):C.construct(BASE,target)
        self.assertEqual((target/'KEEP').read_bytes(),b'keep')

    def test_inverse_rejects_missing_changed_body_and_after_pin(self):
        for mode in ('before','after','kind'):
            with self.subTest(mode=mode):
                root=self.root/mode;receipt=C.construct(BASE,root);path=root/(D.PREFIX+'source48-inverse.json')
                proof=D.decode(path.read_bytes())
                if mode=='before':proof['before_utf8'].pop(C.OLD_WF)
                elif mode=='after':proof['after'][C.NEW_WF]['sha256']='0'*64
                else:proof['kind']='FISH02_UNSUPPORTED_INVERSE'
                path.write_bytes(C.encode(proof));digest=self.repin(root)
                with self.assertRaises(ValueError):D.source(root,digest)

    def test_runtime_accepts_v4_and_refuses_legacy_apt_documents(self):
        root,receipt=self.build();a,r,env,now=self.documents(root,receipt)
        self.admit(root,receipt,a,r,env,now)
        a['kind']='ROOT_FISH02_HOSTED_ADMISSION_V1'
        with self.assertRaises(ValueError):self.admit(root,receipt,a,r,env,now)
        a['kind']='ROOT_FISH02_NO_HOST_APT_ADMISSION_V4';r['kind']='ROOT_FISH02_HOSTED_RUNTIME_V1'
        with self.assertRaises(ValueError):self.admit(root,receipt,a,r,env,now)
        r['kind']='ROOT_FISH02_NO_HOST_APT_RUNTIME_V4';r['host_prerequisites']={}
        with self.assertRaises(ValueError):self.admit(root,receipt,a,r,env,now)

    def test_existing_host_requires_exact_context_tools_and_zero_mutations(self):
        good=self.host();D.existing_host(good,self.policy())
        for mutate in (lambda v:v.update(commands=['apt-get']),lambda v:v.update(package_manager_invocations=1),
                       lambda v:v.update(host_package_mutations=1),lambda v:v['tools'].append('bsdtar'),
                       lambda v:v['context']['checks'].pop('ROOT_UID'),lambda v:v['context']['checks'].update(CI_DISPATCH=False)):
            value=copy.deepcopy(good);mutate(value)
            with self.assertRaises(ValueError):D.existing_host(value,self.policy())
        env=self.environment();env['GITHUB_REF']='refs/heads/codex/fish02-owned-v2-host-prerequisites-source-old'
        with self.assertRaises(ValueError):X.context(env,'aarch64',b'ID=ubuntu\nVERSION_ID=24.04\n',0)

    def test_observation_requires_actual_v4_existing_host_receipt(self):
        policy=self.policy();a=dict(source='a'*40,ref=self.environment()['GITHUB_REF'],nonce='b'*32)
        host=dict(self.host(),receipt=dict(bytes=1,sha256='c'*64))
        value=dict(kind='FISH02_NO_HOST_APT_ACTUAL_DOMAINS_V4',**a,source_map_sha256='d'*64,
                   owner=dict(pid=42,starttime=123,cgroup='/owner',limits=self.limits(policy['owner'])),
                   daemon=dict(cgroup='/daemon',limits=self.limits(policy['daemon'])),host_policy=host,
                   endpoint='unix:///fenced.sock',storage_bytes=policy['storage_bytes'],backend=policy['bootstrap_backend'])
        D.observation(value,a,'d'*64,policy,42,123,'/owner')
        value['kind']='FISH02_ACTUAL_HOSTED_DOMAINS_V2'
        with self.assertRaises(ValueError):D.observation(value,a,'d'*64,policy,42,123,'/owner')
        value['kind']='FISH02_NO_HOST_APT_ACTUAL_DOMAINS_V4';value['host_policy'].pop('receipt')
        with self.assertRaises(ValueError):D.observation(value,a,'d'*64,policy,42,123,'/owner')

    def test_original_inputs_and_generic_inspectors_unchanged(self):
        root,_=self.build()
        for name in ('runtime/scripts/ci/inputs.lock.json','expected349.lock','runtime/scripts/ci/native_arm.py',
                     'runtime/scripts/checks/package_checks.py','runtime/scripts/build/build_v2.py','runtime/scripts/build/compare_v2.py',
                     'recipe/config.fish','recipe/check-config.py','recipe/LICENSE','recipe/NOTICE','recipe/.SRCINFO'):
            self.assertEqual((root/(C.BASE+name)).read_bytes(),(BASE/(C.BASE+name)).read_bytes())
        self.assertIn(b"PKGEXT='.pkg.tar.xz'",(root/(C.BASE+'recipe/PKGBUILD')).read_bytes())
        (root/'.git').mkdir();(root/'.git'/'IGNORED_METADATA').write_bytes(b'DATA')
        D.source(root,C.pin((root/'source-map.json').read_bytes())['sha256'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base',type=Path,required=True)
    args,rest=parser.parse_known_args();BASE=args.base
    unittest.main(argv=[sys.argv[0],*rest])
