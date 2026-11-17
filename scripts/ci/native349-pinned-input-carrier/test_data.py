#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite public MODEL fixtures; no private repository, real key, agent or actor."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PARENT = Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-inner-public-retention-v6-20261117/artifacts/development/llhttp-inner-public-retention-v6-20261117-r1/Source95-DATA')
MODEL = None
ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {'os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','os.kill','os.killpg','os.pidfd_open','resource.setrlimit','os.chown'}:
        ACTORS.append(event); raise RuntimeError('FENCED carrier DATA actor')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)) and (args[2] or 0) & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
        need = Path(os.fsdecode(args[0])).absolute()
        if MODEL is None or not need.is_relative_to(MODEL): raise RuntimeError('FENCED write outside MODEL')
    if event.startswith(('os.mkdir','os.remove','os.rmdir','os.rename','os.chmod','os.symlink','os.link')):
        for value in args[:2]:
            if isinstance(value, (str, bytes, os.PathLike)):
                p = Path(os.fsdecode(value)).absolute()
                if not ((MODEL is not None and p.is_relative_to(MODEL)) or p.parent == Path('/home/gabe') and p.name.startswith('native349-MODEL-')):
                    raise RuntimeError('FENCED mutation outside MODEL')


sys.addaudithook(fence)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


C = load(HERE/'carrier.py', 'native349_model_runtime')
P = load(HERE/'prepare.py', 'native349_model_constructor')


class Controls(unittest.TestCase):
    def setUp(self):
        global MODEL
        MODEL = Path(tempfile.mkdtemp(prefix='native349-MODEL-', dir='/home/gabe')); self.area = MODEL
        self.addCleanup(self.clean); self.addCleanup(self.assertEqual, ACTORS, [])
        self.real_expected = copy.deepcopy(C.EXPECTED); self.real_binding = copy.deepcopy(C.BINDING)

    def clean(self):
        for p in sorted(self.area.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if p.is_symlink() or not p.is_dir(): p.unlink()
            else: p.rmdir()
        self.area.rmdir()

    def fixture(self):
        source = self.area/'fixture'; (source/'packages').mkdir(parents=True, mode=0o700)
        expected = dict(schema=1, input_lock_sha256='b'*64, all501_required=True, signer_fingerprint='6'*40, files={}, package_provenance={})
        for i in range(91):
            name = f'MODEL-{i:03d}-1-aarch64.pkg.tar.xz'
            expected['package_provenance'][f'MODEL-{i:03d}'] = dict(version='1',arch='aarch64',filename=name,url='https://example.invalid/'+name,source_url=['https://example.invalid/source'],license=['MODEL'])
            for suffix in ('','.sig'):
                raw = ('MODEL-'+str(i)+suffix).encode(); path = 'packages/'+name+suffix
                expected['files'][path] = dict(C.pin(raw),mode=420); (source/path).write_bytes(raw); (source/path).chmod(0o644)
        manifest = dict(schema=1,kind='NATIVE349_EXACT_MISSING_PUBLIC_INPUTS_V1',input_lock_sha256=expected['input_lock_sha256'],all501_required=True,files=expected['files'],
            package_provenance={k:dict(v,signature_verification=dict(status='PASS_EXACT_OFFICIAL_SIGNATURE',primary_fingerprint=expected['signer_fingerprint'],receipt=dict(bytes=1,sha256='c'*64)))for k,v in expected['package_provenance'].items()},native_build='NOT RUN',installation='NOT RUN',Root_acceptance=None)
        raw = C.encode(manifest); (source/'manifest.json').write_bytes(raw); (source/'manifest.json').chmod(0o644)
        key = b'MODEL_DEPLOY_PUBLIC_KEY_NOT_A_REAL_KEY'; key64 = base64.b64encode(key).decode()
        binding = dict(repository=C.REPOSITORY,branch='native349-r1',commit='d'*40,tree='e'*40,manifest=C.pin(raw),ssh_host_keys=[C.HOST_REFERENCE['key']],
            deploy_key_fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('='),Root_receipt=dict(bytes=1,sha256='f'*64),readonly_repository_scope=C.REPOSITORY)
        return source, expected, binding, key64

    def modeled(self, expected, binding):
        return patch.multiple(C,EXPECTED=expected,BINDING=binding,TOTAL=sum(r['bytes']for r in expected['files'].values()),LARGEST=max(r['bytes']for r in expected['files'].values()))

    def test_real182_manifest_matches_original_lock_and_unissued_before_secret_access(self):
        self.assertEqual(len(C.EXPECTED['files']),182); self.assertEqual(len(C.EXPECTED['package_provenance']),91)
        self.assertEqual(sum(r['bytes']for r in C.EXPECTED['files'].values()),544634853)
        self.assertEqual(max(r['bytes']for r in C.EXPECTED['files'].values()),104330276)
        self.assertEqual(C.EXPECTED['input_lock_sha256'],'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
        self.assertTrue(C.EXPECTED['all501_required'])
        for name in ('commit','tree','manifest','Root_receipt'): self.assertIsNone(C.BINDING[name])
        class ForbiddenEnv(dict):
            def pop(self,*args): raise AssertionError('no secret access before Root binding')
        with self.assertRaises(ValueError): C.fetch(PARENT,self.area/'fetch',environment=ForbiddenEnv())

    def test_complete183_public_material_and_strict_schema_provenance(self):
        source,expected,binding,_ = self.fixture()
        with self.modeled(expected,binding):
            self.assertEqual(C.material(source,binding['manifest'])['files'],expected['files'])
            value=C.decode((source/'manifest.json').read_bytes())
            for changed in (dict(value,extra='MODEL'),dict(value,input_lock_sha256='f'*64),dict(value,all501_required=False),dict(value,native_build='PASS')):
                with self.assertRaises(ValueError): C.manifest(C.encode(changed))
            wrong=copy.deepcopy(value);first=next(iter(wrong['package_provenance']));wrong['package_provenance'][first]['version']='2'
            with self.assertRaises(ValueError):C.manifest(C.encode(wrong))
            wrong=copy.deepcopy(value);wrong['files'][next(iter(wrong['files']))]['sha256']='0'*64
            with self.assertRaises(ValueError):C.manifest(C.encode(wrong))

    def test_namespace_modes_link_tamper_and_partial_refuse(self):
        source,expected,binding,_=self.fixture()
        with self.modeled(expected,binding):
            path=source/next(iter(expected['files']));raw=path.read_bytes();path.write_bytes(raw+b'wrong')
            with self.assertRaises(ValueError):C.material(source,binding['manifest'])
            path.write_bytes(raw);path.chmod(0o600)
            with self.assertRaises(ValueError):C.material(source,binding['manifest'])
            path.chmod(0o644);(source/'unlisted').write_text('MODEL-private')
            with self.assertRaises(ValueError):C.material(source,binding['manifest'])
            (source/'unlisted').unlink();path.unlink();os.symlink(str(source/'manifest.json'),path)
            with self.assertRaises(ValueError):C.material(source,binding['manifest'])

    def test_exact_public_seed_only182_no_overwrite_url_or_signature_waiver(self):
        source,expected,binding,_=self.fixture();work=self.area/'volume/work';work.mkdir(parents=True);staged=work/'native349-pinned-inputs';cache=work/'llhttp-reference-native/cache';cache.mkdir(parents=True)
        legacy=cache/'MODEL-old-retained-member';legacy.write_bytes(b'unchanged')
        with self.modeled(expected,binding):
            C.copy_public(source,staged)
            row=C.seed(staged,cache);self.assertEqual(row['files'],182);self.assertTrue(row['all501_required']);self.assertFalse(row['URL_overrides'])
            self.assertEqual(legacy.read_bytes(),b'unchanged');self.assertEqual(len(list(cache.iterdir())),183)
            first=cache/next(iter(expected['files'])).removeprefix('packages/');first.write_bytes(b'bad-existing')
            with self.assertRaises(ValueError):C.seed(staged,cache)
            self.assertEqual(first.read_bytes(),b'bad-existing')

    def test_same_run_owned_quota_stage_and_fresh_admission_precede_secret_access(self):
        source,expected,binding,_=self.fixture();run=self.area/'native349-carrier-123-1';run.mkdir();source.rename(run/'public')
        work=self.area/'native-owner/volume/work';work.mkdir(parents=True)
        with self.modeled(expected,binding),patch.dict(C.os.environ,{'GITHUB_RUN_ID':'123'},clear=True):
            row=C.stage(run/'public',work/'native349-pinned-inputs',None,None);self.assertEqual(row['files'],182)
            with self.assertRaises(ValueError):C.stage(run/'public',self.area/'foreign/nested/volume/work/native349-pinned-inputs',None,None)
        class ForbiddenEnv(dict):
            def pop(self,*args):raise AssertionError('no secret access before fresh whole admission')
        with self.modeled(expected,binding),patch.object(C.platform,'machine',return_value='aarch64'):
            with self.assertRaises(ValueError):C.fetch(PARENT,self.area/'fetch',runner=lambda *_:self.fail('no command'),environment=ForbiddenEnv())

    def test_stored_and_reachable_forbidden_unreachable_and_blob_size_refuse_before_checkout(self):
        source,expected,binding,_=self.fixture()
        with self.modeled(expected,binding):
            good=(binding['commit']+' commit\n').encode();self.assertEqual(C.metadata_guard(good,good)['stored'],1)
            for oid in C.FORBIDDEN:
                with self.assertRaises(ValueError):C.metadata_guard(good+(oid+' blob\n').encode(),good)
                with self.assertRaises(ValueError):C.metadata_guard(good,good+(oid+'\n').encode())
            with self.assertRaises(ValueError):C.metadata_guard(good+b'a'*40+b' blob\n',good)
            rows=[]
            for name,row in dict(expected['files'],**{'manifest.json':binding['manifest']}).items():rows.append(f'100644 blob {"a"*40} {row["bytes"]}\t{name}\0'.encode())
            self.assertEqual(len(C.tree_metadata(b''.join(rows))),183)
            with self.assertRaises(ValueError):C.tree_metadata(b''.join(rows).replace(b'100644',b'100755',1))
            with self.assertRaises(ValueError):C.tree_metadata(b''.join(rows).replace(b'\tpackages/',b'\tprivate/',1))

    def fetch_runner(self,fixture,expected,binding,key64,fail=None):
        calls=[];oids={binding['commit'],binding['tree']};tree=[]
        for name,row in dict(expected['files'],**{'manifest.json':binding['manifest']}).items():
            body=(fixture/name).read_bytes();oid=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest();oids.add(oid);tree.append(f'100644 blob {oid} {len(body)}\t{name}\0'.encode())
        def runner(argv,env):
            calls.append(argv)
            self.assertNotIn(C.SECRET,env);self.assertNotIn('SSH_AUTH_SOCK',env);self.assertFalse(any(k.startswith('GIT_TRACE')for k in env))
            if argv[0]=='/usr/bin/ssh-keygen':
                key=Path(argv[-1]);self.assertEqual(stat.S_IMODE(key.stat().st_mode),0o600)
                return ('ssh-ed25519 '+key64+'\n').encode()
            args=argv[len(C.GIT):]
            if args[0]=='init':Path(args[-1]).mkdir(mode=0o700)
            if args[0]=='fetch':
                self.assertIn('IdentityAgent=none',env['GIT_SSH_COMMAND']);self.assertIn('StrictHostKeyChecking=yes',env['GIT_SSH_COMMAND'])
                if fail:raise ValueError('MODEL private failure never printed')
            if args[:2]==['cat-file','--batch-all-objects']:return b''.join((oid+' blob\n').encode()for oid in sorted(oids))
            if args[:2]==['rev-list','--objects']:return b''.join((oid+'\n').encode()for oid in sorted(oids))
            if args[:2]==['cat-file','-p']:return ('tree '+binding['tree']+'\nauthor MODEL\n\nMODEL\n').encode()
            if args[0]=='ls-tree':return b''.join(tree)
            if args[0]=='checkout':
                store=self.area/'fetch/git';self.assertFalse((self.area/'fetch/credential-home/identity').exists())
                shutil.copytree(fixture/'packages',store/'packages');shutil.copyfile(fixture/'manifest.json',store/'manifest.json')
            return b''
        return runner,calls

    def test_mock_fetch_lifecycle_key_deleted_before_checkout_no_agent_no_forwarding(self):
        fixture,expected,binding,key64=self.fixture();runner,calls=self.fetch_runner(fixture,expected,binding,key64)
        fakekey='-----BEGIN OPENSSH PRIVATE KEY-----\nMODEL_NOT_A_KEY\n-----END OPENSSH PRIVATE KEY-----\n';environment={C.SECRET:fakekey,'SSH_AUTH_SOCK':'MODEL-no-agent','GIT_TRACE':'MODEL-no-trace'}
        with self.modeled(expected,binding),patch.object(C,'admitted_source',return_value=None),patch.object(C.platform,'machine',return_value='aarch64'),patch.object(C.shutil,'disk_usage',return_value=type('Free',(),{'free':10**12})()),patch.object(C,'tool',side_effect=lambda n:dict(path='/usr/bin/'+n,identity='MODEL',sha256='a'*64)):
            row=C.fetch(PARENT,self.area/'fetch',runner=runner,environment=environment)
        self.assertTrue(row['private_key_absent']);self.assertFalse(row['credentials_forwarded']);self.assertNotIn(C.SECRET,environment)
        self.assertFalse((self.area/'fetch/credential-home/identity').exists());self.assertFalse((self.area/'fetch/git').exists())
        self.assertNotIn(fakekey,json.dumps(row));self.assertEqual(len(list((self.area/'fetch/public/packages').iterdir())),182)
        names=[x[len(C.GIT)]for x in calls if x[:len(C.GIT)]==C.GIT];self.assertLess(names.index('cat-file'),names.index('checkout'));self.assertLess(names.index('ls-tree'),names.index('checkout'))

    def test_mock_transport_refusal_always_deletes_key_without_retry(self):
        fixture,expected,binding,key64=self.fixture();runner,calls=self.fetch_runner(fixture,expected,binding,key64,fail=True)
        env={C.SECRET:'-----BEGIN OPENSSH PRIVATE KEY-----\nMODEL_NOT_A_KEY\n-----END OPENSSH PRIVATE KEY-----\n'}
        with self.modeled(expected,binding),patch.object(C,'admitted_source',return_value=None),patch.object(C.platform,'machine',return_value='arm64'),patch.object(C.shutil,'disk_usage',return_value=type('Free',(),{'free':10**12})()),patch.object(C,'tool',side_effect=lambda n:dict(path='/usr/bin/'+n,identity='MODEL',sha256='a'*64)):
            with self.assertRaises(ValueError):C.fetch(PARENT,self.area/'fetch',runner=runner,environment=env)
        self.assertFalse((self.area/'fetch/credential-home/identity').exists());self.assertNotIn(C.SECRET,env)
        self.assertEqual(sum(x[len(C.GIT):][:1]==['fetch']for x in calls if x[:len(C.GIT)]==C.GIT),1)

    def test_partial_credential_write_failure_deletes_only_same_temporary_file(self):
        fixture,expected,binding,key64=self.fixture();runner,calls=self.fetch_runner(fixture,expected,binding,key64)
        env={C.SECRET:'-----BEGIN OPENSSH PRIVATE KEY-----\nMODEL_NOT_A_KEY\n-----END OPENSSH PRIVATE KEY-----\n'}
        with self.modeled(expected,binding),patch.object(C,'admitted_source',return_value=None),patch.object(C.platform,'machine',return_value='aarch64'),patch.object(C.shutil,'disk_usage',return_value=type('Free',(),{'free':10**12})()),patch.object(C,'tool',side_effect=lambda n:dict(path='/usr/bin/'+n,identity='MODEL',sha256='a'*64)),patch.object(C.os,'fsync',side_effect=OSError('MODEL disk failure')):
            with self.assertRaises(OSError):C.fetch(PARENT,self.area/'fetch',runner=runner,environment=env)
        self.assertFalse((self.area/'fetch/credential-home/identity').exists());self.assertNotIn(C.SECRET,env);self.assertEqual(calls,[])

    def test_source95_complete_inverse_unchanged_guards_and_seed_before_audit(self):
        old=P.parent_bodies(PARENT);out=self.area/'Source';result=P.construct(PARENT,out);new={str(p.relative_to(out)):p.read_bytes()for p in out.rglob('*')if p.is_file()}
        self.assertEqual(result['files'],95);self.assertLess(result['bytes'],2*1024**2);self.assertEqual(P.inverse(new),old)
        self.assertEqual(set(new)-set(old),{P.HELPER,P.NEW_WF});self.assertEqual(set(old)-set(new),{P.REPACK,P.OLD_WF})
        policy=json.loads(new[P.PREFIX+'policy.json']);policy.pop('private_pinned_input_carrier');self.assertEqual(policy,json.loads(old[P.PREFIX+'policy.json']))
        self.assertTrue(all(new[n]==raw for n,raw in old.items()if n.startswith('held-source/')))
        entry=old['held-source/scripts/ci/llhttp-reference-native-source/base/entry.py'];projected=C.project_entry(entry)
        self.assertLess(projected.index(b'PINNED_CARRIER.seed'),projected.index(b'native.audit('));self.assertIn(b'seed.seed_current_build_cache',projected)
        self.assertEqual(projected.replace(b"\n        PINNED_CARRIER.seed(PINNED_INPUTS,output/'cache')",b''),entry)
        for token in (b'ordinary payload natural success required',b'E.preserve(',b'owner.cleanup()',b'PAIR_PASSED_PENDING_EXTERNAL_CLEANUP'):
            self.assertIn(token,new[P.PREFIX+'hosted_owner.py'])
        for name in (P.HELPER,P.MARKER,P.NEW_WF,P.PREFIX+'payload.py'):
            with self.assertRaises((ValueError,KeyError,json.JSONDecodeError)):P.inverse(dict(new,**{name:new[name]+b'\nMODEL-tamper'}))

    def test_workflow_new_case_five_inputs_secret_only_fetch_and_no_apt(self):
        text=(HERE/'workflow.yml.in').read_text();self.assertIn('native-arm-llhttp-pinned-input-source',text)
        self.assertEqual(text.count('${{ secrets.CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY }}'),1)
        fetch=text.split('- name: Root-admitted exact private native349 public-input carrier',1)[1].split('- name: Admitted existing-host',1)[0]
        self.assertIn(C.SECRET,fetch);controller=text.split('- name: Admitted existing-host',1)[1]
        self.assertNotIn(C.SECRET,controller);self.assertNotIn('set -x',text)
        self.assertEqual(text.count('required: true'),5);self.assertIn('group: native-arm-llhttp-reference-source',text)
        self.assertIn('--carrier-root',controller)
        for bad in ('apt-get','apt install','ssh-agent','StrictHostKeyChecking=no','--nodeps','--nocheck'):self.assertNotIn(bad,text)


if __name__=='__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:raise SystemExit('Use python -I -B unoptimized')
    unittest.main(verbosity=2)
