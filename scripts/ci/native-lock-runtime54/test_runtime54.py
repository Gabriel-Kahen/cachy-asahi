#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced pure DATA controls. Never import or enter an operational module."""
import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import runtime54 as R
spec=importlib.util.spec_from_file_location('_runtime54_DATA_composer',HERE/'prepare.py')
Q=importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)


def fence(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','socket.__new__','ctypes.dlopen'):
        raise AssertionError('actor forbidden in DATA controls: '+event)
    if event=='open' and isinstance(args[0],(str,bytes)) and os.fsdecode(args[0])==str(R.LOCK):
        raise AssertionError('shared lock cannot be opened in DATA controls')
sys.addaudithook(fence)
import fcntl
fcntl.flock=lambda *args:(_ for _ in ()).throw(AssertionError('real flock forbidden in DATA controls'))

P,MANIFEST=Q.composer()
DATA=P.inputs(P.SOURCE_ROOT)
HELD=R.HELPER.read_bytes()
CAPTURE=R.LOCK.parent.parent/'security200-v5-ci-feedback-development-20261031/capture.py'
LEASE=R.LOCK.parent.parent/'setup190-held-lock-identity-fix-development-20261027/lock_identity.py'


def issued():
    value=R.obj(R.read(HERE/'Root-runtime54-profile.TEMPLATE.json'))
    value.update(status='ROOT_BOUND_EXACT_EXISTING_LOCK_RUNTIME54',approved=True,attested_at=datetime.now(timezone.utc).isoformat())
    return value


def definitions(raw,names,ns):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes}==set(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<selected-pure-definitions>','exec'),ns)
    return ns


def modeled_stat():
    return NS(st_dev=54,st_ino=59258250,st_uid=1000,st_gid=1000,st_mode=stat.S_IFREG|420,
              st_nlink=1,st_size=0,st_mtime_ns=R.EXACT['mtime_ns'],st_ctime_ns=R.EXACT['ctime_ns'])


class ModelPath:
    def __init__(self,s):self.s=s
    def __str__(self):return str(R.LOCK)
    def __eq__(self,other):return str(other)==str(R.LOCK)
    def lstat(self):return self.s


def identity_model(fd_stat=None,path_stat=None):
    fd_stat=fd_stat or modeled_stat();path_stat=path_stat or fd_stat
    path=ModelPath(path_stat);fake_os=NS(fstat=lambda fd:fd_stat)
    U=NS(LOCK=path,read=lambda p:HELD,need=R.need,stat=stat,os=fake_os,identity=R.state,canonical=lambda p:path)
    with patch.object(R,'binding',return_value=issued()):identity=R.factory(Path('/MODELED/binding'),dict(bytes=1,sha256='a'*64))(U)
    return identity,fake_os


def call_identity(identity,os_model):
    with patch.object(R,'binding',return_value=issued()),patch.object(R,'os',os_model):return identity(7)


class Runtime54Controls(unittest.TestCase):
    def test_profile_positive_and_every_identity_refusal(self):
        self.assertEqual(R.profile(issued())['identity'],R.EXACT)
        for key,value in R.EXACT.items():
            bad=issued();bad['identity'][key]=value+1 if type(value)is int else value+'.alias'
            with self.subTest(identity=key),self.assertRaises(ValueError):R.profile(bad)
        for device in (52,53,55,56,0,2**63):
            bad=issued();bad['identity']['dev']=device
            with self.subTest(device=device),self.assertRaises(ValueError):R.profile(bad)

    def test_unissued_wrong_issuer_schema_and_authority_refusals(self):
        template=R.obj(R.read(HERE/'Root-runtime54-profile.TEMPLATE.json'))
        with self.assertRaises(ValueError):R.profile(template)
        for key,value in [('schema',True),('issuer','worker'),('approved',None),('status','ROOT_BOUND_RUNTIME55'),
                          ('resource_authority',True),('lock_mutation',True),('attested_at',None)]:
            bad=issued();bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):R.profile(bad)
        for value in [datetime.now(timezone.utc)-timedelta(hours=2),datetime.now(timezone.utc)+timedelta(hours=1),datetime.now()]:
            bad=issued();bad['attested_at']=value.isoformat()
            with self.assertRaises(ValueError):R.profile(bad)
        bad=issued();bad['extra']=True
        with self.assertRaises(ValueError):R.profile(bad)

    def test_exact_whole_external_profile_binding_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'Root-model.json';b=root/'binding.json'
            p.write_bytes(Q.encoded(issued()));b.write_bytes(Q.encoded(dict(path=str(p),**R.pin(p.read_bytes()))))
            self.assertTrue(R.binding(b)['approved'])
            p.write_bytes(p.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'whole external'):R.binding(b)
            b.write_bytes(Q.encoded(dict(path=None,bytes=None,sha256=None)))
            with self.assertRaisesRegex(ValueError,'unissued'):R.binding(b)
        with self.assertRaisesRegex(ValueError,'never a DATA'):R.read(R.LOCK)

    def test_duplicate_nonfinite_and_aliased_data_refusals(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):R.obj(raw)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ordinary';p.write_bytes(b'{}');alias=Path(d)/'alias';alias.symlink_to(p)
            with self.assertRaises(ValueError):R.read(alias)
            alias.unlink();os.link(p,alias)
            with self.assertRaises(ValueError):R.read(p)

    def test_exact_52_to_54_inverse_and_tampered_helper_refusal(self):
        source=R.adapted(HELD)
        node=next(n for n in ast.parse(HELD).body if isinstance(n,ast.FunctionDef) and n.name=='lock_identity')
        self.assertEqual(source.replace('(54,59258250)','(52,59258250)',1),ast.get_source_segment(HELD.decode(),node))
        with self.assertRaises(ValueError):R.adapted(HELD+b'\n')

    def test_identity_returns_real54_and_all_unchanged_fields_refuse(self):
        identity,fake=identity_model();self.assertEqual(call_identity(identity,fake),dict(path=str(R.LOCK),dev=54,inode=59258250,mode=420,nlink=1,bytes=0))
        for field in vars(modeled_stat()):
            for drift_both in (False,True):
                s=modeled_stat();setattr(s,field,getattr(s,field)+1)
                identity,fake=identity_model(s,s if drift_both else modeled_stat())
                with self.subTest(field=field,drift_both=drift_both),self.assertRaises(ValueError):call_identity(identity,fake)
        s=modeled_stat();s.st_mode=stat.S_IFDIR|420
        identity,fake=identity_model(s,s)
        with self.assertRaises(ValueError):call_identity(identity,fake)

    def test_profile_is_rechecked_after_factory(self):
        identity,fake=identity_model()
        with patch.object(R,'binding',side_effect=ValueError('changed profile')),patch.object(R,'os',fake):
            with self.assertRaisesRegex(ValueError,'changed profile'):identity(7)

    def test_coordinated_reference_profile_change_cannot_renew_sealed_attestation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'MODELED-Root-profile.json';reference=root/'binding.json'
            p.write_bytes(Q.encoded(issued()));reference.write_bytes(Q.encoded(dict(path=str(p),**R.pin(p.read_bytes()))))
            fixed=R.pin(reference.read_bytes());factory=R.factory(reference,fixed)
            s=modeled_stat();path=ModelPath(s);fake_os=NS(fstat=lambda fd:s)
            U=NS(LOCK=path,read=lambda p:HELD,need=R.need,stat=stat,os=fake_os,identity=R.state,canonical=lambda p:path)
            identity=factory(U)
            replacement=root/'MODELED-replacement-profile.json';replacement.write_bytes(Q.encoded(issued()))
            reference.write_bytes(Q.encoded(dict(path=str(replacement),**R.pin(replacement.read_bytes()))))
            self.assertTrue(R.binding(reference)['approved'])  # Valid DATA, but not this packet's binding.
            with self.assertRaisesRegex(ValueError,'unchanged sealed'):identity(7)

    def test_bootstrap_installs_before_held_modules_without_old55(self):
        files=Q.overlay(P,DATA,Path('/MODELED/fresh'))
        c=NS(runtime_lock_identity=lambda U:(_ for _ in ()).throw(AssertionError('stale55 invoked')))
        c.modules=lambda:(c.runtime_lock_identity('U'),'S','L')
        calls=[];adapter=NS(factory=lambda path,reference_pin:(calls.append((path,reference_pin)) or (lambda U:'U54')))
        raw=files['input-seal.json'];ns=dict(INPUT_SEAL=R.pin(raw)['sha256'],pin=R.pin,need=R.need,json=json,DEV=R.LOCK.parent.parent,load=lambda *a:c,runtime54_adapter=lambda:adapter)
        class ModelFile:
            def __init__(self,path):self.path=Path(path)
            def __str__(self):return str(self.path)
            def read_bytes(self):
                if self.path.is_relative_to('/MODELED/fresh'):return files[self.path.relative_to('/MODELED/fresh').as_posix()]
                return P.read(self.path,64*1024**2)
        class Packet:
            def __truediv__(self,name):return ModelFile(Path('/MODELED/fresh')/name)
        ns['T']=Packet();ns['Path']=ModelFile
        definitions(files['ROOT-NATIVE-ONCE.py'],['bootstrap'],ns)
        self.assertEqual(ns['bootstrap'](),(c,'U54','S','L'));self.assertEqual([str(p) for p,r in calls],['/MODELED/fresh/runtime54-binding.json'])
        self.assertEqual(calls[0][1],R.pin(files['runtime54-binding.json']))

    def test_unchanged_lease_requires_real_conflict_same_fd_and_close_only(self):
        raw=LEASE.read_bytes();self.assertEqual(R.pin(raw)['sha256'],'1e4d1c7ad7040fb982c2c653deb445677863e579d3700c798d6241e6fb69dfe4')
        record=b'pos:\t0\nflags:\t02500002\nmnt_id:\t62\nino:\t59258250\nlock:\t1: FLOCK ADVISORY WRITE 10 00:21:59258250 0 EOF\n'
        for outcome in ('conflict','acquired','wrong_errno','different_description','wrong_owner'):
            calls=[];s=modeled_stat();different=modeled_stat();different.st_ctime_ns+=1
            identity=dict(path=str(R.LOCK),dev=54,inode=59258250,mode=420,nlink=1,bytes=0)
            fake_os=NS(O_RDWR=os.O_RDWR,O_ACCMODE=os.O_ACCMODE,O_NOFOLLOW=os.O_NOFOLLOW,O_NONBLOCK=os.O_NONBLOCK,O_CLOEXEC=os.O_CLOEXEC,
                fstat=lambda fd:different if outcome=='different_description' and fd==8 else s,
                open=lambda path,flags:(calls.append(('open',path,flags)) or 8),close=lambda fd:calls.append(('close',fd)))
            def flock(fd,flags):
                calls.append(('flock',fd,flags))
                if outcome=='acquired':return
                raise OSError(errno.EPERM if outcome=='wrong_errno' else errno.EAGAIN,'MODELED independent conflict')
            F=NS(lock_identity=lambda fd:(calls.append(('identity',fd)) or dict(identity)),identity=R.state,canonical=lambda p:p,LOCK=R.LOCK)
            ns=dict(os=fake_os,errno=errno,re=__import__('re'),need=R.need,
                    fcntl=NS(flock=flock,LOCK_EX=fcntl.LOCK_EX,LOCK_NB=fcntl.LOCK_NB),fdinfo=lambda fd:record)
            definitions(raw,['parse_fdinfo','verify'],ns)
            if outcome=='conflict':
                self.assertEqual(ns['verify'](F,7,10),identity)
                self.assertIn(('flock',8,fcntl.LOCK_EX|fcntl.LOCK_NB),calls)
            else:
                with self.subTest(outcome=outcome),self.assertRaises(ValueError):ns['verify'](F,7,11 if outcome=='wrong_owner' else 10)
            if any(row[0]=='open' for row in calls):self.assertIn(('close',8),calls)
            self.assertNotIn(('close',7),calls)
            self.assertTrue(all(row[2]==fcntl.LOCK_EX|fcntl.LOCK_NB for row in calls if row[0]=='flock'))

    def test_unchanged_custody_requires_owner_pidfd_starttime_before_and_after_nb(self):
        raw=CAPTURE.read_bytes();self.assertEqual(R.pin(raw)['sha256'],'58f9b0fec11c641f50a3963c67f6a6f4b46b64d43e3f584f1d6c9ba50830a99c')
        for outcome in ('alive','wrong_pid','wrong_start','dead_pidfd','start_changed_after_nb','died_after_nb'):
            calls=[];checks=[]
            def read_stat(pid):
                checks.append(pid)
                return [11 if outcome=='wrong_pid' else pid,None,None,None,
                        1235 if outcome=='wrong_start' or (outcome=='start_changed_after_nb' and len(checks)>1) else 1234]
            def poll(*args):
                return ([9] if outcome=='dead_pidfd' or (outcome=='died_after_nb' and len(checks)>1) else [],[],[])
            L=NS(verify=lambda U,fd,pid:(calls.append((fd,pid)) or dict(inode=59258250,dev=54)),fdinfo=lambda fd:b'MODELED',
                 parse_fdinfo=lambda raw,inode,pid:dict(inode=inode,owner=pid))
            ns=dict(need=R.need,OWNER_START=1234,OWNER_PIDFD=9,S_MODULE=NS(_read_stat=read_stat),select=NS(select=poll),
                    os=NS(close=lambda fd:(_ for _ in ()).throw(AssertionError('owned PIDFD cannot be closed here'))))
            definitions(raw,['held'],ns)
            if outcome=='alive':
                result=ns['held'](NS(),L,7,10);self.assertEqual(calls,[(7,10)]);self.assertEqual(result['release'],'CLOSE_ONLY')
                self.assertTrue(result['same_FD'] and result['real_independent_NB_conflict'] and result['original_owner_pidfd_alive'])
            else:
                with self.subTest(outcome=outcome),self.assertRaises(ValueError):ns['held'](NS(),L,7,10)

    def test_unchanged_natural_owned_retirement_refuses_timeout_or_forcing(self):
        ns=dict(need=R.need);definitions(CAPTURE.read_bytes(),['natural'],ns)
        good=dict(passed=True,reaped=True,group_absent=True,pid_reserved_until_retirement=True,exit=0,error=None,timeout=False,forced_retirement=False)
        ns['natural'](good)
        for key,value in good.items():
            bad=dict(good);bad[key]=not value if type(value)is bool else 1 if key=='exit' else 'MODELED failure'
            with self.subTest(key=key),self.assertRaises(ValueError):ns['natural'](bad)

    def test_all_existing_operator_guards_and_bytes_have_exact_inverse(self):
        out=Path('/MODELED/fresh');before=P.render(DATA,out);after=Q.overlay(P,DATA,out)
        native=after['ROOT-NATIVE-ONCE.py'].replace(Q.RUNTIME_FUNCTION,b'',1).replace(Q.BOOT_NEW,Q.BOOT_OLD,1).replace(Q.VERIFY_NEW,Q.VERIFY_OLD,1)
        native=native.replace(R.pin(after['input-seal.json'])['sha256'].encode(),R.pin(before['input-seal.json'])['sha256'].encode(),1)
        self.assertEqual(native,before['ROOT-NATIVE-ONCE.py'])
        preflight=after['ROOT-INDEPENDENT-PREFLIGHT.py'].replace(R.pin(after['ROOT-NATIVE-ONCE.py'])['sha256'].encode(),R.pin(before['ROOT-NATIVE-ONCE.py'])['sha256'].encode(),1)
        self.assertEqual(preflight,before['ROOT-INDEPENDENT-PREFLIGHT.py'])
        self.assertEqual(after['Root-authority.TEMPLATE.json'].replace(Q.REVIEW_NEW,Q.REVIEW_OLD,1),before['Root-authority.TEMPLATE.json'])
        changed={'ROOT-NATIVE-ONCE.py','ROOT-INDEPENDENT-PREFLIGHT.py','Root-authority.TEMPLATE.json','facts.json','seal.json','input-seal.json','root-commands.json'}
        for name,body in before.items():
            if name not in changed:self.assertEqual(after[name],body,name)

    def test_unissued_verify_refuses_before_bootstrap_or_output(self):
        out=Path('/MODELED/fresh');data=deepcopy(DATA);data['binding']=dict(status='ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN',approved=True)
        files=Q.overlay(P,data,out)
        class ModelFile:
            def __init__(self,p):self.p=p
            def read_bytes(self):return files[self.p.relative_to(out).as_posix()]
            def resolve(self):return self
            def is_symlink(self):return False
            @property
            def parents(self):return []
            def __eq__(self,other):return type(other)is ModelFile and other.p==self.p
        class Packet:
            def __truediv__(self,name):return ModelFile(out/name)
        ns=dict(SOURCE='a'*40,TREE='b'*40,MAP='c'*64,REF='codex/model',INPUT_SEAL='d'*64,T=Packet(),pin=R.pin,need=R.need,json=json,
                runtime54_adapter=lambda:R.binding(Path('/MODELED/unissued')))
        definitions(files['ROOT-NATIVE-ONCE.py'],['verify_packet'],ns)
        with patch.object(R,'read',return_value=Q.encoded(dict(path=None,bytes=None,sha256=None))):
            with self.assertRaisesRegex(ValueError,'unissued'):ns['verify_packet'](R.pin(files['seal.json'])['sha256'])

    def test_seal_complete_closure_fresh_publication_and_unissued_authorities(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);parent.chmod(0o700);out=parent/'fresh';files=Q.overlay(P,DATA,out,manifest=MANIFEST);P.publish(files,out)
            seal=P.obj(files['seal.json']);index=P.obj(files['input-seal.json'])
            for name,row in seal['files'].items():self.assertEqual(R.pin(P.read(out/name)),row)
            for name,row in index.items():self.assertEqual(R.pin(P.read(Path(name),64*1024**2)),row)
            self.assertNotIn('Root-preflight-000',' '.join(index));self.assertFalse((out/'Root-preflight-000').exists())
            self.assertFalse((out/'receipts').exists());self.assertFalse((out/'actual-native').exists())
            self.assertIsNone(P.obj(files['Root-authority.TEMPLATE.json'])['approved'])
            self.assertIsNone(P.obj(files['runtime54-binding.json'])['path'])
            with self.assertRaises(FileExistsError):P.publish(files,out)

    def test_modeled_root_profile_overlay_joins_external_pin_without_grant(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'MODELED-Root-profile.json';p.write_bytes(Q.encoded(issued()));digest=R.pin(p.read_bytes())['sha256']
            files=Q.overlay(P,DATA,Path('/MODELED/fresh'),p,digest)
            reference=P.obj(files['runtime54-binding.json']);index=P.obj(files['input-seal.json'])
            self.assertEqual(reference,dict(path=str(p),**index[str(p)]))
            self.assertEqual(P.obj(files['facts.json'])['runtime_lock']['status'],'EXTERNAL_ROOT_RUNTIME54_IDENTITY_ONLY')
            self.assertIsNone(P.obj(files['Root-authority.TEMPLATE.json'])['approved'])
            with self.assertRaises(ValueError):Q.overlay(P,DATA,Path('/MODELED/fresh'),p,'0'*64)
            with self.assertRaises(ValueError):Q.overlay(P,DATA,Path('/MODELED/fresh'),None,digest)
            with self.assertRaises(ValueError):Q.overlay(P,DATA,Path('/MODELED/fresh'),R.LOCK,digest)


def main():
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Runtime54Controls)
    # The exact committed sixteen inherited source/metadata/CAS/privacy controls.
    path=P.HERE/'test_prepare.py';spec=importlib.util.spec_from_file_location('_held_namespace_DATA_controls',path)
    held=importlib.util.module_from_spec(spec);spec.loader.exec_module(held)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(held))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())


if __name__=='__main__':main()
