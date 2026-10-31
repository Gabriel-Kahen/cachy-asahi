#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow ordinary-DATA controls only. All process/network actor APIs denied."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--basis',type=Path,required=True,help='exact genuine191 root; DATA only')
parser.add_argument('--candidate',type=Path,help='held exact24-source plus profile tree; optional with --payload')
parser.add_argument('--components',type=Path,default=HERE/'payload/native')
parser.add_argument('--payload',type=Path,help='factory payload root containing contract/source tar/config')
parser.add_argument('--output',type=Path,help='optional DATA result; never native evidence')
OPTIONS=parser.parse_args()
COMPONENTS=OPTIONS.components.resolve();BASIS_ROOT=OPTIONS.basis.resolve()
PAYLOAD=(OPTIONS.payload or COMPONENTS.parent).resolve()
sys.dont_write_bytecode=True
sys.path[:0]=[str(COMPONENTS),str(BASIS_ROOT/'native')]
DENIED=[]
def deny_actors(event,args):
    if event in {'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'} or event.startswith('socket.'):
        DENIED.append(event)
        raise RuntimeError('actor API denied in ordinary-DATA controls: '+event)
sys.addaudithook(deny_actors)
import measurement_tools_v1 as T
import measurement_alpm_v1 as A
import measurement_reader_v1 as R
import measurement_projection_v1 as P
import measurement_guest_v1 as G


def tar_data(members):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,raw,mode,kind in members:
            item=tarfile.TarInfo(name);item.mode=mode;item.type=kind
            if kind==tarfile.REGTYPE:item.size=len(raw)
            else:item.linkname='PKGBUILD'
            archive.addfile(item,io.BytesIO(raw) if kind==tarfile.REGTYPE else None)
    return target.getvalue()


class DataControls(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=OPTIONS.output.parent if OPTIONS.output else None,prefix='measurement-data-control-')
        self.root=Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
    def bundle(self):
        members=[];files={}
        if OPTIONS.candidate:
            candidate=OPTIONS.candidate.resolve()
            for path in sorted(candidate.rglob('*')):
                if not path.is_file():continue
                raw=path.read_bytes();name=str(path.relative_to(candidate));mode=path.stat().st_mode&0o777
                members.append((name,raw,mode,tarfile.REGTYPE));files[name]=dict(mode=mode,**T.data_pin(raw))
        else:
            contract=json.loads(T.ordinary(PAYLOAD/'native/measurement-contract-v1.json'))
            files=contract['bundle']['files']
            data=T.recipe_members(PAYLOAD,contract)
            members=[(name,raw,files[name]['mode'],tarfile.REGTYPE) for name,raw in sorted(data.items())]
        source_files={name[len(T.RECIPE_PREFIX):]:row for name,row in files.items() if name.startswith(T.RECIPE_PREFIX)}
        return members,files,source_files
    def policy(self,members,files,source_files):
        raw=tar_data(members);(self.root/'native').mkdir(exist_ok=True);(self.root/'native/measurement-sources-v1.tar').write_bytes(raw)
        return dict(bundle=dict(path='native/measurement-sources-v1.tar',max_bytes=1024**2,members=25,files=files,**T.data_pin(raw)),recipe=dict(source_files=source_files))
    def test_01_five_modules_parse_without_actor_calls(self):
        for path in COMPONENTS.glob('measurement_*.py'):ast.parse(path.read_text())
        self.assertEqual(T.OPERATION,G.OPERATION);self.assertEqual(A.PASS,G.PASS);self.assertEqual(R.PASS,A.PASS)
    def test_02_exact_original_candidate25_data_bundle(self):
        members,files,source_files=self.bundle();policy=self.policy(members,files,source_files)
        self.assertEqual(len(T.recipe_members(self.root,policy)),25)
        self.assertEqual(len(source_files),18);self.assertIn('.SRCINFO',source_files)
    def test_03_link_and_special_bundle_members_refused(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.DIRTYPE):
            members,files,source_files=self.bundle();name,raw,mode,_=members[0];members[0]=(name,raw,mode,kind)
            policy=self.policy(members,files,source_files)
            with self.assertRaises(ValueError):T.recipe_members(self.root,policy)
    def test_04_duplicate_undeclared_and_missing_bundle_members_refused(self):
        members,files,source_files=self.bundle()
        for changed in (members+[members[0]],members[:-1],members+[('extra',b'fake',0o644,tarfile.REGTYPE)]):
            policy=self.policy(changed,files,source_files)
            with self.assertRaises(ValueError):T.recipe_members(self.root,policy)
    def test_05_tar_padding_and_trailer_refused(self):
        members,files,source_files=self.bundle();policy=self.policy(members,files,source_files)
        path=self.root/policy['bundle']['path'];original=path.read_bytes()
        for offset in (512+len(members[0][1]),len(original)-1):
            raw=bytearray(original);raw[offset]=1;path.write_bytes(raw);policy['bundle'].update(T.data_pin(raw))
            with self.assertRaises(ValueError):T.recipe_members(self.root,policy)
    def test_06_recipe_pin_join_refuses_substitution(self):
        members,files,source_files=self.bundle();source_files=copy.deepcopy(source_files);source_files['PKGBUILD']['sha256']='0'*64
        policy=self.policy(members,files,source_files)
        with self.assertRaises(ValueError):T.recipe_members(self.root,policy)
    def test_07_ordinary_symlink_hardlink_fifo_refusal(self):
        original=self.root/'ordinary';original.write_bytes(b'bounded DATA')
        alias=self.root/'alias';alias.symlink_to(original)
        with self.assertRaises(ValueError):T.ordinary(alias)
        alias.unlink();os.link(original,alias)
        with self.assertRaises(ValueError):T.ordinary(original)
        alias.unlink();alias=self.root/'fifo';os.mkfifo(alias)
        with self.assertRaises(ValueError):T.ordinary(alias)
    def test_08_snapshot_binds_bytes_modes_and_alias_data(self):
        directory=self.root/'tree';directory.mkdir();path=directory/'data';path.write_bytes(b'one');first=T.snapshot_receipt(directory)
        path.write_bytes(b'two');self.assertNotEqual(first,T.snapshot_receipt(directory));path.chmod(0o600)
        (directory/'link').symlink_to('/not-followed');self.assertEqual(T.snapshot(directory)['link']['target'],'/not-followed')
    def test_09_null_or_incomplete_actual_selectors_refused_before_io(self):
        for expected in ({},{'source':None,'ref':None,'run':None,'map_sha256':None,'capsule_sha256':None},dict(source='a'*40,ref='refs/heads/codex/control',run='1',map_sha256='b'*64)):
            with self.assertRaisesRegex(ValueError,'before reading'):R.validate(self.root/'absent.tar',expected)
    def test_10_test_signature_parser_refuses_unknown_bad_wrong_or_untrusted(self):
        fingerprint='A'*40
        valid='[GNUPG:] VALIDSIG '+fingerprint+' 2026-10-31 1 0 4 0 22 8 00 '+fingerprint+'\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'
        A.strict_signature(valid,fingerprint);R.strict_test_signature(valid,fingerprint)
        for raw in (valid+'[GNUPG:] BADSIG x\n',valid.replace('TRUST_ULTIMATE','TRUST_UNDEFINED'),valid.replace(fingerprint,'B'*40)):
            with self.assertRaises(ValueError):A.strict_signature(raw,fingerprint)
            with self.assertRaises(ValueError):R.strict_test_signature(raw,fingerprint)
    def test_11_preserve_primary_failure_over_cleanup(self):
        first=RuntimeError('precise original namespace failure')
        cleanup=dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['secondary'])
        self.assertIs(A.primary_failure(first,cleanup),first);self.assertIsInstance(A.primary_failure(None,cleanup),ValueError)
    def test_12_exact_dockerfile_seam_and_map_required(self):
        raw=A.dockerfile('FROM retained\nUSER alarm\nWORKDIR /tmp\n','a'*64)
        self.assertIn('--inside-image --retain-failure-image --map-sha256 '+'a'*64,raw)
        for base,checksum in (('FROM retained\n','a'*64),('USER alarm\nWORKDIR /tmp\n',None)):
            with self.assertRaises(ValueError):A.dockerfile(base,checksum)
    def test_13_all349_expected_dependency_architecture_rows(self):
        result=T.expected_installed(BASIS_ROOT);self.assertEqual(len(result),349)
        self.assertIn('python-3.14.8-1-aarch64',result);self.assertIn('bubblewrap-0.13.0-1-aarch64',result)
    def test_14_exact_inventory_addition_and_inverse(self):
        base=(BASIS_ROOT/'native/expected349.lock').read_bytes()
        self.assertEqual(len(T.inventory_expected(base).splitlines()),349)
        self.assertEqual(len(T.inventory_expected(base,T.VERSION).splitlines()),350)
        with self.assertRaises(ValueError):T.inventory_expected(base,'forged')
    def test_15_cleanup_refuses_unowned_directory_without_actor(self):
        called=[]
        result=A.retire_homes(lambda *args:called.append(args),(self.root/'signing',self.root/'trust'),self.root)
        self.assertFalse(result['private_directory_absent']);self.assertFalse(called);self.assertTrue(self.root.exists())
    def test_16_declared_source_path_traversal_refused(self):
        members,files,source_files=self.bundle();name,raw,mode,kind=members[0]
        files['../escape']=files.pop(name);members[0]=('../escape',raw,mode,kind)
        policy=self.policy(members,files,source_files)
        with self.assertRaises(ValueError):T.recipe_members(self.root,policy)
    def test_17_command_supervision_requires_raw_logs_and_natural_retirement(self):
        raw=b'ordinary known output\n';prefix='journey/measurement-tools-alpm-v1/'
        supervision=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[])
        row=dict(step='known',log='000-known.log',log_pin=T.data_pin(raw),supervision=supervision,expected=0,success=True,argv=['/usr/bin/true'])
        class View:
            def load(self,name):return self.rows
            def read(self,name):return raw
        view=View();view.rows=[row];files={prefix+row['log']:dict(kind='file',**T.data_pin(raw))}
        self.assertEqual(R.measurement_commands(view,files,prefix,view.rows)('known')[0],0)
        for key,value in (('ownership','UNKNOWN'),('group_census','UNKNOWN'),('output_complete',False),('signals',[15]),('timeout',True),('exit',1)):
            broken=copy.deepcopy(row);broken['supervision'][key]=value;view.rows=[broken]
            with self.assertRaises(ValueError):R.measurement_commands(view,files,prefix,view.rows)
    def test_18_actual_native_actor_guard_refuses_host_before_io(self):
        with self.assertRaisesRegex(ValueError,'native image root only'):A.inside(self.root,'a'*64)
        guest_tree=ast.parse((COMPONENTS/'measurement_guest_v1.py').read_text())
        guest=next(node for node in guest_tree.body if isinstance(node,ast.FunctionDef) and node.name=='run')
        self.assertIsInstance(guest.body[0],ast.Expr)
        self.assertIn('actual unprivileged native ARM ALARM consumer required',ast.get_source_segment((COMPONENTS/'measurement_guest_v1.py').read_text(),guest.body[0]))
    def test_19_accepted_cleanup_protocol_is_exact_zero_exit56B_combined_pipe(self):
        self.assertEqual(len(A.ABSENCE_OUTPUT),56);self.assertEqual(A.ABSENCE_OUTPUT,R.ABSENCE_OUTPUT)
        tree=ast.parse((COMPONENTS/'measurement_alpm_v1.py').read_text())
        retirement=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='retire_homes')
        self.assertIn('exact complete zero-exit56B',ast.get_source_segment((COMPONENTS/'measurement_alpm_v1.py').read_text(),retirement))
        self.assertNotIn("'/bye'],'nonzero'",ast.get_source_segment((COMPONENTS/'measurement_alpm_v1.py').read_text(),retirement))
    def test_20_assembled_contract_bundle_and_pair_data_extraction(self):
        for relative in ('bootstrap/scripts/ci/inputs.lock.json','native/input-profile.json','native/expected349.lock'):
            target=self.root/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(BASIS_ROOT/relative,target)
        for name in ('measurement-contract-v1.json','measurement-sources-v1.tar','measurement-makepkg-v1.conf'):
            shutil.copyfile(PAYLOAD/'native'/name,self.root/'native'/name)
        policy,base=T.source_policy(self.root);members=T.recipe_members(self.root,policy)
        self.assertEqual(len(members),25);self.assertEqual(len(base.splitlines()),349)
        destination=T.extract_recipes(self.root,self.root/'extracted',policy)
        for label in ('a','b'):
            self.assertEqual({p.name for p in (destination/label).iterdir()},T.SOURCE_FILES)
            for name,row in policy['recipe']['source_files'].items():
                self.assertEqual(T.pin(destination/label/name),{k:row[k] for k in ('bytes','sha256')})
        self.assertNotEqual((destination/'a').stat().st_ino,(destination/'b').stat().st_ino)
    def test_21_no_actor_api_was_used(self):
        self.assertEqual(DENIED,[])


if __name__=='__main__':
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DataControls))
    report=dict(schema=1,status='PASS_ORDINARY_DATA_CONTROLS_ONLY' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
                failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped),actor_attempts=DENIED,
                native='NOT_RUN',ALPM='NOT_RUN',GPG='NOT_RUN',build='NOT_RUN',workload='NOT_RUN',namespace_support='UNKNOWN',
                physical_M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',output=stream.getvalue())
    if OPTIONS.output:OPTIONS.output.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(stream.getvalue(),end='');raise SystemExit(not result.wasSuccessful())
