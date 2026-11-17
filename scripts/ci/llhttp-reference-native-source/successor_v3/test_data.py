#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced diagnostic/failed-service DATA controls, no systemd/Root/native actors."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
PARENT=Path(os.environ.get('LLHTTP_V3_PARENT','/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/llhttp-go-cli-va-successor-DATA-20261117-r1'))
PUBLIC=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp68-native-result-r1/public-files')
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=module(HERE/'prepare.py','llhttp_v3_prepare_test');F=module(HERE/'failed_retirement.py','llhttp_v3_retirement_test');X=module(HERE/'payload_diagnostic.py','llhttp_v3_diag_test')
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','fcntl.flock','os.pidfd_open','resource.setrlimit'):
        raise RuntimeError('fenced DATA actor forbidden: '+event)
sys.addaudithook(fence)
NONCE='a'*32
UNIT='cachy-llhttp-reference-'+NONCE+'-owner.service'
GROUP='/system.slice/'+UNIT

def fixture():
    owned=dict(submitted=True,pid=123,starttime=456,cgroup=GROUP,original_pidfd=7,original_pidfd_identity=dict(dev=1,inode=2))
    row=dict(Description='cachy-llhttp-reference-owned-'+NONCE+'-owner',LoadState='loaded',ActiveState='failed',SubState='failed',MainPID='0',ControlGroup='',Result='exit-code',ExecMainCode='1',ExecMainStatus='2')
    census=[dict(cgroup=GROUP,path_present=False,events_empty=True,procs_empty=True,pidfd_exited=True)for _ in range(2)]
    return owned,row,census

class Controls(unittest.TestCase):
    def test_hash_only_diagnostics_and_all_phase_ids(self):
        private='PRIVATE_ENV_TOKEN_AND_PATH=/private/unpublished/value'
        for phase in X.PHASES:
            X.phase(phase);text=X.record(ValueError(private));self.assertLessEqual(len(text.encode()),512);self.assertNotIn(private,text);row=json.loads(text.removeprefix('HOLD_PAYLOAD: '));self.assertEqual(row['phase'],phase);self.assertEqual(row['message_bytes'],len(private.encode()));self.assertEqual(row['message_prefix_sha256'],hashlib.sha256(private.encode()).hexdigest())
        X.phase('entry');text=X.record(ValueError(private*1000));row=json.loads(text.removeprefix('HOLD_PAYLOAD: '));self.assertTrue(row['truncated']);self.assertEqual(row['message_prefix_bytes'],8192);self.assertNotIn(private,text)
        with self.assertRaises(ValueError):X.phase(private)

    def test_already_failed_is_retired_but_never_success(self):
        owned,row,census=fixture()
        with patch.object(F,'pidfd_exited',return_value=True):result=F.retire_failed('owner',NONCE,owned,row,row,7,census)
        self.assertEqual(result['retirement'],'STOPPED_EMPTY_FAILED_OWNER');self.assertIs(result['payload_success'],False);self.assertEqual(result['payload_exit'],2);self.assertIs(result['unit_reset'],False)

    def test_active_unknown_foreign_and_custody_refusals(self):
        for mode in ('active-before','active-after','description','unit-cgroup','missing-start','pidfd-ledger','missing-pidfd','wrong-exit','signal-exit','changed-exit','one-census','nonempty','unknown-unit'):
            owned,before,censuses=fixture();after=copy.deepcopy(before);fd=7
            if mode=='active-before':before.update(ActiveState='active',SubState='running',MainPID='123',ControlGroup=GROUP)
            elif mode=='active-after':after.update(ActiveState='active')
            elif mode=='description':after['Description']='foreign'
            elif mode=='unit-cgroup':owned['cgroup']='/foreign'
            elif mode=='missing-start':owned.pop('starttime')
            elif mode=='pidfd-ledger':owned['original_pidfd']=8
            elif mode=='missing-pidfd':fd=None
            elif mode=='wrong-exit':after['ExecMainStatus']='0'
            elif mode=='signal-exit':after['ExecMainCode']='2'
            elif mode=='changed-exit':after['ExecMainStatus']='3'
            elif mode=='one-census':censuses.pop()
            elif mode=='nonempty':censuses[1]['procs_empty']=False
            else:after['LoadState']='not-found'
            with self.subTest(mode=mode),patch.object(F,'pidfd_exited',return_value=True),self.assertRaises(ValueError):F.retire_failed('owner',NONCE,owned,before,after,fd,censuses)
        owned,row,census=fixture()
        with patch.object(F,'pidfd_exited',return_value=False),self.assertRaises(ValueError):F.retire_failed('owner',NONCE,owned,row,row,7,census)
        with patch.object(F,'pidfd_exited',return_value=True),self.assertRaises(ValueError):F.retire_failed('daemon',NONCE,owned,row,row,7,census)

    def test_bounded_empty_cgroup_files_and_unknown_refusals(self):
        with tempfile.TemporaryDirectory(prefix='llhttp-v3-cgroup-MODEL-',dir='/home/gabe')as name:
            path=Path(name);(path/'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n');(path/'cgroup.procs').write_bytes(b'')
            self.assertTrue(F.empty_snapshot(path)['events_empty'])
            (path/'cgroup.procs').write_bytes(b'123\n')
            with self.assertRaises(ValueError):F.empty_snapshot(path)
            (path/'cgroup.procs').write_bytes(b'');(path/'cgroup.events').write_bytes(b'populated 1\n')
            with self.assertRaises(ValueError):F.empty_snapshot(path)
            (path/'cgroup.events').write_bytes(b'unknown 0\n')
            with self.assertRaises(ValueError):F.empty_snapshot(path)
            self.assertFalse(F.empty_snapshot(path/'missing')['path_present'])
            (path/'cgroup.events').write_bytes(b'populated 1\npopulated 0\n')
            with self.assertRaises(ValueError):F.empty_snapshot(path)
            with patch.object(Path,'lstat',side_effect=PermissionError('unknown census access')),self.assertRaises(PermissionError):F.empty_snapshot(path)

    def test_full_constructor_inverse_and_all_original_guards(self):
        if not PARENT.exists():self.skipTest('genuine retained Source68 DATA required')
        original,_=P.parent_bodies(PARENT);projected,seams=P.projections(original)
        for name,raw in projected.items():
            text=raw.decode()
            for seam in reversed(seams[name]):text=text.replace(seam['after'],seam['before'])
            self.assertEqual(text.encode(),original[name])
        before=ast.parse(original[P.PREFIX+'hosted_owner.py']);after=ast.parse(projected[P.PREFIX+'hosted_owner.py'])
        for name in('cleanup','run','main','setup','preflight'):
            get=lambda t:ast.dump(next(n for n in ast.walk(t)if isinstance(n,ast.FunctionDef)and n.name==name),include_attributes=False)
            self.assertEqual(get(before),get(after))
        self.assertNotIn('reset-failed',projected[P.PREFIX+'hosted_owner.py'].decode());self.assertIn("'ordinary payload natural success required'",projected[P.PREFIX+'hosted_owner.py'].decode())
        with tempfile.TemporaryDirectory(prefix='llhttp-v3-Source-DATA-',dir='/home/gabe')as name:
            output=Path(name)/'Source';result=P.construct(PARENT,output);self.assertEqual(result['files'],76);self.assertTrue(all(v is None for v in result['actual'].values()));bodies={str(n.relative_to(output)):n.read_bytes()for n in output.rglob('*')if n.is_file()};self.assertEqual(P.inverse(bodies),original)
            policy=json.loads(bodies[P.PREFIX+'policy.json']);policy.pop('payload_diagnostics');policy.pop('failed_owner_retirement');self.assertEqual(policy,json.loads(original[P.PREFIX+'policy.json']))

    def test_actual84_public_observation_replay_and_failure_preserved(self):
        if not(PUBLIC.exists()and PARENT.exists()):self.skipTest('retained public actual84 DATA required')
        D=module(PARENT/P.PREFIX/'data.py','actual84_public_declarations');obs=json.loads((PUBLIC/'actual-domains.json').read_bytes());owner=obs['owner'];a={k:obs[k]for k in('source','ref','nonce')};policy=json.loads((PARENT/P.PREFIX/'policy.json').read_bytes());D.observation(obs,a,obs['source_map_sha256'],policy,owner['pid'],owner['starttime'],owner['cgroup'])
        report=json.loads((PUBLIC/'owner-report.json').read_bytes());self.assertEqual(report['status'],'HOLD');self.assertEqual(report['cleanup']['errors'],[dict(error='ValueError',step='owner')]);self.assertIs(report['cleanup']['owned_storage_absent'],False);self.assertEqual((PUBLIC/'owner.log').read_bytes(),b'HOLD_PAYLOAD: ValueError\n')

    def test_projected_real_stop_function_failed_and_active_models(self):
        if not PARENT.exists():self.skipTest('genuine retained Source68 DATA required')
        original,_=P.parent_bodies(PARENT);projected,_=P.projections(original);tree=ast.parse(projected[P.PREFIX+'hosted_owner.py']);node=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='stop')
        D=module(PARENT/P.PREFIX/'data.py','llhttp_stop_model_data');scope=dict(D=D,F=F,Path=Path,time=type('Clock',(),{'sleep':staticmethod(lambda _:None)}));exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-stop-function-model>','exec'),scope)
        for mode in('failed','active','foreign','missing-custody'):
            owned,row,censuses=fixture();commands=[]
            if mode=='active':row.update(ActiveState='active',SubState='running',MainPID='123',ControlGroup=GROUP)
            if mode=='foreign':row['Description']='foreign'
            if mode=='missing-custody':owned.pop('original_pidfd')
            model=type('ControllerModel',(),{})();model.nonce=NONCE;model.units={'owner':owned};model.pidfds={'owner':7};model.show=lambda _:copy.deepcopy(row);model.tool=lambda _: '/usr/bin/systemctl';model.run=lambda argv,seconds:commands.append(argv)
            with self.subTest(mode=mode),patch.object(F,'empty_snapshot',return_value=dict(path_present=False,events_empty=True,procs_empty=True)),patch.object(F,'pidfd_exited',return_value=True):
                if mode=='failed':
                    result=scope['stop'](model,'owner');self.assertIs(result['payload_success'],False);self.assertEqual(len(commands),1)
                else:
                    with self.assertRaises(ValueError):scope['stop'](model,'owner')
                    if mode=='foreign':self.assertEqual(commands,[])

if __name__=='__main__':unittest.main(verbosity=2)
