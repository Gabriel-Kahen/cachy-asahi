# SPDX-License-Identifier: MIT
"""Supervisor orchestration fixtures only; no Docker or native packages."""
import hashlib
import importlib.util
import json
import os
import textwrap
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import ExitStack, nullcontext

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import executor as e

ROOT = HERE.parents[2]


def actual_snapshot():
    files = {name: (ROOT / name).read_bytes() for name in e.required_paths.EXPECTED_PATHS}
    metadata = {name: {'mode': f'{(ROOT / name).stat().st_mode & 0o777:04o}',
                      'sha256': e.job.sha(data), 'size_bytes': len(data)} for name, data in files.items()}
    return e.acceptance.Snapshot(ROOT, files, {'files': metadata})


STARTUP_DRIVER = r'''
import json, os, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'scripts/port/ksm-native-job'))
import executor as e
scenario=sys.argv[4]; calls=[]; closed=[]
secret='private-daemon-id-and-path-that-must-not-be-exported'
image_a='sha256:'+'d'*64; image_b='sha256:'+'e'*64
images={image_a:{'Id':image_a,'Architecture':'amd64','Os':'linux','Config':{'Env':[secret]},
    'RootFS':{'Type':'layers','Layers':[]},'Size':17,'RepoTags':['fixture:a','fixture:alias'],
    'RepoDigests':[]},image_b:{'Id':image_b,'Architecture':'arm64','Os':'linux','Config':None,
    'RootFS':{'Type':'layers'},'Size':21,'RepoTags':None,'RepoDigests':None}}
inspections=[0]
expired=[False]; original_clock=time.monotonic; original_stat=Path.stat; original_broker=e.broker.Broker
def clock(): return original_clock()+(181 if expired[0] else 0)
def stat_path(path,*args,**kwargs):
    if scenario=='source-expired' and path in (Path('/run/docker.sock'),Path('/var/run/docker.sock')):
        expired[0]=True
        return original_stat(root/'run/ksm-native-7-1/private/rpc.sock')
    return original_stat(path,*args,**kwargs)
class Backend:
    endpoint='unix:///run/docker.sock'; expected=secret
    cli_sha256='c'*64; socket_identity=(11,12)
    def call(self,argv,timeout=30):
        calls.append(argv[2:])
        if argv[2]=='info':
            return SimpleNamespace(stdout=b'{"Architecture":"aarch64","OSType":"linux","CgroupVersion":"2","SecurityOptions":[]}')
        if argv[2:4]==['image','inspect']:
            inspections[0]+=1
            target=argv[4]
            identity=image_a if target in ('fixture:a','fixture:alias') else target
            if scenario=='baseline-reference-drift' and target=='fixture:a': identity=image_b
            row=dict(images[identity])
            if scenario=='baseline-drift' and inspections[0]>=5: row['Size']+=1
            return subprocess.CompletedProcess(argv,0,json.dumps([row]).encode(),b'')
        if argv[2] in ('image','container'):
            if scenario=='image' and argv[2]=='image': data=secret.encode()+b'\n'
            elif scenario=='container' and argv[2]=='container': data=secret.encode()+b'\n'
            elif scenario=='container-valid' and argv[2]=='container': data=b'9'*64+b'\n'
            elif scenario=='exit' and argv[2]=='image': data=b''
            elif (scenario.startswith('baseline-') or scenario=='source-expired') and argv[2]=='image': data=((image_a+'\n')*3+(image_b+'\n')*3).encode()
            else: data=b''
            return subprocess.CompletedProcess(argv,17 if scenario=='exit' and argv[2]=='image' else 0,data,b'')
        raise AssertionError('actor reached')
    def close(self): closed.append(True)
def capture():
    calls.append(['cli-capture'])
    if scenario=='tripwire': raise ValueError(secret)
    return b'synthetic-sealed-cli'
def forbidden(*args,**kwargs):
    calls.append(['broker-tripwire'])
    raise AssertionError('native actor reached')
def broker_factory(*args,**kwargs):
    return original_broker(*args,**kwargs) if scenario=='source-expired' else forbidden(*args,**kwargs)
args=SimpleNamespace(execute_native=True,source_root=root,source_commit=sys.argv[2],
    packet_sha256=sys.argv[3],output=root/'run/ksm-native-7-1',started_at=time.monotonic())
args.output.parent.mkdir(mode=0o700)
env={'GITHUB_REPOSITORY':'Gabriel-Kahen/cachy-asahi','RUNNER_ARCH':'ARM64','RUNNER_OS':'Linux',
    'GITHUB_SHA':args.source_commit,'GITHUB_WORKFLOW_SHA':args.source_commit,'GITHUB_RUN_ID':'7',
    'GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':str(args.output.parent),'PACKET_SHA256':args.packet_sha256}
original_is_file=Path.is_file; original_access=os.access
tools={Path('/usr/bin')/name for name in ('docker','python3','gpg','lscpu','zstd','git')}
try:
    with patch.dict(os.environ,env),patch.object(e.platform,'machine',return_value='aarch64'), \
         patch.object(e.platform,'system',return_value='Linux'), \
         patch.object(e.time,'monotonic',side_effect=clock),patch.object(Path,'stat',stat_path), \
         patch.object(Path,'is_file',lambda p: True if p in tools else original_is_file(p)), \
         patch.object(os,'access',lambda p,m: True if Path(p) in tools else original_access(p,m)), \
         patch.object(e.shutil,'disk_usage',return_value=SimpleNamespace(free=32*1024**3)), \
         patch.object(e.runtime.os,'fstatvfs',return_value=SimpleNamespace(f_bavail=32*1024**3,f_frsize=1)), \
         patch.object(e.boundary,'cli_capture',side_effect=capture), \
         patch.object(e.boundary,'create',side_effect=lambda *a,**k: Backend()), \
         patch.object(e.broker,'Broker',side_effect=broker_factory),patch.object(e,'pipeline',side_effect=forbidden):
        with e.runtime.cancellation_handlers() as state: report=e.execute(args,state)
    assert json.loads((args.output/'private/result.json').read_bytes())==report
    assert secret not in json.dumps(report)
    print(json.dumps({'report':report,'calls':calls,'closed':len(closed)},sort_keys=True))
finally:
    if args._private_fd is not None: os.close(args._private_fd)
'''


class ExecutorTests(unittest.TestCase):
    def test_actual_captured_stage_nested_base_and_contract_imports(self):
        snapshot = actual_snapshot()
        e.job.source_policy(snapshot.files)
        with tempfile.TemporaryDirectory() as temporary:
            fresh = e.source_tree(snapshot, Path(temporary) / 'source')
            # The previous direct-stage closure reproduces the first nested failure.
            names = ('argparse','fcntl','hashlib','importlib','importlib.util','json','os',
                     'pathlib','platform','re','stat','subprocess','sys','tempfile')
            imports = {name: __import__('importlib').import_module(name) for name in names}
            with self.assertRaisesRegex(ValueError, '^unbound transitive import: contextlib$'):
                fresh.module('scripts/port/ksm-lifecycle/stage.py', 'old_stage_fixture', imports=imports)
            stage = e.stage_module(fresh)
            contract = stage.load_contract(e.job.sha(fresh.files['scripts/port/ksm-lifecycle/contract.py']))
            self.assertEqual(stage.base.__file__, str(fresh.root / 'scripts/client/stage.py'))
            self.assertEqual(contract.__file__, str(fresh.root / 'scripts/port/ksm-lifecycle/contract.py'))
            with self.assertRaisesRegex(ValueError, '^unbound transitive import: executor$'):
                stage.__dict__['__builtins__']['__import__']('executor')
            e.check_source_tree(snapshot, fresh.root)

    def startup_fixture(self, scenario):
        with tempfile.TemporaryDirectory(prefix='ksm-startup-fixture-') as temporary:
            root = Path(temporary) / 'checkout'
            snapshot = actual_snapshot(); e.source_tree(snapshot, root)
            packet = root / 'scripts/port/ksm-native-job/packet.lock.json'
            packet.write_text(json.dumps({'schema_version':1,'files':snapshot.provenance['files']},sort_keys=True))
            env = {'PATH':'/usr/bin:/bin','HOME':temporary,'LC_ALL':'C',
                   'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1'}
            def git(*args):
                return subprocess.check_output(['/usr/bin/git','-C',str(root),*args],env=env,
                                               stderr=subprocess.PIPE,timeout=10).decode().strip()
            git('init','--quiet'); git('add','--force','--all')
            git('-c','user.name=Source Fixture','-c','user.email=fixture@invalid',
                '-c','commit.gpgSign=false','commit','--quiet','-m','synthetic startup fixture')
            result = subprocess.run([sys.executable,'-I','-B','-S','-c',textwrap.dedent(STARTUP_DRIVER),
                str(root),git('rev-parse','HEAD'),e.job.sha(packet.read_bytes()),scenario],
                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertLessEqual(len(result.stdout),65536)
            return json.loads(result.stdout)

    def test_actual_isolated_executor_startup_reaches_cli_tripwire_without_native_actor(self):
        result=self.startup_fixture('tripwire'); report=result['report']
        self.assertEqual(result['calls'],[['cli-capture']]); self.assertEqual(result['closed'],0)
        self.assertEqual(report['source_failure_reason'],'docker-cli-capture-refused')
        self.assertEqual(report['source_observations'],{})
        self.assertEqual(report['failure_category'],'ValueError')
        self.assertEqual(report['phase'],'source'); self.assertFalse(report['ownership_uncertain'])
        for key in ('producer','lifecycle','cleanup','hardware','performance','public_export'):
            self.assertEqual(report[key],'NOT RUN')
        self.assertEqual(report['builds'],['NOT RUN','NOT RUN'])

    def test_source_daemon_baseline_diagnostics_refuse_invalid_images_containers_and_query_exit(self):
        for scenario,kind,code,lines in (('image','image',0,1),('container','container',0,1),
                                        ('container-valid','container',0,1),('exit','image',17,0)):
            with self.subTest(scenario=scenario):
                result=self.startup_fixture(scenario); report=result['report']
                self.assertEqual(report['status'],'FAIL'); self.assertEqual(report['phase'],'source')
                self.assertEqual(report['source_gate'],'daemon-'+kind+'-baseline')
                self.assertEqual(report['source_failure_reason'],'daemon-'+kind+'-baseline-refused')
                self.assertEqual(report['source_observations'][kind+'_returned_exit'],code)
                self.assertEqual(report['source_observations'][kind+'_returned_lines'],lines)
                self.assertEqual(result['closed'],1); self.assertFalse(report['ownership_uncertain'])
                self.assertEqual(report['producer'],'NOT RUN'); self.assertEqual(report['cleanup'],'NOT RUN')
                self.assertEqual(result['calls'][-1],[kind,'ls','--all','--no-trunc','--format','{{.ID}}'])
                if scenario=='container-valid':
                    self.assertEqual(report['daemon_baseline']['initial_container_count'],1)
                    self.assertIsNone(report['daemon_baseline']['initial_image_id_count'])
                    self.assertNotIn('image_returned_lines',report['source_observations'])

    def test_actual_startup_accepts_stable_tagged_and_dangling_baseline_before_broker(self):
        result=self.startup_fixture('baseline-positive'); report=result['report']
        self.assertEqual(result['calls'][-1],['broker-tripwire'])
        self.assertEqual(report['source_gate'],'broker-reservation')
        self.assertEqual(report['producer_mutation'],'NOT_STARTED')
        self.assertEqual(report['producer'],'NOT RUN')
        baseline=report['daemon_baseline']
        self.assertEqual(baseline['status'],'PASS')
        self.assertEqual(baseline['preservation'],'UNVERIFIED')
        self.assertEqual(baseline['protected_image_count'],2)
        self.assertEqual(baseline['initial_image_id_count'],2)
        self.assertEqual(baseline['initial_container_count'],0)
        self.assertEqual(report['source_observations']['image_returned_lines'],6)
        self.assertEqual(report['source_observations']['container_returned_lines'],0)
        self.assertRegex(baseline['receipt_sha256'],'^[0-9a-f]{64}$')

    def test_actual_startup_refuses_baseline_metadata_or_reference_drift_before_broker(self):
        for scenario in ('baseline-drift','baseline-reference-drift'):
            with self.subTest(scenario=scenario):
                result=self.startup_fixture(scenario); report=result['report']
                self.assertNotIn(['broker-tripwire'],result['calls'])
                self.assertEqual(report['status'],'FAIL')
                self.assertEqual(report['daemon_baseline']['status'],'FAIL')
                self.assertEqual(report['producer_mutation'],'NOT_STARTED')
                self.assertEqual(report['producer'],'NOT RUN')

    def test_actual_startup_source_expiry_after_rpc_setup_cannot_launch_producer(self):
        result=self.startup_fixture('source-expired'); report=result['report']
        self.assertNotIn(['broker-tripwire'],result['calls'])
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['source_failure_reason'],'endpoint-alias-observations-refused')
        self.assertEqual(report['producer_mutation'],'NOT_STARTED')
        self.assertEqual(report['producer'],'NOT RUN')

    def test_actual_cli_commands_keep_original_sources_without_override(self):
        command = e.consumer.producer_command('/source', '/private', inputs_sha=e.job.INPUTS_SHA, recipes_sha=e.job.RECIPES_SHA)
        command.insert(1, '-I'); command.insert(3, '-S')
        self.assertEqual(command[:5], ['/usr/bin/python3', '-I', '-B', '-S', '/source/scripts/ci/native_arm.py'])
        self.assertNotIn('fdk', ' '.join(command))
        self.assertEqual(command[5], 'build')

    def test_lifecycle_root_output_scope_inputs_bind_actual_producer_pair_and_sources(self):
        producer={'image_id':'sha256:'+'c'*64,'sha256':{'bootstrap.json':'d'*64}}
        package={'filename':'cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz','sha256':'e'*64}
        binding={'source_commit':'a'*40,'run_id':'7','daemon_id':'daemon1234','uid':os.getuid()}
        expected,pins,inputs=e.lifecycle_grant_inputs(producer,{'package':package},binding)
        self.assertEqual(set(expected),{'schema_version','purpose','scope','phase','source_commit','run_id',
            'daemon_id','image_id','uid','package','approved_inputs_sha256','bootstrap_sha256',
            'packages_sha256','current_inputs_sha256','source_sha256'})
        self.assertEqual(expected['phase'],'lifecycle'); self.assertEqual(expected['uid'],binding['uid'])
        self.assertEqual(expected['bootstrap_sha256'],producer['sha256']['bootstrap.json'])
        self.assertEqual(expected['image_id'],producer['image_id']); self.assertEqual(expected['package'],package)
        self.assertEqual(expected['source_sha256'],pins)
        self.assertEqual(set(pins),{'scripts/client/stage.py','scripts/ci/source_suites.py',
            'scripts/port/ksm-lifecycle/stage.py','scripts/port/ksm-lifecycle/worker.py','scripts/port/ksm-lifecycle/contract.py'})
        self.assertEqual(inputs[package['filename']],package['sha256'])
        self.assertEqual(inputs['approved-inputs.json'],e.job.MAP_SHA)

    def test_native_guard_refuses_without_authorization_and_native_host(self):
        with self.assertRaises(ValueError):
            e.ordinary(SimpleNamespace(execute_native=False))
        args=SimpleNamespace(execute_native=False,source_commit='a'*40,packet_sha256='b'*64,started_at=time.monotonic())
        state=SimpleNamespace(signum=None,check=lambda:None)
        report=e.execute(args,state)
        self.assertEqual(report['source_failure_reason'],'native-coordinator-refused')
        self.assertEqual(report['source_gate'],'native-coordinator')
        self.assertEqual(report['source_observations'],{})
        self.assertEqual(report['producer'],'NOT RUN')

    def test_fresh_snapshot_rejects_extra_pyc_and_changed_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = b'VALUE=1\n'
            snapshot = e.acceptance.Snapshot(root, {'scripts/helper.py': data},
                {'files': {'scripts/helper.py': {'mode': '0644'}}})
            copy = e.source_tree(snapshot, root / 'source')
            (root / 'source/cache.pyc').write_bytes(b'foreign')
            with self.assertRaises(ValueError): e.check_source_tree(snapshot, copy.root)
            (root / 'source/cache.pyc').unlink()
            (root / 'source/scripts/helper.py').write_bytes(b'VALUE=2\n')
            with self.assertRaises(ValueError): e.check_source_tree(snapshot, copy.root)

    def test_deadline_never_borrows_later_reserves(self):
        with patch.object(e.time, 'monotonic', return_value=100):
            self.assertEqual(e.allowance(1800, 6600, 1650), 50)
            with self.assertRaises(ValueError): e.allowance(1750, 6600, 1650)

    def test_owned_cleanup_and_final_baseline_share_one_nonrenewable_cutoff(self):
        owner=SimpleNamespace(operation_deadline=None,backend=SimpleNamespace(cleanup_mode=False,
            runner=SimpleNamespace(phase_scope=lambda end:nullcontext())),cleanup=lambda:{'status':'PASS'})
        with patch.object(e.time,'monotonic',return_value=100):
            self.assertEqual(e.owned_cleanup(owner,1000),{'status':'PASS'})
            self.assertEqual(owner.cleanup_end,280)
        with patch.object(e.time,'monotonic',return_value=200):
            e.owned_cleanup(owner,1000)
            self.assertEqual(owner.cleanup_end,280)
        with patch.object(e.time,'monotonic',return_value=281),self.assertRaises(ValueError):
            e.owned_cleanup(owner,1000)

    def test_late_failure_invalidates_only_pinned_own_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'public').mkdir()
            data = b'{"status":"PASS"}\n'
            path = root / 'public/evidence.json'; path.write_bytes(data)
            report = {'public_evidence_sha256': e.job.sha(data)}
            dirfd=e.contracts.directory(path.parent); filefd=os.open(path,os.O_RDWR)
            info=os.fstat(filefd)
            ownership=(dirfd,filefd,e.directory_identity_fd(dirfd),(info.st_dev,info.st_ino))
            try:
                e.invalidate_public(root, report, ownership)
                self.assertEqual(json.loads(path.read_bytes())['status'], 'FAIL-native-job')
                e.invalidate_public(root, report, ownership)
                path.write_bytes(b'foreign')
                with self.assertRaises(ValueError): e.invalidate_public(root, report, ownership)
                self.assertEqual(path.read_bytes(), b'foreign')
            finally: os.close(filefd); os.close(dirfd)

    def test_launcher_uses_actual_tools_and_private_explicit_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            env = e.launcher_environment(Path('/snapshot with spaces'), private, 'a' * 64, private / 'rpc.sock')
            self.assertTrue(env['PATH'].startswith(str(private / 'bin') + ':'))
            self.assertEqual(env['DOCKER_BUILDKIT'], '0')
            self.assertEqual(env['DOCKER_HOST'], 'unix:///run/docker.sock')
            self.assertNotIn('LD_PRELOAD', env)
            self.assertIn('exec /usr/bin/python3 -I -B -S', (private / 'bin/docker').read_text())
            self.assertIn('--no-autostart --lock-never', (private / 'bin/gpg').read_text())

    def test_durable_journal_must_match_actual_owner_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'journal'
            path.write_bytes(b'{"event":"opened"}\n')
            owner = SimpleNamespace(journal_path=path, events=[{'event': 'opened'}])
            self.assertEqual(e.journal_rows(owner), owner.events)
            owner.events.append({'event': 'foreign'})
            with self.assertRaises(ValueError): e.journal_rows(owner)

    def test_existing_or_replaced_private_result_cannot_be_overwritten_on_late_cancel(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'job'; output.mkdir(); (output / 'private').mkdir()
            path = output / 'private/result.json'; path.write_bytes(b'foreign')
            args = SimpleNamespace(output=output)
            with self.assertRaises(ValueError): e.save_status(args, {'status': 'FAIL'})
            self.assertEqual(path.read_bytes(), b'foreign')
            args._owned_directories = {directory: e.directory_identity(directory)
                                      for directory in (output, output / 'private')}
            (output / 'private').rename(output / 'original-private')
            (output / 'private').mkdir(); path.write_bytes(b'foreign replacement')
            with self.assertRaises(ValueError): e.save_status(args, {'status': 'FAIL'})
            self.assertEqual(path.read_bytes(), b'foreign replacement')

    def test_private_namespace_replacement_during_write_cannot_redirect_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'job'; output.mkdir(); private=output/'private'; private.mkdir()
            (private/'result.json').write_bytes(b'old')
            args=SimpleNamespace(output=output,_private_fd=e.contracts.directory(private))
            args._owned_directories={p:e.directory_identity(p) for p in (output,private)}
            original=e.os.fsync; moved=[False]
            def replace_during_fsync(fd):
                original(fd)
                if not moved[0]:
                    moved[0]=True; private.rename(output/'original-private'); private.mkdir()
                    (private/'result.json').write_bytes(b'foreign')
            try:
                with patch.object(e.os,'fsync',side_effect=replace_during_fsync),self.assertRaises(ValueError):
                    e.save_status(args,{'status':'FAIL'})
                self.assertEqual((private/'result.json').read_bytes(),b'foreign')
                self.assertEqual((output/'original-private/result.json').read_bytes(),b'old')
            finally: os.close(args._private_fd)

    def test_public_directory_replacement_or_symlink_cannot_redirect_invalidation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); public=root/'public'; public.mkdir(); path=public/'evidence.json'
            data=b'{"status":"PASS"}\n'; path.write_bytes(data)
            dirfd=e.contracts.directory(public); filefd=os.open(path,os.O_RDWR); info=os.fstat(filefd)
            ownership=(dirfd,filefd,e.directory_identity_fd(dirfd),(info.st_dev,info.st_ino))
            report={'public_evidence_sha256':e.job.sha(data)}
            try:
                public.rename(root/'owned-public'); public.mkdir(); path.write_bytes(data)
                with self.assertRaises(ValueError):e.invalidate_public(root,report,ownership)
                self.assertEqual(path.read_bytes(),data)
                path.unlink(); public.rmdir(); public.symlink_to(root/'owned-public',target_is_directory=True)
                with self.assertRaises(OSError):e.invalidate_public(root,report,ownership)
                self.assertEqual((root/'owned-public/evidence.json').read_bytes(),data)
            finally: os.close(filefd); os.close(dirfd)

    def test_terminal_sigint_rewrites_failure_before_process_owned_fds_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'job'; output.mkdir(); private=output/'private'; private.mkdir()
            public=output/'public'; public.mkdir(); evidence=public/'evidence.json'
            data=b'{"status":"PASS"}\n'; evidence.write_bytes(data)
            args=SimpleNamespace(output=output,source_commit='a'*40,packet_sha256='b'*64)
            args._private_fd=e.contracts.directory(private)
            args._owned_directories={p:e.directory_identity(p) for p in (output,private)}
            dirfd=e.contracts.directory(public); filefd=os.open(evidence,os.O_RDWR); info=os.fstat(filefd)
            ownership=(dirfd,filefd,e.directory_identity_fd(dirfd),(info.st_dev,info.st_ino))
            report=e.initial(args); report.update(status='PASS',public_export='PASS',public_evidence_sha256=e.job.sha(data))
            args._report=report; e.save_status(args,report)
            def executed(arguments,state): state.owned_public=ownership; return report
            emitted=[]
            def interrupted_print(value, *, flush):
                self.assertTrue(flush)
                emitted.append(json.loads(value))
                if len(emitted)==1: os.kill(os.getpid(),signal.SIGINT)
            try:
                with patch.object(e.argparse.ArgumentParser,'parse_args',return_value=args), \
                     patch.object(e,'execute',side_effect=executed),patch('builtins.print',side_effect=interrupted_print):
                    self.assertEqual(e.main(),1)
                self.assertEqual(json.loads((private/'result.json').read_bytes())['status'],'FAIL')
                self.assertEqual(json.loads(evidence.read_bytes())['status'],'FAIL-native-job')
                self.assertEqual(emitted[-1]['status'],'FAIL')
                for fd in (args._private_fd,dirfd,filefd): os.fstat(fd)
            finally:
                for fd in (args._private_fd,dirfd,filefd): os.close(fd)

    def test_observed_producer_failure_cannot_launch_lifecycle_or_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            journal = private / 'journal'; journal.write_bytes(b'{"event":"opened"}\n')
            owner = SimpleNamespace(failed=False, journal_path=journal, events=[{'event': 'opened'}],
                backend=SimpleNamespace(runner=SimpleNamespace(phase_scope=lambda end: nullcontext())))
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 1, b'private failure')
            runner = SimpleNamespace(run=run, deadline=time.monotonic()+8460)
            report = {'phase': 'source'}
            with patch.object(e, 'check_source_tree'), patch.object(e,'baseline_observe'), self.assertRaises(ValueError):
                e.pipeline(SimpleNamespace(files={}), Path('/source'), private, owner,
                    SimpleNamespace(poll=lambda: None), runner, {}, {}, report, SimpleNamespace(check=lambda: None))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][5], 'build')
            self.assertEqual(report['phase'], 'producer')
            self.assertEqual(report['producer_mutation'],'UNCERTAIN')

    def test_final_baseline_drift_blocks_public_acceptance_after_clean_actor_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=Path(temporary); (private/'lifecycle').mkdir()
            (private/'lifecycle/receipt.json').write_bytes(b'{}')
            producer={'image_id':'sha256:'+'c'*64,'runner_endpoint':'unix:///run/docker.sock',
                      'sha256':{'runner.json':'d'*64,'bootstrap.json':'e'*64}}
            pair={'package':{'filename':'fixture.pkg.tar.xz','sha256':'f'*64},
                  'provenance_sha256':['a'*64,'b'*64]}
            backend=SimpleNamespace(cli_sha256='c'*64,socket_identity=(1,2))
            runner=SimpleNamespace(deadline=time.monotonic()+8460,phase_scope=lambda end:nullcontext(),
                lifecycle_outputs=lambda *args:nullcontext(),
                run=lambda command,**kwargs:subprocess.CompletedProcess(command,0,b'{}',b''))
            backend.runner=runner
            owner=SimpleNamespace(failed=False,backend=backend,operation_deadline=None,cleanup_end=runner.deadline-30,
                baseline=SimpleNamespace(protected=lambda:frozenset()))
            files={'packages/tools/cachy-asahi-ksmctl/'+name:b'fixture' for name in e.job.KSM_INPUTS}
            snapshot=SimpleNamespace(files=files,module=lambda *a,**k:SimpleNamespace())
            expected_map={name:e.job.sha(b'fixture') for name in e.job.KSM_INPUTS}
            map_sha=e.job.sha((json.dumps(expected_map,sort_keys=True,indent=2)+'\n').encode())
            report=e.initial(SimpleNamespace(source_commit='a'*40,packet_sha256='b'*64)); stages=[]
            def observe(owner,stage,end,**kwargs):
                stages.append(stage)
                if stage=='after_cleanup': raise ValueError('baseline-changed')
            with ExitStack() as stack:
                for target,name,value in ((e,'check_source_tree',lambda *a,**k:None),
                    (e,'baseline_observe',observe),(e,'journal_rows',lambda *a:[]),
                    (e.contracts,'validate_producer',lambda *a,**k:producer),
                    (e.contracts,'validate_ksm_pair',lambda *a,**k:pair),
                    (e.consumer,'validate_comparison',lambda *a:None),
                    (e,'lifecycle_grant_inputs',lambda *a:(None,None,None)),
                    (e,'owned_cleanup',lambda *a:{'status':'PASS'})):
                    stack.enter_context(patch.object(target,name,side_effect=value))
                stack.enter_context(patch.object(e.job,'MAP_SHA',map_sha))
                acceptance=stack.enter_context(patch.object(e.contracts,'public_acceptance'))
                export=stack.enter_context(patch.object(e.public,'export'))
                with self.assertRaisesRegex(ValueError,'^baseline-changed$'):
                    e.pipeline(snapshot,Path('/source'),private,owner,SimpleNamespace(poll=lambda:None),
                        runner,{}, {'source_commit':'a'*40,'run_id':'7','daemon_id':'daemon1234'},
                        report,SimpleNamespace(check=lambda:None))
                acceptance.assert_not_called(); export.assert_not_called()
            self.assertEqual(report['producer_mutation'],'COMPLETE_ACCEPTED')
            self.assertEqual(report['builds'],['PASS','PASS'])
            self.assertEqual(report['phase'],'cleanup')
            self.assertEqual(report['public_export'],'NOT RUN')
            self.assertEqual(stages[-1],'after_cleanup')


class SourceDeadlineTests(unittest.TestCase):
    def setUp(self):
        import test_acceptance
        self.fixture = test_acceptance.AcceptanceTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.packet_relative = 'scripts/port/ksm-native-job/packet.lock.json'
        f.packet = f.root / f.packet_relative; f.packet.parent.mkdir(parents=True)
        f.pin = f.write_packet(); f.commit_packet()
        self.clock = [179.0]

    def execute(self, expire):
        f = self.fixture
        run = f.base / 'run'; run.mkdir(mode=0o700)
        args = SimpleNamespace(execute_native=True,source_root=f.root,source_commit=f.commit,
            packet_sha256=f.pin,output=run/'ksm-native-7-1',started_at=0.0)
        env = f.job | {'GITHUB_RUN_ID':'7','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':str(run)}
        original_read, original_copy, original_launcher = e.acceptance.captured_file, e.source_tree, e.launcher_environment
        reads, copies = [], []
        def read(path, **kwargs):
            reads.append(kwargs.get('deadline'))
            value = original_read(path, **kwargs)
            if expire == 'capture': self.clock[0] = 181.0
            return value
        def copy(snapshot, path, **kwargs):
            copies.append(kwargs.get('deadline'))
            if expire == 'copy': self.clock[0] = 181.0
            return original_copy(snapshot,path,**kwargs)
        def launch(*args,**kwargs):
            self.assertEqual(kwargs['deadline'],180.0)
            value=original_launcher(*args,**kwargs)
            self.clock[0]=181.0
            return value
        try:
            with patch.dict(os.environ,env), patch.object(e.time,'monotonic',side_effect=lambda:self.clock[0]), \
                 patch.object(e,'ordinary'), patch.object(e.required_paths,'EXPECTED_PATHS',f.required), \
                 patch.object(e.required_paths,'WORKFLOW',f.workflow), patch.object(e.job,'source_policy'), \
                 patch.object(e.acceptance,'captured_file',side_effect=read), \
                 patch.object(e,'source_tree',side_effect=copy), \
                 patch.object(e,'launcher_environment',side_effect=launch), \
                 patch.object(e.boundary,'create') as backend, patch.object(e,'pipeline') as producer:
                with e.runtime.cancellation_handlers() as state: report=e.execute(args,state)
            backend.assert_not_called(); producer.assert_not_called()
            self.assertEqual(report['status'],'FAIL');self.assertEqual(report['producer'],'NOT RUN')
            self.assertEqual(json.loads((args.output/'private/result.json').read_bytes()),report)
            self.assertEqual(set(reads),{180.0})
            if expire == 'capture':
                self.assertEqual(copies,[]);self.assertFalse((args.output/'private/source').exists())
                self.assertEqual(report['source_gate'],'source-capture')
            elif expire == 'copy':
                self.assertEqual(copies,[180.0]);self.assertFalse((args.output/'private/source').exists())
                self.assertEqual(report['source_gate'],'source-copy')
            else:
                self.assertEqual(copies,[180.0]);self.assertEqual(report['source_gate'],'private-launchers')
        finally:
            if args._private_fd is not None: os.close(args._private_fd)

    def test_actual_two_file_git_capture_expiry_stops_before_copy_or_backend(self): self.execute('capture')
    def test_actual_git_capture_cannot_copy_after_callers_expiry(self): self.execute('copy')
    def test_cold_capture_and_copy_pass_but_launcher_overrun_stops_backend(self): self.execute('launcher')

    def test_copy_and_verification_stop_after_bounded_io_crosses_cutoff(self):
        f=self.fixture
        with patch.object(e.time,'monotonic',side_effect=lambda:self.clock[0]): snapshot=f.capture(deadline=180.0)
        destination=f.base/'fresh';original_fsync=e.os.fsync;written=[]
        def fsync(fd):
            original_fsync(fd);written.append(fd);self.clock[0]=181.0
        with patch.object(e.time,'monotonic',side_effect=lambda:self.clock[0]), patch.object(e.os,'fsync',side_effect=fsync):
            with self.assertRaisesRegex(ValueError,'aggregate deadline'): e.source_tree(snapshot,destination,deadline=180.0)
        self.assertEqual(len(written),1)
        self.assertEqual(len([p for p in destination.rglob('*') if p.is_file()]),1)
        self.clock[0]=179.0;destination2=f.base/'verified';e.source_tree(snapshot,destination2)
        original_read=e.acceptance.captured_file;reads=[]
        def read(path,**kwargs):
            self.assertEqual(kwargs['deadline'],180.0);reads.append(path)
            result=original_read(path,**kwargs);self.clock[0]=181.0;return result
        with patch.object(e.time,'monotonic',side_effect=lambda:self.clock[0]),patch.object(e.acceptance,'captured_file',side_effect=read):
            with self.assertRaisesRegex(ValueError,'aggregate deadline'):e.check_source_tree(snapshot,destination2,deadline=180.0)
        self.assertEqual(len(reads),1)

class UnbufferedCopyTests(unittest.TestCase):
    def snapshot(self, data):
        return e.acceptance.Snapshot(Path('/unused'), {'tiny.py':data},
            {'files':{'tiny.py':{'mode':'0644'}}})

    def test_post_write_expiry_closes_without_deferred_source_write(self):
        data=b'BUFFERED SOURCE FIXTURE\n';clock=[179.0];events=[];real_write=e.os.write
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'source'
            def write(fd,chunk):
                events.append(('write-start',clock[0],e.os.fstat(fd).st_size))
                result=real_write(fd,chunk)
                events.append(('write-return',clock[0],e.os.fstat(fd).st_size))
                clock[0]=181.0
                return result
            with patch.object(e.time,'monotonic',side_effect=lambda:clock[0]), \
                 patch.object(e.os,'write',side_effect=write),patch.object(e.os,'fsync') as sync:
                with self.assertRaisesRegex(ValueError,'aggregate deadline'):
                    e.source_tree(self.snapshot(data),destination,deadline=180.0)
                sync.assert_not_called()
            self.assertEqual(events,[('write-start',179.0,0),('write-return',179.0,len(data))])
            self.assertEqual((destination/'tiny.py').read_bytes(),data)
            self.assertEqual(clock[0],181.0)

    def test_prewrite_expiry_does_not_queue_or_flush_bytes_on_close(self):
        data=b'BUFFERED SOURCE FIXTURE\n';clock=[179.0];real_chmod=e.os.fchmod
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'source'
            def chmod(fd,mode):
                real_chmod(fd,mode);clock[0]=181.0
            with patch.object(e.time,'monotonic',side_effect=lambda:clock[0]), \
                 patch.object(e.os,'fchmod',side_effect=chmod),patch.object(e.os,'write') as write, \
                 patch.object(e.os,'fsync') as sync:
                with self.assertRaisesRegex(ValueError,'aggregate deadline'):
                    e.source_tree(self.snapshot(data),destination,deadline=180.0)
                write.assert_not_called();sync.assert_not_called()
            self.assertEqual((destination/'tiny.py').stat().st_size,0)

    def test_short_writes_preserve_bytes_bound_chunks_and_refuse_no_progress(self):
        data=b'abc123'*12000;real_write=e.os.write;counts=[]
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            def short(fd,chunk):
                counts.append(len(chunk));return real_write(fd,chunk[:17])
            with patch.object(e.os,'write',side_effect=short):
                e.source_tree(self.snapshot(data),root/'short',deadline=time.monotonic()+30)
            self.assertEqual((root/'short/tiny.py').read_bytes(),data)
            self.assertGreater(len(counts),1);self.assertLessEqual(max(counts),65536)
            with patch.object(e.os,'write',return_value=0) as write:
                with self.assertRaisesRegex(ValueError,'source-copy-write-progress'):
                    e.source_tree(self.snapshot(data),root/'zero',deadline=time.monotonic()+30)
                self.assertEqual(write.call_count,1)
            self.assertEqual((root/'zero/tiny.py').stat().st_size,0)

if __name__ == '__main__':
    unittest.main()
