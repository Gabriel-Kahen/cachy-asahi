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
            runner = SimpleNamespace(run=run, deadline=time.monotonic()+8460, phase_scope=lambda end:nullcontext())
            report = {'phase': 'source'}
            with patch.object(e.current_cache,'prefill'), patch.object(e, 'check_source_tree'), patch.object(e,'baseline_observe'), self.assertRaises(ValueError):
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
                for target,name,value in ((e.current_cache,'prefill',lambda *a,**k:None),
                    (e,'check_source_tree',lambda *a,**k:None),
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


class ProducerRefusalTests(unittest.TestCase):
    def record(self, **changes):
        return {'schema_version':1,'last_source_gate':'GRAPH_LOAD','predicate':'producer-code-custody', **changes}

    def result(self, value=None, raw=None):
        return subprocess.CompletedProcess(['inert-source-fixture'],125,
            raw if raw is not None else e.REFUSAL_PREFIX + json.dumps(value or self.record()).encode() + b'\n')

    def observed(self):
        return {'started':True,'natural_poll_code':125,'runner_return_code':125,'reaped_code':125,
                'reaping':'COMPLETED','before_cleanup':{'state':'exited','returncode':125}}

    def test_fixed_source_enums_and_every_record_are_shared_without_driver_import(self):
        import ast
        tree=ast.parse((Path(e.__file__).with_name('producer_driver.py')).read_bytes())
        assignments={node.targets[0].id:node.value for node in tree.body
                     if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
        for name in ('REFUSAL_GATES','REFUSAL_PREDICATES'):
            self.assertEqual(frozenset(ast.literal_eval(assignments[name].args[0])),getattr(e,name))
        for gate in e.REFUSAL_GATES:
            for predicate in e.REFUSAL_PREDICATES:
                value=self.record(last_source_gate=gate,predicate=predicate)
                self.assertEqual(e.producer_refusal(self.result(value),self.observed()),value)

    def test_missing_nonnatural_and_bad_return_observations_never_adopt_a_leaf(self):
        for key in ('started','natural_poll_code','runner_return_code','reaped_code','reaping','before_cleanup'):
            row=self.observed();row.pop(key)
            self.assertIsNone(e.producer_refusal(self.result(),row))
        for code in (True,0,1,-15,None):
            result=self.result();result.returncode=code
            self.assertIsNone(e.producer_refusal(result,self.observed()))
        for field in ('natural_poll_code','runner_return_code','reaped_code'):
            row=self.observed();row[field]=True
            self.assertIsNone(e.producer_refusal(self.result(),row))
        class Foreign:
            @property
            def returncode(self): raise AssertionError('foreign getter invoked')
        class Derived(subprocess.CompletedProcess): pass
        self.assertIsNone(e.producer_refusal(Foreign(),self.observed()))
        self.assertIsNone(e.producer_refusal(Derived([],125,b''),self.observed()))

    def test_malformed_transport_keys_types_and_private_values_are_unknown(self):
        good=e.REFUSAL_PREFIX+json.dumps(self.record()).encode()+b'\n'
        for raw in (b'',good[:-1],good+good,b'private path only\n',
                    e.REFUSAL_PREFIX+b'{"schema_version":1,"schema_version":1}\n',
                    e.REFUSAL_PREFIX+b'{"schema_version":1e999}\n',
                    e.REFUSAL_PREFIX+b'\xff\n',e.REFUSAL_PREFIX+b' '*513+b'\n'):
            with self.subTest(raw=raw):self.assertIsNone(e.producer_refusal(self.result(raw=raw),self.observed()))
        for value in (self.record(schema_version=True),self.record(schema_version=2),
                      self.record(last_source_gate='/private/path'),self.record(predicate='private exception'),
                      self.record(extra='password'),self.record(predicate=[])):
            self.assertIsNone(e.producer_refusal(self.result(value),self.observed()))
        for raw in (b'ordinary private log\n'+good, good+b'ordinary private log\n'):
            self.assertEqual(e.producer_refusal(self.result(raw=raw),self.observed()),self.record())

    def test_observation_values_and_keys_never_invoke_foreign_equality(self):
        calls=[]
        class Foreign:
            def __eq__(self,other):calls.append(other);return True
            def __hash__(self):return hash('reaping')
        for slot in ('reaping','state'):
            row=self.observed()
            if slot=='state':row['before_cleanup']['state']=Foreign()
            else:row[slot]=Foreign()
            self.assertIsNone(e.producer_refusal(self.result(),row))
        for group in ('observation','before_cleanup','result'):
            row=self.observed();result=self.result()
            target=row if group=='observation' else row['before_cleanup'] if group=='before_cleanup' else result.__dict__
            target[Foreign()]=None;calls.clear()
            self.assertIsNone(e.producer_refusal(result,row));self.assertEqual(calls,[])
        self.assertEqual(calls,[])

    def test_pipeline_leaf_is_after_source_check_and_cannot_replace_business_failure(self):
        for fault in (None,ValueError('observer defect'),KeyboardInterrupt('observer control'),SystemExit(7)):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                private=Path(temporary);diagnostics=e.broker.Diagnostics()
                owner=SimpleNamespace(failed=False,diagnostics=diagnostics,
                    backend=SimpleNamespace(runner=SimpleNamespace(phase_scope=lambda end:nullcontext())),operation_deadline=None)
                report={};events=[];original=ValueError('existing producer refusal')
                def run(command,**options):
                    events.append('run');runner.observation.__dict__.update(self.observed())
                    return self.result()
                runner=SimpleNamespace(run=run,deadline=time.monotonic()+8460,phase_scope=lambda end:nullcontext(),observation=None)
                actual=e.producer_refusal
                def decode(*args):
                    events.append('decode')
                    if fault is not None:raise fault
                    return actual(*args)
                with patch.object(e.current_cache,'prefill'),patch.object(e,'baseline_observe'),patch.object(e,'journal_rows',return_value=[]),\
                     patch.object(e,'check_source_tree',side_effect=lambda *a,**k:events.append('source')),\
                     patch.object(e,'producer_refusal',side_effect=decode),\
                     patch.object(e.contracts,'validate_producer',side_effect=original),self.assertRaises(ValueError) as caught:
                    e.pipeline(SimpleNamespace(files={}),Path('/source'),private,owner,
                        SimpleNamespace(poll=lambda:None),runner,{}, {},report,SimpleNamespace(check=lambda:None))
                self.assertIs(caught.exception,original)
                self.assertLess(events.index('source'),events.index('decode'))
                self.assertEqual(report.get('producer_refusal'),self.record() if fault is None else None)
                self.assertEqual(report['producer_mutation'],'UNCERTAIN')
                self.assertEqual(report['producer_diagnostics']['producer']['runner_return_code'],125)


class ProducerObservationTests(unittest.TestCase):
    def test_existing_return_or_callback_exception_never_promotes_producer(self):
        for throws in (False,True):
            with tempfile.TemporaryDirectory() as temporary:
                private=Path(temporary);diagnostics=e.broker.Diagnostics();diagnostics.begin()
                owner=SimpleNamespace(failed=False,diagnostics=diagnostics,
                    backend=SimpleNamespace(runner=SimpleNamespace(phase_scope=lambda end:nullcontext())),operation_deadline=None)
                report={'phase':'source'};prior=object();commands=[]
                def run(command,**options):
                    commands.append((command,options))
                    if throws:raise BrokenPipeError('private RPC path')
                    return subprocess.CompletedProcess(command,7,b'private producer output')
                runner=SimpleNamespace(run=run,deadline=time.monotonic()+8460,phase_scope=lambda end:nullcontext(),observation=prior)
                with patch.object(e.current_cache,'prefill'),patch.object(e,'baseline_observe'),patch.object(e,'check_source_tree'),patch.object(e,'journal_rows',return_value=[]),\
                     patch.object(e.contracts,'validate_producer',side_effect=ValueError('unaccepted fixture')),\
                     self.assertRaises((BrokenPipeError,ValueError)):
                    e.pipeline(SimpleNamespace(files={}),Path('/source'),private,owner,
                        SimpleNamespace(poll=lambda:None),runner,{}, {},report,SimpleNamespace(check=lambda:None))
                self.assertIs(runner.observation,prior);self.assertEqual(len(commands),1)
                row=report['producer_diagnostics'];self.assertEqual(row['producer']['runner_return_code'],None if throws else 7)
                self.assertEqual(report['producer_mutation'],'UNCERTAIN');self.assertNotIn('private',json.dumps(row))
                if throws:self.assertEqual(row['rpc']['first_failure']['category'],'BrokenPipeError')

    def test_initial_projection_is_finite_unobserved_and_does_not_claim_cleanup(self):
        row=e.initial(SimpleNamespace(source_commit='a'*40,packet_sha256='b'*64))['producer_diagnostics']
        self.assertLessEqual(len(json.dumps(row).encode()),4096)
        self.assertEqual(row['schema_version'],2)
        self.assertEqual(row['producer']['before_cleanup'],{'state':'unavailable','returncode':None})
        self.assertIsNone(row['cleanup']);self.assertIsNone(row['producer']['runner_return_code'])
        self.assertFalse(row['producer']['started']);self.assertIsNone(row['rpc']['first_failure'])

    def test_failed_pipeline_keeps_precleanup_sample_separate_from_reaping(self):
        for sampled, reaped in (({'state':'alive','returncode':None},-15),
                                ({'state':'exited','returncode':1},1),
                                ({'state':'unavailable','returncode':None},1)):
            with self.subTest(sampled=sampled),tempfile.TemporaryDirectory() as temporary:
                diagnostics=e.broker.Diagnostics();diagnostics.begin();diagnostics.kind(['run'])
                original=BrokenPipeError('private caller output cannot establish its exception')
                diagnostics.failure('REPLY',original)
                owner=SimpleNamespace(failed=False,diagnostics=diagnostics,
                    backend=SimpleNamespace(runner=SimpleNamespace(phase_scope=lambda end:nullcontext())),
                    operation_deadline=None)
                prior=object();report={};calls=[]
                def run(command,**options):
                    calls.append(command)
                    observation=runner.observation
                    observation.started=True;observation.before_cleanup=dict(sampled)
                    observation.reaping='COMPLETED';observation.reaped_code=reaped
                    raise original
                runner=SimpleNamespace(run=run,deadline=time.monotonic()+8460,phase_scope=lambda end:nullcontext(),observation=prior)
                with patch.object(e.current_cache,'prefill'),patch.object(e,'baseline_observe'),self.assertRaises(BrokenPipeError) as caught:
                    e.pipeline(SimpleNamespace(files={}),Path('/source'),Path(temporary),owner,
                        SimpleNamespace(poll=lambda:None),runner,{}, {},report,SimpleNamespace(check=lambda:None))
                self.assertIs(caught.exception,original);self.assertIs(runner.observation,prior)
                self.assertEqual(len(calls),1);self.assertEqual(report['producer_mutation'],'UNCERTAIN')
                row=report['producer_diagnostics'];self.assertEqual(row['schema_version'],2)
                self.assertEqual(row['producer']['before_cleanup'],sampled)
                self.assertIsNone(row['producer']['natural_poll_code'])
                self.assertIsNone(row['producer']['runner_return_code'])
                self.assertEqual(row['producer']['reaped_code'],reaped)
                self.assertEqual(row['rpc']['first_failure']['stage'],'REPLY')
                self.assertEqual(row['rpc']['last_failure']['stage'],'PRODUCER')
                self.assertNotIn('private',json.dumps(row));self.assertIsNone(row['cleanup'])


class LifecycleDiagnosticTests(unittest.TestCase):
    def leaf(self):
        return {'schema_version':1,'source_commit':'a'*40,'run_id':'7','first_failure':
            {'selector':'LIFECYCLE','site':'WORKER_RESULT','check':'worker-phase-failed','category':'VALUE_ERROR'},
            'cleanup_failure':None,'cancelled':False,'attach_return':{'SIGN':0,'LIFECYCLE':1}}

    def observation(self, code=1):
        return {'started':True,'natural_poll_code':code,'runner_return_code':code,'reaped_code':code,
            'reaping':'COMPLETED','before_cleanup':{'state':'exited','returncode':code}}

    def result(self, leaf=None, code=1):
        if leaf is None: leaf=self.leaf()
        return subprocess.CompletedProcess(['/selected/lifecycle'],code,
            b'KSM_LIFECYCLE_DIAGNOSTIC_V1 '+json.dumps(leaf).encode()+b'\n',None)

    def parse(self, result=None, observation=None, binding=None):
        return e.lifecycle_diagnostic(self.result() if result is None else result,
            self.observation() if observation is None else observation,
            {'source_commit':'a'*40,'run_id':'7'} if binding is None else binding)

    def test_exact_bound_controller_leaf_accepts_coherent_natural_zero_or_nonzero_only(self):
        for code in (0,1,-15,255,-128):
            with self.subTest(code=code):
                self.assertEqual(self.parse(self.result(code=code),self.observation(code)),self.leaf())

    def test_process_observations_do_not_infer_natural_return_from_reaping(self):
        for key,value in (('started',False),('natural_poll_code',None),('runner_return_code',None),
                ('reaped_code',-15),('reaping','FAILED'),('before_cleanup',{'state':'alive','returncode':None}),
                ('before_cleanup',{'state':'exited','returncode':True}),('natural_poll_code',True)):
            with self.subTest(key=key,value=value):
                self.assertIsNone(self.parse(observation={**self.observation(),key:value}))
        self.assertIsNone(self.parse(result=self.result(code=True)))
        self.assertIsNone(self.parse(result=self.result(code=256),observation=self.observation(256)))
        self.assertIsNone(self.parse(observation={**self.observation(),'extra':1}))

    def test_parser_rejects_unknown_fields_enums_types_bindings_and_private_text(self):
        mutations=[lambda x:x.update(extra='PRIVATE SENTINEL'),lambda x:x.update(schema_version=True),
            lambda x:x.update(source_commit='b'*40),lambda x:x.update(run_id='8'),
            lambda x:x.update(cancelled=1),lambda x:x.update(attach_return={'SIGN':True,'LIFECYCLE':0}),
            lambda x:x.update(attach_return={'SIGN':0,'LIFECYCLE':256}),
            lambda x:x.update(attach_return={'SIGN':0}),lambda x:x.update(first_failure=[])]
        for key in ('selector','site','check','category'):
            mutations.append(lambda x,key=key:x['first_failure'].update({key:'PRIVATE SENTINEL'}))
            mutations.append(lambda x,key=key:x['first_failure'].update({key:1}))
        for mutate in mutations:
            leaf=self.leaf();mutate(leaf)
            with self.subTest(leaf=leaf):self.assertIsNone(self.parse(self.result(leaf)))
        self.assertIsNone(self.parse(binding={'source_commit':'a'*39,'run_id':'7'}))
        self.assertIsNone(self.parse(binding={'source_commit':'a'*40,'run_id':7}))
        self.assertIsNone(self.parse(binding={'source_commit':'a'*40,'run_id':'7'*21}))
        self.assertNotIn('PRIVATE',json.dumps(self.parse()))

    def test_duplicate_keys_tokens_truncation_utf8_nonfinite_and_byte_bounds_are_unavailable(self):
        good=self.result().stdout
        raws=(b'',b'no marker\n',good[:-1],b'x'+good,good+good,
            good.replace(b'"schema_version": 1',b'"schema_version": 1,"schema_version":1'),
            good.replace(b'"cancelled": false',b'"cancelled": NaN'),
            good.replace(b'"category": "VALUE_ERROR"',b'"category":"VALUE_ERROR","category":"UNKNOWN"'),
            e.LIFECYCLE_PREFIX+b'\xff\n',e.LIFECYCLE_PREFIX+b' '+b' '*16384+b'\n',
            b' '* (8*1024**2)+good)
        for raw in raws:
            with self.subTest(length=len(raw)):
                result=self.result();result.stdout=raw;self.assertIsNone(self.parse(result))
        raw=b'PRIVATE SENTINEL\n'+good+b'private output\n'
        result=self.result();result.stdout=raw
        self.assertEqual(self.parse(result),self.leaf())
        self.assertNotIn('PRIVATE',json.dumps(self.parse(result)))

    def test_exact_completed_process_and_observation_shape_required(self):
        class Foreign(subprocess.CompletedProcess):pass
        self.assertIsNone(self.parse(result=Foreign([],1,self.result().stdout)))
        result=self.result();result.extra='private';self.assertIsNone(self.parse(result))
        result=self.result();result.stdout=bytearray(result.stdout);self.assertIsNone(self.parse(result))
        self.assertIsNone(self.parse(observation={'started':True}))

    def test_optional_parser_does_not_swallow_cancel_or_keyboard_interrupt(self):
        for failure in (e.runtime.Cancelled(15),KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__),patch.object(e.json,'loads',side_effect=failure), \
                 self.assertRaises(type(failure)):
                self.parse()

    def interval_fixture(self, code=0, fault=None, previous='present', exit_error=None, grant_enter_error=None):
        leaf=self.leaf();result=self.result(leaf,code)
        calls=[];prior=object();runner=SimpleNamespace(deadline=time.monotonic()+8460)
        if previous=='present':runner.observation=prior
        runner.phase_scope=lambda end: nullcontext()
        class Grant:
            def __enter__(self):
                calls.append('grant-enter')
                if grant_enter_error:raise grant_enter_error
            def __exit__(self,*args):
                calls.append('grant-exit')
                if exit_error:raise exit_error
        runner.lifecycle_outputs=lambda *a:Grant()
        def run(command,**kwargs):
            calls.append(('run',command,kwargs));observation=runner.observation
            observation.started=True
            if fault:
                observation.before_cleanup={'state':'alive','returncode':None}
                observation.reaping='COMPLETED';observation.reaped_code=-15
                raise fault
            observation.natural_poll_code=code;observation.runner_return_code=code
            observation.reaping='COMPLETED';observation.reaped_code=code
            observation.before_cleanup={'state':'exited','returncode':code}
            return result
        runner.run=run
        owner=SimpleNamespace(backend=SimpleNamespace(cli_sha256='b'*64,socket_identity=(1,2)))
        producer={'image_id':'sha256:'+'c'*64,'runner_endpoint':'unix:///run/docker.sock',
            'sha256':{'runner.json':'d'*64,'bootstrap.json':'e'*64}}
        pair={'provenance_sha256':['f'*64,'1'*64]}
        binding={'source_commit':'a'*40,'run_id':'7','daemon_id':'daemon1234'}
        report={'lifecycle':'NOT RUN'}
        return runner,prior,owner,producer,pair,binding,report,calls

    def call_interval(self, fixture, *, grant_inputs=None, capture=None, decode=None, observe=None, command=None, allowance=None):
        runner,prior,owner,producer,pair,binding,report,calls=fixture
        with ExitStack() as stack:
            stack.enter_context(patch.object(e.consumer,'lifecycle_command',side_effect=command or (lambda *a:['/python','-B','/stage'])))
            if allowance is not None:stack.enter_context(patch.object(e,'allowance',side_effect=allowance))
            stack.enter_context(patch.object(e,'lifecycle_grant_inputs',side_effect=grant_inputs or (lambda *a:(None,None,None))))
            stack.enter_context(patch.object(e,'baseline_observe',side_effect=observe or (lambda *a:calls.append(a[1]))))
            captured=stack.enter_context(patch.object(e.contracts,'capture',side_effect=capture or (lambda *a:b'{}')))
            decoded=stack.enter_context(patch.object(e.contracts,'decode',side_effect=decode or (lambda *a:{})))
            try:
                return e.lifecycle_interval(Path('/source'),Path('/private'),owner,runner,binding,producer,pair,report)
            finally:
                calls.append(('captures',captured.call_count,decoded.call_count))

    def test_nonzero_controller_exposes_optional_diagnostic_before_clean_exit_without_capture(self):
        fixture=self.interval_fixture(code=1)
        with self.assertRaises(ValueError):self.call_interval(fixture)
        runner,prior,_,_,_,_,report,calls=fixture
        diagnostics=report['lifecycle_diagnostics']
        self.assertEqual(diagnostics['controller'],self.leaf())
        self.assertEqual(diagnostics['first_failure'],{'site':'CLEAN_EXIT','category':'VALUE_ERROR','check':'UNKNOWN'})
        self.assertEqual(report['lifecycle'],'NOT RUN');self.assertIs(runner.observation,prior)
        self.assertEqual(calls[-1],('captures',0,0))
        self.assertEqual(diagnostics['process'],self.observation(1))

    def test_successful_controller_preserves_gates_argument_order_and_restores_absent_attribute(self):
        fixture=self.interval_fixture(previous='absent');result,receipt,end=self.call_interval(fixture)
        runner,_,_,_,_,_,report,calls=fixture
        self.assertEqual(result.returncode,0);self.assertEqual(receipt,{})
        self.assertFalse(hasattr(runner,'observation'));self.assertIsNone(report['lifecycle_diagnostics']['first_failure'])
        self.assertEqual(report['lifecycle_diagnostics']['site'],'BASELINE_AFTER')
        self.assertEqual(report['lifecycle'],'NOT RUN');self.assertEqual(calls[-1],('captures',1,1))
        self.assertEqual(next(row[1] for row in calls if type(row) is tuple and row[0]=='run'),['/python','-I','-B','-S','/stage'])

    def test_runner_primary_precedes_grant_cleanup_exception_and_preserves_process_unknowns(self):
        original=ValueError('PRIVATE primary');cleanup=OSError('PRIVATE cleanup')
        fixture=self.interval_fixture(fault=original,exit_error=cleanup)
        with self.assertRaises(OSError) as caught:self.call_interval(fixture)
        self.assertIs(caught.exception,cleanup)
        runner,prior,_,_,_,_,report,calls=fixture;diagnostics=report['lifecycle_diagnostics']
        self.assertIs(runner.observation,prior)
        self.assertEqual(diagnostics['first_failure'],{'site':'RUNNER','category':'VALUE_ERROR','check':'UNKNOWN'})
        self.assertEqual(diagnostics['cleanup_failure'],{'site':'GRANT_EXIT','category':'OS_ERROR','check':'UNKNOWN'})
        self.assertIsNone(diagnostics['process']['natural_poll_code']);self.assertEqual(diagnostics['process']['reaped_code'],-15)
        self.assertEqual(diagnostics['process']['before_cleanup'],{'state':'alive','returncode':None})
        self.assertIsNone(diagnostics['controller']);self.assertNotIn('PRIVATE',json.dumps(diagnostics))
        self.assertEqual(calls[-1],('captures',0,0))

    def test_cancellation_is_separate_sticky_and_preserves_primary_under_context_cleanup(self):
        for fault,cleanup in ((e.runtime.Cancelled(15),OSError('cleanup')),(KeyboardInterrupt(),None),
                (ValueError('primary'),e.runtime.Cancelled(15))):
            fixture=self.interval_fixture(fault=fault,exit_error=cleanup)
            with self.subTest(fault=type(fault).__name__),self.assertRaises(type(cleanup or fault)):
                self.call_interval(fixture)
            runner,prior,_,_,_,_,report,_=fixture;diagnostics=report['lifecycle_diagnostics']
            self.assertTrue(diagnostics['cancelled']);self.assertIs(runner.observation,prior)
            expected='VALUE_ERROR' if isinstance(fault,ValueError) else ('CANCELLED' if isinstance(fault,e.runtime.Cancelled) else 'KEYBOARD_INTERRUPT')
            self.assertEqual(diagnostics['first_failure']['category'],expected)

    def test_prelaunch_grant_refusal_is_not_launch_and_input_scope_precedes_enter(self):
        for fault_site in ('inputs','enter'):
            fixture=self.interval_fixture(grant_enter_error=ValueError('private') if fault_site=='enter' else None)
            runner,prior,_,_,_,_,report,calls=fixture
            def fail(*args):raise ValueError('private')
            with self.subTest(site=fault_site),self.assertRaises(ValueError):
                self.call_interval(fixture,grant_inputs=fail if fault_site=='inputs' else None)
            diagnostics=report['lifecycle_diagnostics'];self.assertIs(runner.observation,prior)
            self.assertFalse(diagnostics['process']['started'])
            self.assertEqual(diagnostics['first_failure']['site'],'GRANT_INPUTS' if fault_site=='inputs' else 'GRANT_ENTER')
            self.assertFalse(any(type(row) is tuple and row[0]=='run' for row in calls))

    def test_capture_decode_and_after_baseline_refusals_are_separate_observed_sites(self):
        for site in ('CAPTURE','DECODE','BASELINE_AFTER'):
            fixture=self.interval_fixture()
            def fail(*args):raise ValueError('PRIVATE')
            def observe(*args):
                if args[1]=='after_lifecycle':raise ValueError('PRIVATE')
            with self.subTest(site=site),self.assertRaises(ValueError):
                self.call_interval(fixture,capture=fail if site=='CAPTURE' else None,
                    decode=fail if site=='DECODE' else None,observe=observe if site=='BASELINE_AFTER' else None)
            runner,prior,_,_,_,_,report,calls=fixture;diagnostics=report['lifecycle_diagnostics']
            self.assertEqual(diagnostics['first_failure']['site'],site)
            self.assertEqual(diagnostics['process'],self.observation(0));self.assertIs(runner.observation,prior)
            self.assertNotIn('PRIVATE',json.dumps(diagnostics));self.assertEqual(report['lifecycle'],'NOT RUN')

    def test_diagnostic_first_failure_never_rewrites_and_categories_are_closed(self):
        value=e.lifecycle_initial();e.lifecycle_failure(value,'CAPTURE',KeyError('private'))
        first=dict(value['first_failure']);e.lifecycle_failure(value,'RUNNER',e.runtime.Cancelled(15))
        self.assertEqual(value['first_failure'],first);self.assertTrue(value['cancelled'])
        for error,category in ((OSError('x'),'OS_ERROR'),(TypeError('x'),'TYPE_ERROR'),
                (subprocess.SubprocessError('x'),'SUBPROCESS_ERROR'),(RuntimeError('x'),'UNKNOWN')):
            value=e.lifecycle_initial();e.lifecycle_failure(value,'unsafe-private-site',error)
            self.assertEqual(value['first_failure'],{'site':'UNOBSERVED','category':category,'check':'UNKNOWN'})


    def test_unavailable_diagnostic_cannot_advance_nonzero_exit_or_promote_lifecycle(self):
        fixture=self.interval_fixture(code=1);runner,prior,_,_,_,_,report,calls=fixture
        run=runner.run
        def invalid(*args,**kwargs):
            returned=run(*args,**kwargs);returned.stdout=b'PRIVATE invalid marker\n';return returned
        runner.run=invalid
        with self.assertRaises(ValueError):self.call_interval(fixture)
        self.assertIsNone(report['lifecycle_diagnostics']['controller'])
        self.assertEqual(report['lifecycle'],'NOT RUN');self.assertEqual(calls[-1],('captures',0,0))
        self.assertIs(runner.observation,prior)

    def test_returned_child_diagnostic_survives_later_grant_disposal_error(self):
        error=OSError('PRIVATE cleanup');fixture=self.interval_fixture(code=1,exit_error=error)
        with self.assertRaises(OSError) as caught:self.call_interval(fixture)
        self.assertIs(caught.exception,error)
        runner,prior,_,_,_,_,report,calls=fixture
        self.assertEqual(report['lifecycle_diagnostics']['controller'],self.leaf())
        self.assertEqual(report['lifecycle_diagnostics']['process'],self.observation(1))
        self.assertEqual(report['lifecycle_diagnostics']['first_failure']['site'],'GRANT_EXIT')
        self.assertEqual(report['lifecycle_diagnostics']['cleanup_failure']['site'],'GRANT_EXIT')
        self.assertEqual(report['lifecycle'],'NOT RUN');self.assertIs(runner.observation,prior)
        self.assertEqual(calls[-1],('captures',0,0))

    def test_foreign_keys_cannot_execute_hash_or_equality_during_parser(self):
        calls=[]
        class Foreign:
            def __hash__(self):calls.append('hash');return hash('started')
            def __eq__(self,other):calls.append('eq');return False
        key=Foreign()
        for target in ('binding','observation','before','result'):
            observation=self.observation();binding={'source_commit':'a'*40,'run_id':'7'};result=self.result()
            selected={'binding':binding,'observation':observation,'before':observation['before_cleanup'],
                'result':result.__dict__}[target]
            selected[key]='PRIVATE';calls.clear()
            self.assertIsNone(self.parse(result,observation,binding));self.assertEqual(calls,[])

    def test_binding_command_allowance_and_baseline_before_have_prelaunch_sites(self):
        for site in ('BINDING','COMMAND','ALLOWANCE','BASELINE_BEFORE'):
            fixture=self.interval_fixture();runner,prior,_,_,_,binding,report,calls=fixture
            def fail(*args,**kwargs):raise ValueError('PRIVATE')
            if site=='BINDING':del binding['daemon_id']
            with self.subTest(site=site),self.assertRaises(KeyError if site=='BINDING' else ValueError):
                self.call_interval(fixture,command=fail if site=='COMMAND' else None,
                    allowance=fail if site=='ALLOWANCE' else None,observe=fail if site=='BASELINE_BEFORE' else None)
            diagnostics=report['lifecycle_diagnostics'];self.assertFalse(diagnostics['process']['started'])
            self.assertEqual(diagnostics['first_failure']['site'],site);self.assertIs(runner.observation,prior)
            self.assertFalse(any(type(row) is tuple and row[0]=='run' for row in calls))

    def test_grant_input_evaluation_stays_inside_existing_phase_scope(self):
        fixture=self.interval_fixture();runner=fixture[0];inside=[]
        class Phase:
            def __enter__(self):inside.append(True)
            def __exit__(self,*args):inside.pop()
        runner.phase_scope=lambda end:Phase()
        def inputs(*args):self.assertEqual(inside,[True]);return None,None,None
        self.call_interval(fixture,grant_inputs=inputs);self.assertEqual(inside,[])

    def test_parser_cancellation_after_return_stays_sticky_and_restores_observation(self):
        fixture=self.interval_fixture()
        with patch.object(e,'lifecycle_diagnostic',side_effect=e.runtime.Cancelled(15)), \
             self.assertRaises(e.runtime.Cancelled):self.call_interval(fixture)
        runner,prior,_,_,_,_,report,calls=fixture;diagnostics=report['lifecycle_diagnostics']
        self.assertIs(runner.observation,prior);self.assertTrue(diagnostics['cancelled'])
        self.assertEqual(diagnostics['process'],self.observation(0))
        self.assertEqual(diagnostics['first_failure']['category'],'CANCELLED')
        self.assertEqual(calls[-1],('captures',0,0))


    def test_phase_disposal_failure_is_distinct_from_natural_success_or_prior_grant_failure(self):
        for primary in (None,ValueError('PRIVATE primary')):
            cleanup=OSError('PRIVATE phase cleanup');fixture=self.interval_fixture(fault=primary)
            runner,prior,_,_,_,_,report,calls=fixture
            class Phase:
                def __enter__(self):return None
                def __exit__(self,*args):raise cleanup
            runner.phase_scope=lambda end:Phase()
            with self.subTest(primary=primary is not None),self.assertRaises(OSError) as caught:
                self.call_interval(fixture)
            self.assertIs(caught.exception,cleanup);self.assertIs(runner.observation,prior)
            diagnostics=report['lifecycle_diagnostics']
            self.assertEqual(diagnostics['first_failure']['site'],'RUNNER' if primary else 'PHASE_EXIT')
            self.assertEqual(diagnostics['cleanup_failure'],{'site':'PHASE_EXIT','category':'OS_ERROR','check':'UNKNOWN'})
            self.assertEqual(diagnostics['process']['natural_poll_code'],None if primary else 0)
            self.assertEqual(calls[-1],('captures',0,0));self.assertEqual(report['lifecycle'],'NOT RUN')

    def test_propagated_identical_body_exception_is_not_a_cleanup_failure(self):
        error=ValueError('PRIVATE');fixture=self.interval_fixture(fault=error,exit_error=error)
        with self.assertRaises(ValueError) as caught:self.call_interval(fixture)
        self.assertIs(caught.exception,error)
        diagnostics=fixture[6]['lifecycle_diagnostics']
        self.assertEqual(diagnostics['first_failure']['site'],'RUNNER')
        self.assertIsNone(diagnostics['cleanup_failure'])


    def test_ordinary_summary_or_parser_error_cannot_replace_business_result(self):
        for stage in ('summary','parser'):
            for code in (0,1):
                fixture=self.interval_fixture(code=code);runner,prior=fixture[:2];run=runner.run
                def fail():raise ValueError('PRIVATE observer')
                def fault(*args,**kwargs):
                    result=run(*args,**kwargs)
                    if stage=='summary':runner.observation.summary=fail
                    return result
                runner.run=fault
                with self.subTest(stage=stage,code=code),ExitStack() as stack:
                    if stage=='parser':stack.enter_context(patch.object(e,'lifecycle_diagnostic',side_effect=ValueError('PRIVATE parser')))
                    if code:
                        with self.assertRaises(ValueError) as caught:self.call_interval(fixture)
                        self.assertNotIn('PRIVATE',str(caught.exception))
                        self.assertEqual(fixture[6]['lifecycle_diagnostics']['first_failure']['site'],'CLEAN_EXIT')
                    else:
                        self.assertEqual(self.call_interval(fixture)[0].returncode,0)
                        self.assertIsNone(fixture[6]['lifecycle_diagnostics']['first_failure'])
                self.assertIs(runner.observation,prior)
                self.assertNotIn('PRIVATE',json.dumps(fixture[6]['lifecycle_diagnostics']))

    def test_summary_failure_during_primary_or_cancellation_always_restores_prior_observer(self):
        for summary_error in (ValueError('PRIVATE observer'),e.runtime.Cancelled(15)):
            primary=TypeError('PRIVATE primary');fixture=self.interval_fixture(fault=primary)
            runner,prior=fixture[:2];run=runner.run
            def fail():raise summary_error
            def fault(*args,**kwargs):
                try:return run(*args,**kwargs)
                finally:runner.observation.summary=fail
            runner.run=fault
            with self.subTest(summary=type(summary_error).__name__), \
                 self.assertRaises(TypeError) as caught:
                self.call_interval(fixture)
            self.assertIs(caught.exception,primary)
            self.assertIs(runner.observation,prior)
            diagnostics=fixture[6]['lifecycle_diagnostics']
            self.assertEqual(diagnostics['first_failure'],{'site':'RUNNER','category':'TYPE_ERROR','check':'UNKNOWN'})
            self.assertEqual(diagnostics['cancelled'],isinstance(summary_error,e.runtime.Cancelled))
            self.assertNotIn('PRIVATE',json.dumps(diagnostics))


    def test_pipeline_acceptance_refusal_is_observed_without_lifecycle_pass_or_public_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=Path(temporary);(private/'lifecycle').mkdir();(private/'lifecycle/receipt.json').write_bytes(b'{}')
            producer={'image_id':'sha256:'+'c'*64,'runner_endpoint':'unix:///run/docker.sock',
                'sha256':{'runner.json':'d'*64,'bootstrap.json':'e'*64}}
            pair={'package':{'filename':'fixture.pkg.tar.xz','sha256':'f'*64},'provenance_sha256':['a'*64,'b'*64]}
            runner=SimpleNamespace(deadline=time.monotonic()+8460,phase_scope=lambda end:nullcontext(),
                lifecycle_outputs=lambda *args:nullcontext(),run=lambda command,**kwargs:subprocess.CompletedProcess(command,0,b'{}',b''))
            owner=SimpleNamespace(failed=False,backend=SimpleNamespace(cli_sha256='c'*64,socket_identity=(1,2),runner=runner),
                operation_deadline=None,cleanup_end=runner.deadline-30,
                baseline=SimpleNamespace(protected=lambda:frozenset(),summary=lambda:{'preservation':'PASS'}))
            files={'packages/tools/cachy-asahi-ksmctl/'+name:b'fixture' for name in e.job.KSM_INPUTS}
            snapshot=SimpleNamespace(files=files,module=lambda *a,**k:SimpleNamespace())
            approved={name:e.job.sha(b'fixture') for name in e.job.KSM_INPUTS}
            map_sha=e.job.sha((json.dumps(approved,sort_keys=True,indent=2)+'\n').encode())
            report=e.initial(SimpleNamespace(source_commit='a'*40,packet_sha256='b'*64))
            original=ValueError('PRIVATE acceptance refusal')
            with ExitStack() as stack:
                for target,name,value in ((e.current_cache,'prefill',lambda *a,**k:None),
                        (e,'check_source_tree',lambda *a,**k:None),(e,'baseline_observe',lambda *a,**k:None),
                        (e,'journal_rows',lambda *a:[]),(e.contracts,'validate_producer',lambda *a,**k:producer),
                        (e.contracts,'validate_ksm_pair',lambda *a,**k:pair),
                        (e.consumer,'validate_comparison',lambda *a:None),
                        (e,'lifecycle_grant_inputs',lambda *a:(None,None,None)),
                        (e,'owned_cleanup',lambda *a:{'status':'PASS'})):
                    stack.enter_context(patch.object(target,name,side_effect=value))
                stack.enter_context(patch.object(e.job,'MAP_SHA',map_sha))
                stack.enter_context(patch.object(e.contracts,'public_acceptance',side_effect=original))
                export=stack.enter_context(patch.object(e.public,'export'))
                with self.assertRaises(ValueError) as caught:
                    e.pipeline(snapshot,Path('/source'),private,owner,SimpleNamespace(poll=lambda:None),runner,{},
                        {'source_commit':'a'*40,'run_id':'7','daemon_id':'daemon1234'},report,SimpleNamespace(check=lambda:None))
                self.assertIs(caught.exception,original);export.assert_not_called()
            self.assertEqual(report['lifecycle'],'NOT ACCEPTED');self.assertEqual(report['public_export'],'NOT RUN')
            self.assertEqual(report['lifecycle_diagnostics']['first_failure'],{'site':'ACCEPTANCE','category':'VALUE_ERROR','check':'UNKNOWN'})
            self.assertIsNone(report['lifecycle_diagnostics']['controller'])
            self.assertNotIn('PRIVATE',json.dumps(report['lifecycle_diagnostics']))


class LifecycleErrorPreservationTests(unittest.TestCase):
    def prepared(self, error):
        cause=RuntimeError('PRIVATE cause')
        try:raise error from cause
        except BaseException as primary:
            return primary,object.__getattribute__(primary,'args'),object.__getattribute__(primary,'__cause__'),object.__getattribute__(primary,'__traceback__')

    def run_context(self, primary, *, wrapped, suppression=False, cleanup=None, diagnostics=None):
        class Context:
            def __init__(self):self.received=None;self.events=[]
            def __enter__(self):self.events.append('enter');return self
            def __exit__(self,kind,error,traceback):
                self.received=(kind,error,traceback);self.events.append('exit')
                if cleanup is not None:raise cleanup
                return suppression
        context=Context();value=e.lifecycle_initial() if diagnostics is None else diagnostics
        selected=e._LifecycleScope(context,value,'PHASE_EXIT') if wrapped else context
        observed=None;returned=False
        try:
            with selected:
                if primary is not None:raise primary
            returned=True
        except BaseException as error:observed=error
        return context,value,observed,returned

    def assert_primary_held(self, context, prepared, observed, *, suppressed=False):
        primary,args,cause,tail=prepared
        self.assertEqual(context.events,['enter','exit'])
        self.assertIs(context.received[0],type(primary));self.assertIs(context.received[1],primary)
        self.assertIs(context.received[2].tb_next,tail)
        self.assertIs(object.__getattribute__(primary,'args'),args)
        self.assertIs(object.__getattribute__(primary,'__cause__'),cause)
        self.assertIs(observed,None if suppressed else primary)

    def test_hostile_primary_class_metadata_preserves_paired_original_exit_tuple_and_primary(self):
        touches=[];secondary=LookupError('PRIVATE secondary')
        class Hostile(ValueError):
            @property
            def __class__(self):touches.append(True);raise secondary
        for wrapped in (False,True):
            prepared=self.prepared(Hostile('PRIVATE primary'))
            context,diagnostics,observed,returned=self.run_context(prepared[0],wrapped=wrapped)
            self.assert_primary_held(context,prepared,observed);self.assertFalse(returned)
            if wrapped:self.assertEqual(diagnostics['first_failure']['category'],'VALUE_ERROR')
        self.assertEqual(touches,[])

    def test_spoofed_class_and_hostile_metaclass_hooks_are_not_classification_authority(self):
        touches=[]
        class Meta(type):
            def __getattribute__(cls,name):touches.append(('get',name));raise LookupError('PRIVATE meta')
            def __eq__(cls,other):touches.append(('eq',));raise LookupError('PRIVATE equality')
            def __hash__(cls):touches.append(('hash',));raise LookupError('PRIVATE hash')
            def __instancecheck__(cls,obj):touches.append(('instance',));raise LookupError('PRIVATE instance')
            def __subclasscheck__(cls,obj):touches.append(('subclass',));raise LookupError('PRIVATE subclass')
        class Genuine(ValueError,metaclass=Meta):pass
        class Spoof(RuntimeError):
            @property
            def __class__(self):touches.append(('spoof',));return e.runtime.Cancelled
        for error,category in ((Genuine('PRIVATE'),'VALUE_ERROR'),(Spoof('PRIVATE'),'UNKNOWN')):
            value=e.lifecycle_initial();e.lifecycle_failure(value,'RUNNER',error)
            self.assertEqual(value['first_failure']['category'],category);self.assertFalse(value['cancelled'])
        self.assertEqual(touches,[])

    def test_genuine_cancel_subclasses_remain_sticky_under_suppression_and_recorder_fault(self):
        touches=[]
        class Meta(type):
            def __getattribute__(cls,name):touches.append(name);raise LookupError('PRIVATE meta')
            def __eq__(cls,other):touches.append('eq');raise LookupError('PRIVATE equality')
        class Cancel(e.runtime.Cancelled,metaclass=Meta):
            @property
            def __class__(self):touches.append('class');raise LookupError('PRIVATE property')
        class Interrupt(KeyboardInterrupt,metaclass=Meta):pass
        for error in (Cancel(15),Interrupt('PRIVATE')):
            for recorder_fault in (False,True):
                prepared=self.prepared(error)
                with ExitStack() as stack:
                    if recorder_fault:stack.enter_context(patch.object(e,'lifecycle_failure',side_effect=LookupError('PRIVATE recorder')))
                    context,value,observed,returned=self.run_context(error,wrapped=True,suppression=True)
                self.assert_primary_held(context,prepared,observed,suppressed=True)
                self.assertTrue(returned);self.assertTrue(value['cancelled'])
        self.assertEqual(touches,[])

    def test_recorder_secondary_fault_cannot_skip_exit_or_replace_primary_and_cancellation_is_independent(self):
        for secondary in (LookupError('PRIVATE secondary'),KeyboardInterrupt('PRIVATE secondary'),e.runtime.Cancelled(15)):
            for suppress in (False,True):
                prepared=self.prepared(TypeError('PRIVATE primary'))
                with patch.object(e,'lifecycle_failure',side_effect=secondary):
                    context,value,observed,returned=self.run_context(prepared[0],wrapped=True,suppression=suppress)
                self.assert_primary_held(context,prepared,observed,suppressed=suppress)
                self.assertEqual(returned,suppress)
                self.assertEqual(value['cancelled'],type(secondary) is not LookupError)
                self.assertNotIn('PRIVATE',json.dumps(value))

    def test_record_construction_fault_preserves_first_error_and_cleanup_error_precedence(self):
        for wrapped in (False,True):
            for failed_record in (False,True):
                primary=self.prepared(ValueError('PRIVATE primary'));cleanup=self.prepared(OSError('PRIVATE cleanup'))
                with ExitStack() as stack:
                    if failed_record:stack.enter_context(patch.object(e,'lifecycle_failure_record',side_effect=LookupError('PRIVATE record')))
                    context,value,observed,returned=self.run_context(primary[0],wrapped=wrapped,cleanup=cleanup[0])
                self.assert_primary_held(context,primary,None,suppressed=True)
                self.assertIs(observed,cleanup[0]);self.assertFalse(returned)
                self.assertIs(object.__getattribute__(cleanup[0],'args'),cleanup[1])
                self.assertIs(object.__getattribute__(cleanup[0],'__cause__'),cleanup[2])
                trace=object.__getattribute__(cleanup[0],'__traceback__')
                while trace is not cleanup[3] and trace is not None:trace=trace.tb_next
                self.assertIs(trace,cleanup[3])
                if wrapped and not failed_record:
                    self.assertEqual(value['first_failure']['category'],'VALUE_ERROR')
                    self.assertEqual(value['cleanup_failure']['category'],'OS_ERROR')

    def test_foreign_site_and_diagnostic_tables_cannot_prevent_original_exit(self):
        touches=[]
        class Site(str):
            def __hash__(self):touches.append('hash');raise LookupError('PRIVATE site')
            def __eq__(self,other):touches.append('eq');raise LookupError('PRIVATE site')
        record=e.lifecycle_failure_record(Site('RUNNER'),ValueError('PRIVATE'))
        self.assertEqual(record['site'],'UNOBSERVED')
        class Table(dict):
            def __getitem__(self,key):touches.append('get');raise LookupError('PRIVATE table')
            def __setitem__(self,key,value):touches.append('set');raise LookupError('PRIVATE table')
        primary=self.prepared(ValueError('PRIVATE primary'))
        context,_,observed,_=self.run_context(primary[0],wrapped=True,diagnostics=Table(site='RUNNER'))
        self.assert_primary_held(context,primary,observed);self.assertEqual(touches,[])

    def test_snapshot_active_primary_is_held_while_no_primary_genuine_cancel_remains_operative(self):
        class Cancel(e.runtime.Cancelled):pass
        class Interrupt(KeyboardInterrupt):pass
        class Spoof(LookupError):
            @property
            def __class__(self):raise LookupError('PRIVATE class')
        for secondary in (LookupError('PRIVATE'),Spoof('PRIVATE'),Cancel(15),Interrupt('PRIVATE')):
            def summary():raise secondary
            for primary in (None,TypeError('PRIVATE primary'),Cancel(15)):
                value=e.lifecycle_initial();observed=None
                try:
                    if primary is None:e.lifecycle_snapshot(value,SimpleNamespace(summary=summary))
                    else:
                        try:raise primary
                        except BaseException:
                            e.lifecycle_snapshot(value,SimpleNamespace(summary=summary))
                            raise
                except BaseException as error:observed=error
                genuine=type(secondary) is Cancel or type(secondary) is Interrupt
                self.assertIs(observed,primary if primary is not None else secondary if genuine else None)
                self.assertEqual(value['cancelled'],genuine)

    def test_same_primary_recorder_fault_does_not_change_context_suppression(self):
        for suppress in (False,True):
            prepared=self.prepared(ValueError('PRIVATE primary'))
            with patch.object(e,'lifecycle_failure',side_effect=prepared[0]):
                context,value,observed,returned=self.run_context(prepared[0],wrapped=True,suppression=suppress)
            self.assert_primary_held(context,prepared,observed,suppressed=suppress)
            self.assertEqual(returned,suppress)

    def test_original_exit_nonboolean_return_is_forwarded_by_identity(self):
        sentinel=object();calls=[];error=ValueError('PRIVATE')
        class Context:
            def __enter__(self):return None
            def __exit__(self,*args):calls.append(args);return sentinel
        value=e.lifecycle_initial();trace=object()
        with patch.object(e,'lifecycle_failure',side_effect=LookupError('PRIVATE recorder')):
            result=e._LifecycleScope(Context(),value,'PHASE_EXIT').__exit__(ValueError,error,trace)
        self.assertIs(result,sentinel);self.assertEqual(len(calls),1)
        self.assertIs(calls[0][0],ValueError);self.assertIs(calls[0][1],error);self.assertIs(calls[0][2],trace)


    def test_real_mro_descriptor_ignores_hostile_metaclass_mro_property_for_genuine_cancel(self):
        touches=[]
        class Meta(type):
            @property
            def __mro__(cls):touches.append('mro-property');raise LookupError('PRIVATE mro')
        class Cancel(e.runtime.Cancelled,metaclass=Meta):pass
        class Interrupt(KeyboardInterrupt,metaclass=Meta):pass
        for error,category in ((Cancel(15),'CANCELLED'),(Interrupt('PRIVATE'),'KEYBOARD_INTERRUPT')):
            value=e.lifecycle_initial();e.lifecycle_failure(value,'RUNNER',error)
            self.assertTrue(value['cancelled']);self.assertEqual(value['first_failure']['category'],category)
            prepared=self.prepared(error)
            context,value,observed,returned=self.run_context(error,wrapped=True,suppression=True)
            self.assert_primary_held(context,prepared,observed,suppressed=True)
            self.assertTrue(returned);self.assertTrue(value['cancelled'])
        self.assertEqual(touches,[])

    def test_same_primary_recorder_mutation_restores_all_builtin_slots_before_context_exit(self):
        for suppress in (False,True):
            primary=self.prepared(ValueError('PRIVATE original'));original=primary[0]
            seen=[]
            def corrupt(*args,**kwargs):
                before=e.lifecycle_error_state(original);seen.append(before)
                for name,value in (('args',('PRIVATE mutated',)),('__cause__',TypeError('PRIVATE mutated cause')),
                        ('__context__',OSError('PRIVATE mutated context')),('__suppress_context__',False)):
                    BaseException.__dict__[name].__set__(original,value)
                raise original
            with patch.object(e,'lifecycle_failure',side_effect=corrupt):
                context,_,observed,returned=self.run_context(original,wrapped=True,suppression=suppress)
            self.assert_primary_held(context,primary,observed,suppressed=suppress)
            state=e.lifecycle_error_state(original)
            self.assertIs(state[0],primary[1]);self.assertIs(state[1],primary[2])
            self.assertIs(state[2],seen[0][2]);self.assertIs(state[3],context.received[2])
            self.assertIs(state[4],seen[0][4]);self.assertEqual(returned,suppress)

    def test_same_cleanup_recorder_fault_preserves_cleanup_object_and_traceback_chain(self):
        cleanup=self.prepared(OSError('PRIVATE cleanup'));observed_states=[]
        def recorder(diagnostics,site,error):
            if error is cleanup[0]:
                observed_states.append(e.lifecycle_error_state(error))
                BaseException.__dict__['args'].__set__(error,('PRIVATE changed',))
                raise error
        with patch.object(e,'lifecycle_failure',side_effect=recorder):
            context,_,observed,_=self.run_context(ValueError('PRIVATE primary'),wrapped=True,cleanup=cleanup[0])
        self.assertIs(observed,cleanup[0]);current=e.lifecycle_error_state(observed)
        self.assertIs(current[0],cleanup[1]);self.assertIs(current[1],cleanup[2])
        self.assertIs(current[2],observed_states[0][2])
        trace=current[3]
        while trace is not observed_states[0][3] and trace is not None:
            self.assertNotIn(trace.tb_frame.f_code.co_name,('recorder','_execute_mock_call'))
            trace=trace.tb_next
        self.assertIs(trace,observed_states[0][3])
        self.assertIs(current[4],observed_states[0][4]);self.assertEqual(context.events,['enter','exit'])

    def test_faulting_recorder_and_faulting_cancellation_fallback_still_delegate_original_exit(self):
        for suppress in (False,True):
            prepared=self.prepared(ValueError('PRIVATE primary'))
            with patch.object(e,'lifecycle_failure',side_effect=LookupError('PRIVATE recorder')), \
                 patch.object(e,'lifecycle_cancelled',side_effect=RuntimeError('PRIVATE fallback')):
                context,_,observed,returned=self.run_context(prepared[0],wrapped=True,suppression=suppress)
            self.assert_primary_held(context,prepared,observed,suppressed=suppress);self.assertEqual(returned,suppress)

    def test_snapshot_after_success_preserves_nonexception_baseexception_and_active_primary_identity(self):
        for secondary in (SystemExit(7),GeneratorExit('PRIVATE')):
            def summary():raise secondary
            value=e.lifecycle_initial()
            with self.assertRaises(type(secondary)) as caught:e.lifecycle_snapshot(value,SimpleNamespace(summary=summary))
            self.assertIs(caught.exception,secondary)
            primary=self.prepared(TypeError('PRIVATE primary'))
            try:
                try:raise primary[0]
                except TypeError:
                    before=e.lifecycle_error_state(primary[0])
                    e.lifecycle_snapshot(value,SimpleNamespace(summary=summary))
                    after=e.lifecycle_error_state(primary[0])
                    for left,right in zip(before,after):self.assertIs(left,right)
                    raise
            except BaseException as observed:self.assertIs(observed,primary[0])

    def test_snapshot_same_active_primary_raise_restores_metadata_without_optional_frames(self):
        primary=self.prepared(TypeError('PRIVATE primary'));value=e.lifecycle_initial()
        def summary():raise primary[0]
        try:
            try:raise primary[0]
            except TypeError:
                before=e.lifecycle_error_state(primary[0]);e.lifecycle_snapshot(value,SimpleNamespace(summary=summary))
                after=e.lifecycle_error_state(primary[0])
                for left,right in zip(before,after):self.assertIs(left,right)
                raise
        except BaseException as observed:self.assertIs(observed,primary[0])


if __name__ == '__main__':
    unittest.main()
