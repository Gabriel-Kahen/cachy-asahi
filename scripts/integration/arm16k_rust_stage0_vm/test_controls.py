# SPDX-License-Identifier: MIT
"""FENCED DATA-only controls. No Root prepare/boot/compiler/daemon invocation."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location('fenced_rust16k_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


K,O,P,R,V,C=(load(n) for n in ('contracts','ownership','protocol','runtime','vm_actor','construct'))


def natural():
    return dict(passed=True,reaped=True,ownership='REAPED',exit=0,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,output=b'')


def result_fields(epoch):
    return dict(STATUS='PASS',ARCH='aarch64',PAGESIZE='16384',UID='1000',PREFIX=K.PREFIX,RUSTC_RELEASE='1.98.0',RUSTC_HOST='aarch64-unknown-linux-gnu',CARGO_VERSION='1.98.0',INVENTORY_BEFORE_SHA256='a'*64,INVENTORY_AFTER_SHA256='a'*64,OWNED_READABLE_BEFORE='PASS',OWNED_READABLE_AFTER='PASS',GUEST_SYNC='PASS',DIRECT_RUSTC='PASS',CARGO_OFFLINE='PASS',CORRECTNESS_RUNS='2',RTC_PRESENT='yes',RTC_DRIVER='pl031',RTC_HCTOSYS='1',HOST_BOOT_UTC=str(epoch),GUEST_BEFORE_CRYPTO_UTC=str(epoch+3),RTC_BEFORE_CRYPTO_UTC=str(epoch+3),RTC_CLOCK_ADVANCED='yes',CLOCK_SETTING='none')


class Controls(unittest.TestCase):
    def test_terminal_report_refuses_term_during_private_write(self):
        boot=load('boot');cancel=K.helper('reference_controller.py').Cancellation
        passed='PASS_EMULATED_ARM16K_RUST_STAGE0_FIXTURE_ONLY'
        original=Path.write_text
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);report=dict(status=passed,owned_container_absence_verified=True)
            state=cancel();state.cleaning=True
            def write(path,body):
                self.assertFalse((out/'report.json').exists())
                if json.loads(body)['status']==passed:signal.raise_signal(signal.SIGTERM)
                return original(path,body)
            with patch.object(Path,'write_text',write):
                state.__enter__()
                boot.publish_report(out,report,state)
            self.assertEqual(report['status'],'HOLD_CLEANUP_OR_CANCELLED')
            self.assertEqual(report['cancelled_signals'],[signal.SIGTERM])
            self.assertEqual(json.loads((out/'report.json').read_bytes()),report)
            self.assertEqual(list(out.iterdir()),[out/'report.json'])

    def test_templates_unbound_and_root_authority_refuses(self):
        a=K.load(HERE/'authority.TEMPLATE.json')
        self.assertIsNone(a['issued_by']);self.assertFalse(a['allow_prepare']);self.assertFalse(a['allow_boot'])
        for field in ('source_lock','kernel_bundle','qemu_metadata','stage0_data','guest_inputs','credentials','prepared','resource_review'):
            self.assertIsNone(a[field])
        self.assertTrue(all(v is None for v in a['public_source'].values()))
        with self.assertRaisesRegex(ValueError,'fresh Root'):
            K.authority(HERE/'authority.TEMPLATE.json',K.pin(HERE/'authority.TEMPLATE.json')['sha256'],'prepare',Path('/FENCED_NOT_PRESENT'))
        g=K.load(HERE/'guest-inputs.TEMPLATE.json');self.assertEqual(g['status'],'UNQUALIFIED')
        self.assertTrue(all(v is None for row in g['files'].values() for v in row.values()))

    def test_root_failure_precedes_input_clone_and_daemon_paths(self):
        args=SimpleNamespace(authority=Path('/FENCED'),authority_sha256='a'*64,publication=Path('/FENCED'))
        with patch.object(K.os,'getuid',return_value=1000),patch.object(K.os,'geteuid',return_value=1000),patch.object(K,'authority',side_effect=ValueError('FENCED missing Root')),patch.object(K,'baseline') as baseline,patch.object(K,'endpoint') as daemon:
            with self.assertRaisesRegex(ValueError,'missing Root'):K.preflight(args,'prepare')
            baseline.assert_not_called();daemon.assert_not_called()

    def test_exact_official_metadata_and_frozen_helper_bytes_only(self):
        s=load('stage0');spec=K.load(HERE/'data/stage0.json');facts=s.verify_specs(HERE/'data',spec)['summary']
        self.assertEqual((facts['nodes'],facts['files'],facts['file_bytes'],facts['elf_files']),(166,145,511504024,14))
        self.assertEqual(facts['compatibility'],'UNQUALIFIED')
        self.assertEqual(sum(row['bytes'] for row in spec['archives'].values()),108298076)
        origin=K.load(HERE/'origin.json')
        for name,row in origin['files'].items():self.assertEqual(K.pin(HERE/name),{k:row[k] for k in ('bytes','sha256')})

    def test_guest_resolver_keeps_absolute_links_inside_fenced_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'usr/lib').mkdir(parents=True);(root/'usr/lib/model').write_text('FENCED private DATA')
            (root/'lib').symlink_to('/usr/lib')
            name,p=O.resolve(root,'/lib/model');self.assertEqual(name,'/usr/lib/model');self.assertEqual(p.read_text(),'FENCED private DATA')
            (root/'usr/lib/loop').symlink_to('/usr/lib/loop')
            with self.assertRaisesRegex(ValueError,'cycle'):O.resolve(root,'/lib/loop')

    def test_all111_localdb_and_owned_bytes_are_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);expected={}
            for index in range(111):
                name='fenced'+str(index);expected[name]='1';directory=root/'var/lib/pacman/local'/(name+'-1');directory.mkdir(parents=True)
                (directory/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1\n')
                (directory/'files').write_text('%FILES%\nusr/bin/'+name+'\n')
                p=root/'usr/bin'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('FENCED_NOT_EXECUTABLE')
            before=O.namespace(root);owned=O.all_owned(root,expected,before);self.assertEqual(len(owned),111)
            (root/'usr/bin/fenced0').write_text('changed')
            self.assertNotEqual(O.all_owned(root,expected,O.namespace(root)),owned)
            (root/'var/lib/pacman/local/fenced0-1/files').write_text('%FILES%\nusr/bin/missing\n')
            with self.assertRaisesRegex(ValueError,'missing'):O.all_owned(root,expected,O.namespace(root))

    def test_readable_subset_avoids_root_private_and_inaccessible_paths(self):
        nodes={'etc':dict(kind='dir',mode=0o755),'root':dict(kind='dir',mode=0o700),
               'etc/public':dict(kind='file',mode=0o644),'etc/shadow':dict(kind='file',mode=0o600),
               'etc/link':dict(kind='link',mode=0o777),'root/secret':dict(kind='file',mode=0o644)}
        owned={k:v for k,v in nodes.items() if '/' in k}
        self.assertEqual(set(O.readable(owned,nodes)),{'etc/public','etc/link'})

    def test_postboot_full_owned_protected_and_prefix_are_independent_gates(self):
        original={'usr/bin/fenced':dict(kind='file',mode=0o755,bytes=1,sha256='a'*64)}
        protected={'etc/arm16k-systemd-nonce':dict(kind='file',mode=0o644,bytes=32,sha256='b'*64)}
        payload={'bin/rustc':dict(kind='file',mode=0o755,bytes=1,sha256='c'*64)}
        nodes={**original,**protected,K.PREFIX.lstrip('/')+'/bin/rustc':payload['bin/rustc']}
        baseline=dict(packages={'FENCED': '1'},owned=original,protected=protected)
        with patch.object(O,'namespace',return_value=nodes),patch.object(O,'all_owned',return_value=original):
            result=O.preservation(Path('/FENCED_NOT_PRESENT'),baseline,payload,K.PREFIX)
            self.assertTrue(result['all111_unchanged']);self.assertTrue(result['PAM_boot_unchanged'])
            for name in ('etc/arm16k-systemd-nonce',K.PREFIX.lstrip('/')+'/bin/rustc'):
                broken=dict(nodes);broken.pop(name)
                with patch.object(O,'namespace',return_value=broken),self.assertRaises(ValueError):
                    O.preservation(Path('/FENCED_NOT_PRESENT'),baseline,payload,K.PREFIX)
            with patch.object(O,'all_owned',return_value={}),self.assertRaisesRegex(ValueError,'all111'):
                O.preservation(Path('/FENCED_NOT_PRESENT'),baseline,payload,K.PREFIX)

    def test_postboot_proof_requires_bounded_journal_check_and_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp);inputs=work/'inputs';inputs.mkdir();(inputs/'ownership.json').write_text('{}')
            prepared=dict(ownership={},files={'guest.raw':{'bytes':4}},fixture_payload={},nonce='a'*32,source_lock={})
            contract=SimpleNamespace(checked=Mock(),load=Mock(return_value={}),need=K.need,RESOURCES=K.RESOURCES,PREFIX=K.PREFIX)
            calls=[]
            def command(argv,out,label,cap,deadline,**kw):
                calls.append((label,kw));self.assertEqual(deadline,123.0)
                if label=='postboot-convert':(work/'verification.raw').write_bytes(b'DATA')
                if label=='postboot-journal':return SimpleNamespace(returncode=0)
            runtime=SimpleNamespace(command=command,allocated=lambda p:0)
            owned=SimpleNamespace(preservation_nodes=Mock(return_value={'all111_unchanged':True}))
            reader=SimpleNamespace(scan=Mock(return_value=dict(nodes={},records={},profile={'reader':'FENCED'})))
            with patch.object(V.shutil,'disk_usage',return_value=SimpleNamespace(free=3*K.GIB)):
                V.postboot(contract,runtime,owned,inputs,work,prepared,123.0,reader=reader)
            reader.scan.assert_called_once()
            self.assertEqual([x[0] for x in calls],['postboot-convert','postboot-journal','postboot-ext4-readonly'])
            self.assertTrue(all(x[1]['watched_tree'][1]==K.RESOURCES['boot_allocated_cap'] for x in calls))
            self.assertFalse((work/'verification.raw').exists());self.assertFalse((work/'verification-view').exists())
            self.assertEqual(json.loads((work/'postboot-preservation.json').read_text())['nonce'],prepared['nonce'])

    def test_private_prefix_additions_do_not_write_platform_paths(self):
        syntax=ast.parse((HERE/'prepare_image.py').read_text())
        # This source-level check protects the fixed debugfs writer boundary;
        # full runtime readback still remains unexecuted.
        code=(HERE/'prepare_image.py').read_text()
        self.assertIn("guest=K.PREFIX+'/'+name",code)
        self.assertNotIn("'rm '+",code)
        self.assertNotIn('openssl',code)
        self.assertNotIn('machine-id', ' '.join(n.value for n in ast.walk(syntax) if isinstance(n,ast.Constant) and isinstance(n.value,str)))

    def test_nonce_frames_and_wrong_page_version_inventory_refuse(self):
        epoch=1800000000;fields=result_fields(epoch);nonce='a'*32
        raw=('RUST_STAGE0_BEGIN '+nonce+'\n'+''.join(k+'='+v+'\n' for k,v in fields.items())+'RUST_STAGE0_END '+nonce+'\n').encode()
        self.assertEqual(P.validate(P.frame(raw,nonce),'a'*64,epoch,epoch+50),fields)
        for key,value in [('PAGESIZE','4096'),('CARGO_VERSION','0.99.0'),('OWNED_READABLE_AFTER','NOT_RUN'),('GUEST_SYNC','FAIL'),('CLOCK_SETTING','set'),('INVENTORY_AFTER_SHA256','b'*64)]:
            changed=dict(fields);changed[key]=value
            with self.assertRaises(ValueError):P.validate(changed,'a'*64,epoch,epoch+50)
        with self.assertRaises(ValueError):P.frame(raw+raw,nonce)
        with self.assertRaises(ValueError):P.frame(raw,'b'*32)

    def test_journey_preserves_baseline_nonce_and_logs_out_on_complete_fail(self):
        nonce,baseline='a'*32,'b'*32;f=result_fields(1800000000);f['STATUS']='FAIL'
        raw=('RUST_STAGE0_BEGIN '+nonce+'\n'+''.join(k+'='+v+'\n' for k,v in f.items())+'RUST_STAGE0_END '+nonce).encode()
        serial=SimpleNamespace(data=bytearray(raw),until=Mock(),send=Mock())
        parse=Mock(return_value={'ARCH':'aarch64','PAGESIZE':'16384'})
        result=P.journey(serial,'FENCED_PASSWORD_NOT_REAL',baseline,nonce,parse)
        parse.assert_called_once_with(raw,baseline)
        sent=[c.args[0] for c in serial.send.call_args_list]
        self.assertIn(b'/usr/local/libexec/arm16k-login-proof\n',sent)
        self.assertEqual(sent[-1],b'exit\n');self.assertTrue(result['normal_PAM_logout_observed'])
        self.assertNotIn(b'arm16k-systemd-nonce',b''.join(sent))

    def test_qemu_fixed_software2cpu2g_rtc_and_two_nonces(self):
        args=V.qemu_argv({'nonce':'a'*32,'baseline_nonce':'b'*32},1800000000)
        for name,value in [('-smp','2'),('-m','2048'),('-accel','tcg,thread=multi'),('-rtc','base=utc,clock=host'),('-nic','none')]:self.assertEqual(args[args.index(name)+1],value)
        command=args[args.index('-append')+1]
        self.assertIn('arm16k_systemd_nonce='+'b'*32,command);self.assertIn('arm16k_rust_stage0_nonce='+'a'*32,command)
        self.assertNotIn('kvm',' '.join(args))
        self.assertEqual(K.RESOURCES['work_seconds']+K.RESOURCES['cleanup_seconds'],600)

    def test_runtime_natural_rejects_forced_unknown_or_cancelled(self):
        value=natural();value.pop('output');self.assertTrue(R.natural(value))
        for key,v in [('signals',['SIGTERM']),('reaped',False),('ownership','UNKNOWN'),('timeout',True),('command_cancelled',[2])]:
            changed=dict(value);changed[key]=v;self.assertFalse(R.natural(changed))

    def test_recorded_launch_cancellation_still_hands_child_to_frozen_supervisor(self):
        stub=SimpleNamespace(need=lambda ok,why:None if ok else (_ for _ in ()).throw(ValueError(why)))
        owned=SimpleNamespace(prepare=Mock(),supervise=Mock(return_value=natural()));stub.helper=lambda name:owned
        def spawn(*a,**kw):
            signal.getsignal(signal.SIGINT)(signal.SIGINT,None)
            return SimpleNamespace(pid=123456789)
        before=signal.getsignal(signal.SIGINT)
        with tempfile.TemporaryDirectory() as tmp,patch.object(R,'module',return_value=stub),patch.object(R.subprocess,'Popen',side_effect=spawn):
            with self.assertRaises(KeyboardInterrupt):R.command(['FENCED_NOT_EXECUTED'],Path(tmp),'cancel-model',seconds=5)
            owned.supervise.assert_called_once()
            self.assertEqual(signal.getsignal(signal.SIGINT),before)
            self.assertTrue(json.loads((Path(tmp)/'cancel-model.json').read_text())['command_cancelled'])

    def test_local_rootless_transport_is_explicit_and_restored(self):
        with patch.object(R,'module',return_value=SimpleNamespace(endpoint=lambda a:'unix:///FENCED.socket')),patch.dict(os.environ,{'DOCKER_HOST':'unix:///ORIGINAL.socket','DOCKER_CONTEXT':'ORIGINAL'}):
            with R.transport({}):self.assertEqual(os.environ['DOCKER_HOST'],'unix:///FENCED.socket');self.assertNotIn('DOCKER_CONTEXT',os.environ)
            self.assertEqual(os.environ['DOCKER_CONTEXT'],'ORIGINAL');self.assertEqual(os.environ['DOCKER_HOST'],'unix:///ORIGINAL.socket')

    def test_source_constructor_git_vectors_without_construction(self):
        self.assertEqual(C.git_tree({}),'4b825dc642cb6eb9a060e54bf8d69288fbee4904')
        self.assertEqual(C.git_tree({'x':(b'',0o644)}),hashlib.sha1(b'tree 29\0'+b'100644 x\0'+bytes.fromhex('e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')).hexdigest())
        with self.assertRaises(ValueError):C.git_tree({'../escape':(b'x',0o644)})


if __name__=='__main__':unittest.main()
