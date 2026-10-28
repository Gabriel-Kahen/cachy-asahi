# SPDX-License-Identifier: MIT
import copy
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import deps as d
import payload_vm as vm
import run as caller
import native_capture
import job

ROOT = Path(__file__).resolve().parents[3]


def elf(align=16384):
    raw = bytearray(128); raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 3, 183, 1)
    struct.pack_into('<Q', raw, 32, 64); struct.pack_into('<HH', raw, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0, len(raw), len(raw), align)
    return bytes(raw)


class Audio16KControls(unittest.TestCase):
    def test_public_seed_bytes_are_verified_before_execution(self):
        self.assertEqual(job.PUBLIC_SEED_COMMIT,'04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd')
        self.assertEqual(job.PUBLIC_SEED_PINS, {
            'seed.py':'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3',
            'index.json':'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'})
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);files={'seed.py':b'inert source','index.json':b'fixed index'}
            for name,raw in files.items():(root/name).write_bytes(raw)
            with patch.object(job,'PUBLIC_SEED_PINS',{name:d.sha(raw) for name,raw in files.items()}):
                self.assertEqual(len(job.verify_public_seed(root)['files']),2)
                (root/'index.json').write_bytes(b'drift')
                with self.assertRaises(ValueError):job.verify_public_seed(root)

    def test_public_seed_order_and_immutable_workflow_checkout(self):
        script=(d.HERE/'ci_sequence.sh').read_text()
        secret=script.index('"$task_dir/job.py" seed')
        verify=script.index('job.verify_public_seed(')
        public=script.index('"$task_public_inputs/seed.py" --cache "$task_owner/base/context/deps"')
        build=script.index('"$task_dir/job.py" build')
        self.assertTrue(secret < verify < public < build)
        workflow=(ROOT/'.github/workflows/native-arm-generic16k-audio-userspace.yml').read_text()
        self.assertIn('ref: '+job.PUBLIC_SEED_COMMIT,workflow)
        self.assertIn('path: retained-public-inputs',workflow)
        self.assertIn('"$GITHUB_WORKSPACE/retained-public-inputs"',workflow)

    def test_failed574_report_is_retained_before_owner_cleanup_without_waiving_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'base').mkdir();(root/'public').mkdir()
            report={'status':'FAILED','native_build':'NOT_RUN','packages':574,'acquired':1151,
                    'error_kind':'ValueError','failures':[{'filename':'one.pkg.tar.xz','kind':'HTTPError',
                    'http_status':404,'url':'https://example.invalid/private-url-not-selected'}]}
            (root/'base/report.json').write_text(json.dumps(report))
            (root/'build.log').write_bytes(b'x'*9000+b'fixed final diagnostic')
            def save(path,value):path.write_text(json.dumps(value))
            def cleanup(args,interrupted):
                (root/'base/report.json').unlink();(root/'base').rmdir();(root/'build.log').unlink()
                save(root/'public/result.json',{'status':'FAIL','owner_cleanup':{'bootstrap_retirement':'UNKNOWN'}})
                return 1
            owner=SimpleNamespace(phase=lambda _:None,cleanup=cleanup,save=save)
            code=job.bind(owner,ROOT).cleanup(SimpleNamespace(root=root),[])
            value=json.loads((root/'public/result.json').read_text())
            self.assertEqual(code,1);self.assertEqual(value['status'],'FAIL')
            self.assertEqual(value['owner_cleanup']['bootstrap_retirement'],'UNKNOWN')
            record=value['bootstrap_diagnostics'];self.assertEqual(record['report']['failures'][0]['http_status'],404)
            self.assertEqual(record['build_log']['tail_bytes'],8192)
            self.assertNotIn('private-url-not-selected',json.dumps(record))

    def test_bootstrap_diagnostic_refuses_oversize_and_malformed_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'base').mkdir();p=root/'base/report.json'
            for raw in (b'x'*(1024**2+1),json.dumps({'failures':'not-list'}).encode(),
                        json.dumps({'acquired':True,'failures':[]}).encode()):
                p.write_bytes(raw)
                self.assertEqual(job.bootstrap_diagnostics(root)['report']['status'],'REFUSED_BOUNDED_PROJECTION')

    def test_new_native_producer_uses_one_unchanged_host_compile_recipe(self):
        common = d.load(ROOT, 'scripts/ci/asahi-lsp-offline/container.py')
        commands = []
        fake = SimpleNamespace(HEADERS=common.HEADERS, FLAGS=common.FLAGS,
                               digest=lambda path: next(row[1] for row in common.HEADERS.values() if row[0] == path),
                               pkg_flags=lambda raw: ['-I/usr/include/lilv-0', '-llilv-0'],
                               command=lambda argv,name,seconds: commands.append((argv,name,seconds)) or b'flags')
        source, host, argv, headers = native_capture.compile_host(ROOT, fake)
        self.assertEqual(len([x for x in commands if x[1] == 'compile']), 1)
        self.assertEqual(argv[:1+len(common.FLAGS)], ['/usr/bin/gcc', *common.FLAGS])
        self.assertEqual(argv[-2:], ['-ldl', '-lm'])
        self.assertEqual(d.sha(source.read_bytes()), '8e17986c68bb7fdbee644026bbdce4045179e65a0d34d210622260654b9e72a7')
        self.assertEqual(host, Path('/tmp/offline/host'))

    def test_job_adapter_preserves_base_phases_and_image_owner_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root/'public').mkdir(); calls=[]
            def save(path, value):path.write_text(json.dumps(value))
            def cleanup(args, interrupted):
                calls.append('original image owner cleanup')
                save(root/'public/result.json', {'status':'PASS','owner_cleanup':{'image':'ABSENT'}})
                return 0
            owner=SimpleNamespace(phase=lambda args:calls.append(args.mode),cleanup=cleanup,save=save)
            job.bind(owner, ROOT).phase(SimpleNamespace(mode='build'))
            self.assertEqual(owner.cleanup(SimpleNamespace(root=root), []),0)
            value=json.loads((root/'public/result.json').read_text())
            self.assertEqual(calls,['build','original image owner cleanup'])
            self.assertEqual(value['owner_cleanup']['image'],'ABSENT')
            self.assertIn('16KiB',value['scope'])

    def test_job_failure_keeps_bounded_native_and_vm_receipts_without_accepting_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);public=root/'audio-public';public.mkdir()
            (public/'native.json').write_text(json.dumps({'status':'NATIVE_PAYLOAD_CAPTURED'}))
            (public/'vm.json').write_text(json.dumps({'status':'FAIL'}))
            (public/'result.json').write_text(json.dumps({'status':'FAIL'}))
            (public/'native-compile.tail.txt').write_bytes(b'bounded compiler failure')
            owner=SimpleNamespace(save=lambda path,value:path.write_text(json.dumps(value)))
            job.public_runtime(SimpleNamespace(root=root),root/'absent-kernel.json',owner,False)
            value=json.loads((root/'public/runtime.json').read_text())
            result=json.loads((root/'public/result.json').read_text())
            self.assertEqual(value['vm']['status'],'FAIL')
            self.assertEqual(value['log_tails']['native-compile.tail.txt']['sha256'],d.sha(b'bounded compiler failure'))
            self.assertEqual(result['status'],'FAIL')
            self.assertEqual(result['cases'],'NOT ACCEPTED')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=d.HERE)
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.generic = d.load(ROOT, 'scripts/virtual/generic16k/fixture.py')

    def test_no_execute_validates_sources_without_native_or_vm_actors(self):
        result = caller.run(SimpleNamespace(source_root=ROOT, execute=False))
        self.assertEqual(result['status'], 'SOURCE_VALIDATED_NOT_RUN')

    def test_native_command_preserves_owned574_isolation_and_adds_only_readonly_inputs(self):
        argv = caller.native_command(ROOT, 'sha256:'+'a'*64, 'cachy-asahi-lsp-offline-'+'b'*16,
                                     self.root/'bundles', self.root/'out', self.root/'lock', ROOT, self.root/'archives')
        for flag in ('--rm', '--pull=never', '--platform=linux/arm64', '--cap-drop=ALL',
                     '--read-only', '--network=none', '--security-opt=no-new-privileges'):
            self.assertIn(flag, argv)
        self.assertIn('/source/native_capture.py', argv)
        self.assertIn('type=bind,src='+str(ROOT)+',dst=/repo,readonly', argv)
        self.assertIn('type=bind,src='+str(self.root/'archives')+',dst=/accepted-archives,readonly', argv)

    def test_dependency_drift_refused_before_import(self):
        with patch.object(d, 'POLICY', {'dependencies': {'one.py': {'bytes': 5, 'sha256': d.sha(b'fixed')}}}):
            (self.root/'one.py').write_bytes(b'wrong')
            with self.assertRaises(ValueError): d.source(self.root, 'one.py')

    def test_structural_16k_accepts_arm64_and_refuses_4k(self):
        self.assertEqual(d.closed_elf(elf(), self.generic), (None, []))
        with self.assertRaises(ValueError): d.closed_elf(elf(4096), self.generic)

    def receipt(self, archive, files):
        return {'schema':1,'status':'NATIVE_PAYLOAD_CAPTURED','inventory_count':574,
                'inventory_before':d.POLICY['inventory_sha256'],'inventory_after':d.POLICY['inventory_sha256'],
                'August_rootfs_used':False,'host_source_sha256':d.POLICY['dependencies']['scripts/ci/asahi-rust-lv2-offline/host.c']['sha256'],
                'system_pins_observed':d.POLICY['runtime_system_pins'], 'files':files,
                'host_sha256':files['usr/bin/lv2-host']['sha256'],
                'payload_tar':{'bytes':archive.stat().st_size,'sha256':d.sha(archive.read_bytes())}}

    def test_payload_hash_member_types_and_same_image_receipt_are_mandatory(self):
        archive = self.root/'payload.tar'; data=elf()
        with tarfile.open(archive,'w') as stream:
            member=tarfile.TarInfo('usr/bin/lv2-host'); member.mode=0o755; member.size=len(data)
            stream.addfile(member,io.BytesIO(data))
        files={'usr/bin/lv2-host':{'bytes':len(data),'mode':0o755,'sha256':d.sha(data)}}
        receipt=self.receipt(archive,files)
        self.assertIn('usr/bin/lv2-host',vm.payload_files(archive,receipt,self.generic))
        for field,value in [('August_rootfs_used',True),('inventory_after','a'*64),('host_source_sha256','a'*64)]:
            wrong=copy.deepcopy(receipt);wrong[field]=value
            with self.assertRaises(ValueError):vm.payload_files(archive,wrong,self.generic)
        archive.write_bytes(archive.read_bytes()+b'changed')
        with self.assertRaises(ValueError):vm.payload_files(archive,receipt,self.generic)

    def test_payload_symlink_and_escape_cannot_enter_initramfs(self):
        for name,kind in [('usr/bin/lv2-host',tarfile.SYMTYPE),('../outside',tarfile.REGTYPE)]:
            archive=self.root/'bad.tar'
            with tarfile.open(archive,'w') as stream:
                member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc/passwd';stream.addfile(member)
            files={'usr/bin/lv2-host':{'bytes':0,'mode':0,'sha256':d.sha(b'')}}
            with self.assertRaises(ValueError):vm.payload_files(archive,self.receipt(archive,files),self.generic)

    def report_fixture(self):
        retained=json.loads((d.HERE/'test-data/runtime.json').read_text())
        files={}; loader={}
        for name,uri in [('bankstown','https://chadmed.au/bankstown'),('triforce-lv2','https://chadmed.au/triforce')]:
            names=[];paths=[]
            for row in retained['loader'][name]['loaded_libraries']:
                identity=row['identity'];basename=identity.split('/')[-1];names.append(basename)
                if identity.startswith('virtual/'):
                    paths.append(None)
                else:
                    path=('/usr/lib/'+identity.removeprefix('system/')) if identity.startswith('system/') else '/'+identity
                    paths.append(path);files[path.lstrip('/')]={'sha256':row['sha256']}
            loader[name]={'schema_version':1,'mode':'loader','status':'PASS','failure_class':None,
                          'selected_uris':[uri],'descriptor_count':1,'loaded_basenames':names,'loaded_paths':paths,
                          'audio_devices':'NOT USED','hardware':'NOT RUN','optimization_acceptance':'NOT RUN'}
        return {'files':files},loader,retained['processing']

    def uart(self,loader,processing,page='16384',nonce='a'*32):
        lines=['UNAME16K aarch64 7.1.13-generic16k-smoke','GETCONF16K '+page,
               'SMOKE16K: mmap,mprotect,file-offset PASS']
        for name in ('bankstown','triforce-lv2'):
            lines.append('AUDIO16K_REPORT '+name+' '+json.dumps(loader[name]))
        lines+=['AUDIO16K_REPORT processing '+json.dumps(processing),'AUDIO16K PASS '+nonce]
        return ('\n'.join(lines)+'\n').encode()

    def test_unchanged_strict_property_projection_accepts_inert_retained_grid_only_with_16k_proof(self):
        receipt,loader,processing=self.report_fixture();nonce='a'*32;release='7.1.13-generic16k-smoke'
        result=vm.reports(self.uart(loader,processing),0,nonce,release,receipt,ROOT)
        self.assertEqual((result['processing']['case_count'],result['processing']['instance_count']),(60,120))
        for page,code,n in [('4096',0,nonce),('16384',-9,nonce),('16384',0,'b'*32)]:
            with self.assertRaises(ValueError):vm.reports(self.uart(loader,processing,page),code,n,release,receipt,ROOT)

    def test_case_oracle_and_loader_closure_refusals_stay_strict(self):
        receipt,loader,processing=self.report_fixture();nonce='a'*32;release='7.1.13-generic16k-smoke'
        wrong=copy.deepcopy(processing);wrong['case_count']=59
        with self.assertRaises(Exception):vm.reports(self.uart(loader,wrong),0,nonce,release,receipt,ROOT)
        wrong=copy.deepcopy(processing)
        case=next(x for x in wrong['cases'] if x['fixture']=='bypass');case['max_oracle_error']=1
        with self.assertRaises(Exception):vm.reports(self.uart(loader,wrong),0,nonce,release,receipt,ROOT)
        wrong=copy.deepcopy(loader);wrong['bankstown']['loaded_paths'][0]='/outside/bankstown.so'
        with self.assertRaises(ValueError):vm.reports(self.uart(wrong,processing),0,nonce,release,receipt,ROOT)

    def test_guest_calls_only_fixed_existing_host_modes_and_no_devices(self):
        data=vm.script('a'*32,'7.1.13-generic16k-smoke')
        self.assertEqual(data.count(b'/usr/bin/lv2-host --loader'),2)
        self.assertEqual(data.count(b'/usr/bin/lv2-host --bundle /candidate'),1)
        self.assertNotIn(b'/dev/snd',data)
        with self.assertRaises(ValueError):vm.script('a'*32,'bad;name')


if __name__ == '__main__':unittest.main()
