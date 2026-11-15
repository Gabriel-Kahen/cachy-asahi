# SPDX-License-Identifier: MIT
"""DATA/refusal controls only: never Docker, ALPM, GPG, Perl or package mutation."""
import importlib.util
import io
import copy
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('lifecycle_control_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


C, A, P = load('common'), load('actor'), load('producer')
DOMAIN = C.decode(C.read(HERE / 'domain.json'))


def admitted():
    return dict(schema=1, operation=C.OPERATION, run='root-test-r1', source_map_sha256='a'*64,
                image='sha256:'+'b'*64, base_labels={}, container='cachy-perl-lifecycle-root-test-r1',
                inputs='/root/qualified-inputs', test_fingerprint='C'*40,
                baseline_fingerprint='D'*40, root_qualification_sha256='e'*64)


class Controls(unittest.TestCase):
    def test_templates_refuse_authority(self):
        with self.assertRaises(ValueError):
            C.admission(C.decode(C.read(HERE / 'admission.TEMPLATE.json')), 'a'*64)

    def test_exact_admission_accepts_data_only(self):
        C.admission(admitted(), 'a'*64)

    def test_moving_image_refused(self):
        a = admitted(); a['image'] = 'archlinuxarm:latest'
        with self.assertRaises(ValueError): C.admission(a, 'a'*64)

    def test_build_domain_selector_refused(self):
        a = admitted(); a['operation'] = 'perl5423-native-namespace-v1'
        with self.assertRaises(ValueError): C.admission(a, 'a'*64)

    def test_production_signer_alias_refused(self):
        a = admitted(); a['test_fingerprint'] = a['baseline_fingerprint']
        with self.assertRaises(ValueError): C.admission(a, 'a'*64)

    def test_container_alias_refused(self):
        a = admitted(); a['container'] = 'some-other-running-container'
        with self.assertRaises(ValueError): C.admission(a, 'a'*64)

    def test_source_substitution_refused(self):
        with self.assertRaises(ValueError): C.admission(admitted(), 'f'*64)

    def test_duplicate_json_refused(self):
        with self.assertRaises(ValueError): C.decode(b'{"key":1,"key":2}')

    def test_nonfinite_json_refused(self):
        with self.assertRaises(ValueError): C.decode(b'{"key":NaN}')

    def test_single_link_operand(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'operand'; p.write_bytes(b'public-data')
            (Path(directory) / 'alias').hardlink_to(p)
            with self.assertRaises(ValueError): C.read(p)

    def test_symlink_operand(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'operand'; p.write_bytes(b'public-data')
            alias = Path(directory) / 'alias'; alias.symlink_to(p)
            with self.assertRaises(OSError): C.read(alias)

    def test_exact_source_map(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p/'data').write_bytes(b'input')
            raw = C.encode(dict(schema=1, operation=C.OPERATION, files={'data':C.pin(b'input')}))
            (p/'source-map.json').write_bytes(raw)
            self.assertEqual(C.source(p,C.pin(raw)['sha256'])['operation'],C.OPERATION)
            (p/'secret.asc').write_bytes(b'unsolicited signing material')
            with self.assertRaises(ValueError): C.source(p,C.pin(raw)['sha256'])

    def test_source_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p/'data').write_bytes(b'tampered')
            raw = C.encode(dict(schema=1, operation=C.OPERATION, files={'data':C.pin(b'input')}))
            (p/'source-map.json').write_bytes(raw)
            with self.assertRaises(ValueError): C.source(p,C.pin(raw)['sha256'])

    def test_full_inventory_preservation(self):
        rows = {'pkg-%03d'%n:'1-1' for n in range(348)}; rows['perl']='5.42.3-1'
        raw = ''.join(k+' '+rows[k]+'\n' for k in sorted(rows)).encode()
        self.assertEqual(C.inventory(raw),rows)
        with self.assertRaises(ValueError): C.inventory(raw.replace(b'perl 5.42.3-1',b'perl 5.42.2-2'))

    def test_inventory_addition_refused(self):
        raw = ''.join('pkg-%03d 1-1\n'%n for n in range(350)).encode()
        with self.assertRaises(ValueError): C.inventory(raw)

    def test_normal_alpm_install_timestamp_only(self):
        first = b'%NAME%\nperl\n\n%INSTALLDATE%\n1234\n\n%REASON%\n1\n'
        second = first.replace(b'1234', b'567890')
        self.assertEqual(A.normalize_desc(first)[0], A.normalize_desc(second)[0])
        self.assertNotEqual(A.normalize_desc(first)[0], A.normalize_desc(second.replace(b'%REASON%\n1', b'%REASON%\n0'))[0])

    def test_missing_db_date_refused(self):
        with self.assertRaises(ValueError): A.normalize_desc(b'%NAME%\nperl\n')

    def test_required_trust_without_hook_bypass(self):
        config = A.config('/work/trust')
        self.assertIn('LocalFileSigLevel = Required',config)
        self.assertIn('SigLevel = Required',config)
        self.assertNotIn('HookDir',config)
        self.assertNotIn('Never',config)

    def test_borrowed_trust_path_refused(self):
        with self.assertRaises(ValueError): A.config('/root/.gnupg')

    def test_exact_primary_signature(self):
        fp='F'*40
        raw=('[GNUPG:] VALIDSIG '+fp+' 2026-11-15 1 0 4 0 1 10 00 '+fp+'\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n').encode()
        A.signature(raw,fp)
        with self.assertRaises(ValueError): A.signature(raw,'E'*40)
        with self.assertRaises(ValueError): A.signature(raw+b'[GNUPG:] BADSIG key user\n',fp)

    def test_unknown_trust_refusal(self):
        fp='F'*40
        raw=('[GNUPG:] VALIDSIG '+fp+' 2026-11-15 1 0 4 0 1 10 00 '+fp+'\n[GNUPG:] TRUST_UNDEFINED 0 pgp\n').encode()
        with self.assertRaises(ValueError): A.signature(raw,fp)

    def test_missing_lifecycle_evidence_refused(self):
        self.assertFalse(C.natural(dict(returncode=0)))

    def test_forced_cleanup_never_success(self):
        row=dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
                 exit_observed_via_waitpid=True,ownership_lost=False,forced_cleanup=True,retirement='REAPED',exit=0)
        self.assertFalse(C.natural(row)); row['forced_cleanup']=False
        self.assertTrue(C.natural(row))

    def test_options_define_separate_root_domain(self):
        a=admitted(); argv=P.options(a,C.encode(a),'f'*64,DOMAIN)
        self.assertIn('--user=0:0',argv); self.assertIn('--network=none',argv)
        self.assertIn('--cap-add=SYS_CHROOT',argv)
        self.assertNotIn('--read-only',argv); self.assertNotIn('--privileged',argv)
        self.assertEqual(argv.count('--mount'),1)
        self.assertNotIn('/var/run/docker.sock',argv[argv.index('create'):])
        self.assertNotIn('-Rdd',argv); self.assertNotIn('--nodeps',argv)

    def test_inspect_refuses_extra_mount_and_capability(self):
        a=admitted(); sha='f'*64
        row=dict(Id='1'*64,Image=a['image'],Name='/'+a['container'],
            Config=dict(User='0:0',Hostname=DOMAIN['hostname'],Labels=P.labels(a,sha)),
            HostConfig=dict(NetworkMode='none',ReadonlyRootfs=False,Privileged=False,Init=True,
                Memory=DOMAIN['memory'],MemorySwap=DOMAIN['memory_swap'],NanoCpus=2*10**9,PidsLimit=128,
                CapDrop=['ALL'],CapAdd=DOMAIN['cap_add'],SecurityOpt=['no-new-privileges'],
                Tmpfs=DOMAIN['tmpfs'],IpcMode='private'),
            Mounts=[dict(Type='bind',Source=a['inputs'],Destination='/inputs',RW=False)])
        P.inspect(row,a,sha,DOMAIN,'1'*64)
        other=copy.deepcopy(row); other['Mounts'].append(dict(Type='bind',Source='/var/run/docker.sock',Destination='/socket',RW=True))
        with self.assertRaises(ValueError): P.inspect(other,a,sha,DOMAIN,'1'*64)
        other=copy.deepcopy(row); other['HostConfig']['CapAdd'].append('SYS_ADMIN')
        with self.assertRaises(ValueError): P.inspect(other,a,sha,DOMAIN,'1'*64)

    def test_reviewed_labelled_parent_and_collision_refusal(self):
        a=admitted(); a['base_labels']={'cachy-asahi.hosted-perl':'Root-owned', 'cachy-asahi.source':'old-baseline-source'}
        C.admission(a,'a'*64)
        image=dict(Id=a['image'],Architecture='arm64',Os='linux',Config=dict(Labels=a['base_labels']))
        P.image_identity(image,a)
        merged=P.labels(a,'f'*64)
        self.assertEqual(merged['cachy-asahi.source'],'old-baseline-source')
        self.assertEqual(merged['cachy-asahi.perl-lifecycle.source'],'a'*64)
        other=copy.deepcopy(image); other['Config']['Labels']['unreviewed']='addition'
        with self.assertRaises(ValueError): P.image_identity(other,a)
        a['base_labels']['cachy-asahi.perl-lifecycle.operation']='borrowed-authority'
        with self.assertRaises(ValueError): C.admission(a,'a'*64)

    def test_readonly_consumer_needs_original_external_hash(self):
        reader=load('read_result')
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory); (p/'producer-report.json').write_bytes(b'{}')
            raw=C.encode(dict(schema=1,operation=C.OPERATION,files={'data':C.pin(b'input')}))
            (p/'source-map.json').write_bytes(raw); (p/'data').write_bytes(b'input')
            # Keep source and evidence disjoint, as they are in real use.
            with tempfile.TemporaryDirectory() as evidence:
                (Path(evidence)/'producer-report.json').write_bytes(b'{}')
                (p/'producer-report.json').unlink()
                args=type('Args',(),dict(evidence=evidence,inputs=directory,
                    source_map_sha256=C.pin(raw)['sha256'],producer_report_sha256='0'*64))()
                with self.assertRaises(ValueError): reader.review(args)

    def test_untrusted_tar_export_never_extracts_paths(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            info=tarfile.TarInfo('result/../../escape'); info.size=1
            archive.addfile(info,io.BytesIO(b'x'))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): P.unpack(stream.getvalue(),Path(directory))

    def test_symlink_export_refused(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            info=tarfile.TarInfo('result/report.json'); info.type=tarfile.SYMTYPE; info.linkname='/etc/shadow'
            archive.addfile(info)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): P.unpack(stream.getvalue(),Path(directory))

    def test_owned_helper_exact_pin(self):
        self.assertTrue(callable(C.load('owned_child.py').run))

    def test_snapshot_detects_content_and_preserves_links_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory); (p/'ordinary').write_bytes(b'before'); (p/'link').symlink_to('/outside')
            before=A.snapshot(p); (p/'ordinary').write_bytes(b'after')
            self.assertEqual(before['link']['target'],'/outside')
            self.assertNotEqual(before['ordinary']['sha256'],A.snapshot(p)['ordinary']['sha256'])

    def test_wrong_runtime_refuses_before_mutation(self):
        if __import__('platform').machine() == 'aarch64' and __import__('os').getuid() == 0:
            self.skipTest('host refusal only; native root runtime is not probed by DATA controls')
        with self.assertRaises(ValueError): A.runtime(DOMAIN)


if __name__ == '__main__': unittest.main()
