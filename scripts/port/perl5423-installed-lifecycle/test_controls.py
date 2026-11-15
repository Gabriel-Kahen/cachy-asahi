# SPDX-License-Identifier: MIT
"""DATA/refusal controls only: never Docker, ALPM, GPG, Perl or package mutation."""
import importlib.util
import io
import copy
import contextlib
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('lifecycle_control_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


C, A, P, R = load('common'), load('actor'), load('producer'), load('read_result')
DOMAIN = C.decode(C.read(HERE / 'domain.json'))


def admitted():
    return dict(schema=1, operation=C.OPERATION, run='root-test-r1', source_map_sha256='a'*64,
                image='sha256:'+'b'*64, base_labels={}, container='cachy-perl-lifecycle-root-test-r1',
                inputs='/root/qualified-inputs', test_fingerprint='C'*40,
                baseline_fingerprint='D'*40, root_qualification_sha256='e'*64)


class Controls(unittest.TestCase):
    def removal_fixture(self):
        expected = {'pkg-%03d'%n:'1-1' for n in range(347)}
        expected.update(perl='5.42.3-1', autoconf='2.72-1')
        inventory = ''.join(name+' '+expected[name]+'\n' for name in sorted(expected)).encode()
        descriptor = b'%NAME%\nautoconf\n\n%VERSION%\n2.72-1\n\n%DEPENDS%\nperl>=5.42\nm4\n\n'
        relative = 'autoconf-2.72-1/desc'
        database = dict(raw={relative:dict(type='file', **C.pin(descriptor))}, normalized={}, perl_install_date='1')
        files = {'usr/bin/perl':dict(type='file', **C.pin(b'baseline interpreter'))}
        user = {'config':dict(type='file', uid=1001, **C.pin(b'user edit'))}
        home = {'.':dict(type='directory', uid=1001), '.perl5423-lifecycle/config':user['config']}
        original = dict(files=files, accounts={n:C.pin(n.encode()) for n in ('passwd','group','shadow','gshadow')},
                        trust={}, hooks={}, pacman_conf=C.pin(b'ordinary config'))
        before = dict(inventory=C.pin(inventory), database=C.pin(C.encode(database)),
            package_owned=C.pin(C.encode(files)), user_fixture=C.pin(C.encode(user)),
            alarm_home=C.pin(C.encode(home)), accounts=original['accounts'],
            trust=C.pin(C.encode({})), hooks=C.pin(C.encode({})), pacman_conf=original['pacman_conf'])
        diagnostic = (b'error: failed to prepare transaction (could not satisfy dependencies)\n'
                      b":: removing perl breaks dependency 'perl>=5.42' required by autoconf\n")
        natural = dict(natural_exit=True, group_absent=True, leader_held_until_group_inspection=True,
                       exit_observed_via_waitpid=True, ownership_lost=False, forced_cleanup=False,
                       retirement='REAPED', exit=1)
        steps = ['probe-baseline','inventory-before-removal-refusal','dependency-protected-removal',
                 'inventory-after-removal-refusal','trusted-upgrade']
        commands = [dict(step=name, argv=['/usr/bin/pacman','-Q'], expected=0, returncode=0,
                         success=True, lifecycle={**natural,'exit':0}) for name in steps]
        commands[2].update(argv=A.REMOVAL_ARGV[:], expected=1, returncode=1, lifecycle=natural)
        members = {'dependency-protected-removal.stdout':b'checking dependencies...\n',
                   'dependency-protected-removal.stderr':diagnostic,
                   'inventory-before-removal-refusal.stdout':inventory,
                   'inventory-after-removal-refusal.stdout':inventory}
        witnesses = A.removal_witnesses(b'',diagnostic,expected,database['raw'],lambda name:descriptor)
        actor = dict(commands=commands, original=original, baseline=dict(database=database,user=user),
            removal_refusal=dict(status='PASS_DEPENDENCY_PROTECTED_REMOVAL_REFUSAL',before=before,
                after=copy.deepcopy(before),witnesses=witnesses,alarm_home_before=home,
                alarm_home_after=copy.deepcopy(home),baseline_payload_verified_after_refusal=True,full_uninstall='NOT_RUN'))
        return actor, members, expected

    def test_normal_removal_argv_keeps_dependency_checks_and_trusted_config(self):
        self.assertEqual(A.REMOVAL_ARGV,
            ['/usr/bin/pacman','--config','/work/pacman.conf','--noconfirm','-R','perl'])
        self.assertFalse({'--nodeps','-Rdd','--force','--overwrite','--print'} & set(A.REMOVAL_ARGV))

    def test_removal_needs_specific_complete_dependency_diagnostic(self):
        actor, members, expected = self.removal_fixture()
        raw = members['dependency-protected-removal.stderr']
        self.assertEqual(A.removal_diagnostic(b'',raw,expected),
                         [dict(dependency='perl>=5.42',consumer='autoconf')])
        for bad in (b'error: database is locked\n', raw.split(b'::')[0],
                    raw.replace(b'autoconf',b'not-in-baseline'), raw.replace(b"'perl>=5.42'",b"'python'"),
                    raw + b":: removing perl breaks dependency 'python' required by autoconf\n"):
            with self.assertRaises(ValueError): A.removal_diagnostic(b'',bad,expected)

    def test_actor_dependency_witness_bound_to_baseline_db_and_declared_dependency(self):
        actor, members, expected = self.removal_fixture()
        witness = actor['removal_refusal']['witnesses'][0]
        db = actor['baseline']['database']['raw']; raw = witness['descriptor'].encode()
        for changed in (raw.replace(b'perl>=5.42',b'python'), raw.replace(b'2.72-1',b'2.71-1')):
            with self.assertRaises(ValueError):
                A.removal_witnesses(b'',members['dependency-protected-removal.stderr'],expected,db,lambda name:changed)

    def test_reader_binds_original_negative_before_upgrade(self):
        R.removal_refusal(*self.removal_fixture())

    def test_reader_refuses_bypass_success_forced_retirement_order_and_uninstall_credit(self):
        for changed in ('argv','exit','forced','order','payload','uninstall'):
            actor, members, expected = self.removal_fixture()
            row = actor['commands'][2]
            if changed == 'argv': row['argv'] = row['argv'] + ['--nodeps']
            elif changed == 'exit': row['returncode'] = row['lifecycle']['exit'] = 0
            elif changed == 'forced': row['lifecycle']['forced_cleanup'] = True
            elif changed == 'order': actor['commands'][2],actor['commands'][4] = actor['commands'][4],actor['commands'][2]
            elif changed == 'payload': actor['removal_refusal']['baseline_payload_verified_after_refusal'] = False
            else: actor['removal_refusal']['full_uninstall'] = 'PASS'
            with self.subTest(changed=changed), self.assertRaises(ValueError): R.removal_refusal(actor,members,expected)

    def test_reader_refuses_each_changed_preservation_scope(self):
        for key in ('inventory','database','package_owned','user_fixture','alarm_home','accounts','trust','hooks','pacman_conf'):
            actor, members, expected = self.removal_fixture()
            actor['removal_refusal']['after'][key] = {'changed':True}
            with self.subTest(key=key), self.assertRaises(ValueError): R.removal_refusal(actor,members,expected)

    def test_reader_requires_original_stream_diagnostic_and_all349_inventory(self):
        for changed in ('diagnostic','witness','inventory'):
            actor, members, expected = self.removal_fixture()
            if changed == 'diagnostic': members['dependency-protected-removal.stderr'] = b'unrelated failure'
            elif changed == 'witness': actor['removal_refusal']['witnesses'] = []
            else: members['inventory-after-removal-refusal.stdout'] = members['inventory-after-removal-refusal.stdout'].replace(b'perl 5.42.3-1',b'perl 5.42.3-1.3')
            with self.subTest(changed=changed), self.assertRaises(ValueError): R.removal_refusal(actor,members,expected)

    def test_reader_rejects_detached_descriptor_and_baseline_or_home_drift(self):
        for changed in ('descriptor','baseline_db','baseline_files','home'):
            actor, members, expected = self.removal_fixture()
            if changed == 'descriptor': actor['removal_refusal']['witnesses'][0]['descriptor'] += '\nchanged'
            elif changed == 'baseline_db': actor['baseline']['database']['extra'] = 'change'
            elif changed == 'baseline_files': actor['original']['files']['usr/bin/perl']['uid'] = 9
            else: actor['removal_refusal']['alarm_home_after']['.']['uid'] = 9
            with self.subTest(changed=changed), self.assertRaises(ValueError): R.removal_refusal(actor,members,expected)

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


if __name__ == '__main__':
    with contextlib.ExitStack() as stack:
        for module, names in ((subprocess,('Popen','run','check_output')),
                              (socket,('socket','create_connection')), (fcntl,('flock',)),
                              (os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','pidfd_open'))):
            for name in names:
                if hasattr(module,name):
                    stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
        unittest.main()
