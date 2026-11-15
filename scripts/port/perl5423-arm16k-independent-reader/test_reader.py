#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Source-local FICTION ONLY. No artifact code, credentials, actors or Root roles."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('fenced_perl16k_' + name, HERE / (name + '.py'))
    m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


R, J = load('reader'), load('joins')
NONCE, BASE_NONCE = 'a' * 32, 'b' * 32


def elf(dynamic=False):
    raw = bytearray(1024);raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 3, 183, 1);struct.pack_into('<Q', raw, 32, 64)
    struct.pack_into('<HH', raw, 54, 56, 2 if dynamic else 1)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 65536, 0, 1024, 1024, 65536)
    if dynamic:
        struct.pack_into('<IIQQQQQQ', raw, 120, 2, 6, 256, 65792, 0, 112, 112, 8)
        for i, (tag, value) in enumerate([(5, 66048), (10, 40), (1, 0), (0x6ffffffe, 66176), (0x6fffffff, 1), (0, 0)]):
            struct.pack_into('<qQ', raw, 256 + 16 * i, tag, value)
        raw[512:533] = b'libc.so.6\0GLIBC_2.17\0\0'
        struct.pack_into('<HHIII', raw, 640, 1, 1, 0, 16, 0)
        struct.pack_into('<IHHII', raw, 656, 0, 0, 2, 10, 0)
    return bytes(raw)


def outer(phase, status):
    lease = dict(identity=dict(bytes=0, dev=1, inode=7, mode=0o644, nlink=1, path='/FENCED/empty.lock'), acquiring_pid=71,
                 owner_starttime=2, proof=dict(inode=7, owner=71), same_FD=True,
                 original_owner_pidfd_alive=True, real_independent_NB_conflict=True, release='CLOSE_ONLY', fdinfo='FLOCK WRITE')
    return dict(status='PASS_OUTER_ONLY_NOT_RUNTIME_ACCEPTANCE', phase=phase, producer_report_status=status, Root_acceptance=None,
                initial_same_FD_PIDFD_NB=True, final_same_FD_PIDFD_NB=True, owned_children_reaped=True, owned_container_absent=True,
                close_only=True, live_HOME_guard_pass=True, signals=[], cleanup_errors=[], initial_lease=lease, final_lease=copy.deepcopy(lease),
                producer_retirement=dict(passed=True, reaped=True, group_absent=True, pid_reserved_until_retirement=True, exit=0,
                                         forced_retirement=False, timeout=False, error=None))


def report(phase, status):
    return dict(operation=J.OP, phase=phase, status=status, cleanup_errors=[], cleanup_ownership_verified=True,
                owned_container_removed=True, owned_container_absence_verified=True, Root_acceptance=None, VM_acceptance=None,
                container_id='c' * 64, docker_cli={'FICTION': 'NO_EXECUTABLE'})


def natural(argv):
    return dict(argv=argv, passed=True, reaped=True, output_complete=True, ownership='REAPED', exit=0,
                group_census='EMPTY_TWICE', signals=[], timeout=False, error=None)


def frame(fields, nonce, phase):
    prefix = 'TCG_LOGIN_' if phase == 'LOGIN' else 'PERL5423_' + phase + '_'
    return (prefix + 'BEGIN ' + nonce + '\n' + ''.join(k + '=' + v + '\n' for k, v in fields.items()) + prefix + 'END ' + nonce + '\n').encode()


def fixture():
    """Fabricated schema relationships, including 54 tiny non-executed ELF DATA."""
    source = {('guest/' + n): b'# FICTION ONLY\n' for n in ('root.sh', 'probe.sh', 'case.sh', 'official-trust.sh', 'runtime.pl', 'smoke.t')}
    source.update({'frozen/' + n: b'# FICTION ONLY\n' for n in ('rtc-clock.sh', 'guest-runtime.sh')})
    lock = R.digest(b'FICTION_SOURCE_LOCK')
    native = dict(issuer='Root', accepted=True, archive=J.ARCHIVE, status='ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY',
                  page_bytes=4096, raw_bytes_identical=True, payload_identical=True, authenticated_original_artifact=int(J.NATIVE['artifact']),
                  binding=dict(source=J.SOURCE['sha'], run=J.NATIVE['run'], job=J.NATIVE['job']), FICTION=True)
    inventory = dict(glibc='1', gdbm='1.26-2', libxcrypt='4.5.2-1', bzip2='1.0.8-6', zlib='1:1.3.2-3', **{'fenced' + str(i): '1' for i in range(106)})
    base = dict(kind='ROOT_ACCEPTED_ARM16K_PAM_BASELINE_V1', issued_by='Root', accepted=True, baseline_count=111,
                architecture='aarch64', page_bytes=16384, normal_PAM_logout_observed=True, owned_container_absence_verified=True,
                inventory=inventory, raw=dict(bytes=1610612736, sha256=R.digest(b'FICTION_UNREAD_RAW')['sha256']))
    dependency = dict(name='db5.3', version='5.3.28-7', full_ELF_coverage=True, elf_paths=['/usr/lib/libdb-5.3.so'])
    paths = sorted(['/usr/bin/perl', '/usr/lib/perl5/5.42/core_perl/CORE/libperl.so'] + ['/usr/lib/perl5/fenced' + str(i) + '.so' for i in range(52)])
    provider_owners = {'/usr/lib/libgdbm.so.6': 'gdbm', '/usr/lib/libcrypt.so.2': 'libxcrypt', '/usr/lib/libbz2.so.1.0': 'bzip2', '/usr/lib/libz.so.1': 'zlib'}
    providers = ['/usr/lib/libdb-5.3.so'] + list(provider_owners) + ['/usr/lib/fenced-provider' + str(i) + '.so' for i in range(22)]
    binary = elf();pin = R.digest(binary);files = {};elfs = {};rows = []
    for path in paths + providers:
        owner = 'perl' if path in paths else 'db5.3' if 'libdb-' in path else provider_owners.get(path, 'glibc')
        version = J.VERSION if owner == 'perl' else dependency['version'] if owner == 'db5.3' else inventory[owner]
        files[path] = dict(pin, owner=owner, version=version, resolved=path, mode=0o755)
        elfs[path] = dict(sha256=pin['sha256'], machine=183, **{'class': 64}, byte_order='little', static_16k_geometry=True,
                          needed=[], providers={}, version_needs={}, interpreter=None)
        rows.append(dict(expected_path=path, expected_member_bytes=pin['bytes'], expected_member_sha256=pin['sha256'], expected_package=owner, expected_package_version=version))
    rt = dict(kind='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1', issued_by='Root', accepted=True,
              baseline_certificate=R.digest(R.canonical(base)), Root_runtime_certificate=None, actual_guest_hashes=None,
              actual_guest_namespace=None, actual_guest_ALPM_ownership=None, runtime_acceptance=False, reverse_dependencies=[],
              rollback=dict(mode='REMOVE', local_database_policy='EXACT'), expected_payload=dict(kind='EXPECTED_PACKAGE_PAYLOAD_INPUTS_ONLY', rows=rows, aliases={},
              actual_guest_hashes=None, actual_guest_ownership=None, Root_runtime_certificate=None, runtime_acceptance=False),
              full_payload_elf_coverage=True, dependency_transaction=dependency, files=files, elfs=elfs,
              baseline_files={p: r for p, r in files.items() if r['owner'] in inventory},
              effective_hook_policy=dict(scriptlets_enabled=True, suppression_added=False, transaction_same_effective_policy=True),
              restoration_allowances=dict(pacman_log_before=None))
    dependencies = {'glibc': 'glibc', 'gdbm>=1.17': 'gdbm', 'db5.3': 'db5.3', 'libxcrypt': 'libxcrypt', 'libcrypt.so=2-64': 'libxcrypt', 'bzip2': 'bzip2', 'zlib': 'zlib'}
    rt['alpm_dependencies'] = list(dependencies)
    rt['dependency_resolution'] = {n: dict(satisfied=True, owner=owner, version=dependency['version'] if owner == 'db5.3' else inventory[owner], providers=[p for p in providers if files[p]['owner'] == owner]) for n, owner in dependencies.items()}
    binding = dict(source='445b37a9475a4e92804954f4f0e3d0ac84cd9511', run='43734696338', job='132874611601')
    installed = dict(issuer='Root', accepted=True, page_bytes=4096, archive=J.ARCHIVE, candidate_version=J.VERSION, binding=binding,
                     references=dict(accepted_native_pair=dict(R.digest(R.canonical(native)), path='/FENCED/decision.json')))
    installed_reader = dict(binding=binding, status='PASS_INDEPENDENT_RETAINED_OUTPUT_AND_PINNED_LIFECYCLE_DATA_ONLY', retention=dict(natural_owned_cleanup=True))
    resource = dict(issued_by='Root', accepted=True, baseline_certificate=R.digest(R.canonical(base)), package=J.ARCHIVE,
                    guest_output_cap_bytes=128*1024**2, logs_cap_bytes=64*1024**2, log_bytes=1024**2, prepared_raw_bytes=1610612736, cpus=2, guest_memory_bytes=2*1024**3, owner_memory_bytes=3*1024**3, pids=128)
    cert = dict(baseline_certificate=base, runtime_certificate=rt, resource_certificate=resource, installed_Reader=installed_reader, installed_component_decision=installed)
    case = dict(operation=J.OP, source=J.SOURCE, native=J.NATIVE, package=dict(name='perl', version=J.VERSION, arch='aarch64', archive=J.ARCHIVE),
                trust=dict(public_only=True, signature_valid=True, revoked=False, created_utc=1794700000, evaluated_utc=1794700001, expires_utc=1794900000, fingerprint='F' * 40),
                evidence={n: R.digest(R.canonical(v)) for n, v in cert.items()})
    cert['Root_decision'] = dict(kind='ROOT_ACCEPTED_PERL5423_INPUT_FOR_VM_V1', issued_by='Root', accepted=True, accepted_for_vm_input=True,
                                operation=J.OP, native=J.NATIVE, source=J.SOURCE, package=case['package'], package_signature_authenticated=True,
                                trust=case['trust'], evidence=copy.deepcopy(case['evidence']))
    case['evidence']['Root_decision'] = R.digest(R.canonical(cert['Root_decision']))
    data = {n + '.json': R.canonical(v) for n, v in cert.items()};data['case-inputs.json'] = R.canonical(case)
    data.update({n.split('/', 1)[1] if n.startswith('guest/') else n: v for n, v in source.items()})
    for n, inv in [('expected-base.lock', inventory), ('expected-dependencies.lock', dict(inventory, **{'db5.3': '5.3.28-7'})), ('expected-installed.lock', dict(inventory, **{'db5.3': '5.3.28-7', 'perl': J.VERSION}))]:
        data[n] = J.inv_bytes(inv)
    data['elf-paths.tsv'] = ''.join(str(i) + '.elf\t' + p + '\t' + pin['sha256'] + '\n' for i, p in enumerate(paths)).encode()
    data['source-lock-selection.json'] = R.canonical(lock)
    packet = dict(Source_lock=lock, nonce=NONCE, operation=J.OP, status='PREPARED_CASE_PACKET_NOT_INSTALLED_OR_BOOTED', actual=dict(VM=None), case=R.digest(data['case-inputs.json']))
    ctx = J.case_context(packet, data, source, lock, NONCE, R.parse, R.digest)
    ctx['native_pair_pin'] = R.digest(R.canonical(native))
    prepared = dict(status='PREPARED_NOT_BOOTED', operation=J.OP, packet=R.digest(R.canonical(packet)), nonce=NONCE,
                    baseline=base['raw'], raw=dict(bytes=1610612736, sha256=R.digest(b'FICTION_PREPARED_RAW')['sha256']), baseline_nonce=BASE_NONCE, VM=None, ALPM=None, Root_acceptance=None)
    observation = dict(status='OBSERVED_READONLY_BASELINE_ABI_PROVIDERS_MATCH_EXPECTED_INPUTS_ONLY', baseline_certificate=case['evidence']['baseline_certificate'],
                       raw=base['raw'], runtime_acceptance=False, Root_runtime_certificate=None, VM=None, crypto_verification=None, aliases={},
                       files={p: dict(bytes=r['bytes'], sha256=r['sha256'], owner=r['owner'], version=r['version'], mode=r['mode'], uid=0, gid=0) for p, r in rt['baseline_files'].items()})
    return ctx, packet, data, source, native, prepared, observation


def receipts(data):
    rows = {n: b'FENCED_PRESERVED_RECEIPT\n' for n in J.RECEIPTS}
    for n, expected in [('base.lock', 'expected-base.lock'), ('dependencies.lock', 'expected-dependencies.lock'), ('installed.lock', 'expected-installed.lock'), ('final.lock', 'expected-base.lock')]:rows[n] = data[expected]
    meta = b'/proc/\x0041ed\x000\x000\x002\x00quoted\x00'
    for stage in ('before', 'after'):
        rows[stage + '.meta'] = meta;rows[stage + '.meta-equality'] = J.metadata_view(meta)
    rows['pacman-log-before'] = b''
    rows['pacman-log-after'] = ''.join('[FENCED] [ALPM] ' + action + ' ' + name + ' (' + version + ')\n' for action, name, version in [('installed', 'db5.3', '5.3.28-7'), ('installed', 'perl', J.VERSION), ('removed', 'perl', J.VERSION), ('removed', 'db5.3', '5.3.28-7')]).encode()
    rows.update({n: token for n, token in [('install.log', b'perl'), ('remove.log', b'perl'), ('dependency-install.log', b'db5.3'), ('dependency-remove.log', b'db5.3')]})
    return rows


def boot_fixture():
    c, p, packet_data, _, _, prepared, _ = fixture();epoch = 1794800000
    session = dict(ARCH='aarch64', PAGESIZE='16384', UID='1000', USERNAME='builder', PID1='systemd', Name='builder', User='1000',
                   Class='user', Type='tty', Service='login', Remote='no', LOGIND='active', DBUS='active', Id='fenced', XDG_SESSION_ID='fenced', Leader='71', State='active')
    fields = dict(J.RESTORED, BASE_SHA256=R.digest(packet_data['expected-base.lock'])['sha256'], FINAL_SHA256=R.digest(packet_data['expected-base.lock'])['sha256'],
                  FUNCTIONAL_SHA256=R.digest(J.FUNCTIONAL)['sha256'], ELF_MANIFEST_SHA256=R.digest(packet_data['elf-paths.tsv'])['sha256'],
                  HOST_BOOT_UTC=str(epoch), GUEST_BEFORE_CRYPTO_UTC=str(epoch + 1), RTC_BEFORE_CRYPTO_UTC=str(epoch + 1))
    result = {str(i) + '.elf': elf() for i in range(54)}
    result.update({n: b'FENCED_COMMAND_DATA\n' for n in J.LOGS})
    result.update({'functional.log': J.FUNCTIONAL, 'version.log': b'v5.42.3\n', 'paths.log': b'/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n',
                   'json.log': b'{"answer":42}\n', 'sha.log': b'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  digest-input\n',
                   'corelist.log': b'5.42.3', 'perldoc.log': b'print', 'podtext.log': b'candidate document', 'podcheck.log': b'pod syntax OK', 'prove.log': b'Result: PASS', 'splain.log': b'undefined value'})
    pre = ''.join('\t'.join((r['expected_path'], str(r['expected_member_bytes']), r['expected_member_sha256'], r['expected_package'], r['expected_package_version'])) + '\n' for r in c['runtime']['expected_payload']['rows'] if r['expected_package'] in c['base']['inventory'])
    result['before-alpm-provider-observation.tsv'] = pre.encode()
    names = sorted(str(i) + '.elf' for i in range(54)) + sorted(J.LOGS) + ['before-alpm-provider-observation.tsv']
    result['outputs.sha256'] = ''.join(R.digest(result[n])['sha256'] + '  ' + n + '\n' for n in names).encode()
    result['summary.env'] = frame(fields, NONCE, 'RESTORED')
    preservation = dict(status='PASS_COMPLETE_BASELINE_AND_USER_PRESERVATION', packages=111, account_user_residuals=[], normal_install_date=None,
                        pacman_log='ABSENCE_RESTORED_WITH_RETAINED_NORMAL_TRANSACTION_LOG')
    r = report('boot', 'PASS_EMULATED_ARM16K_PERL5423_DATA_ONLY')
    r.update(normal_PAM_logout_observed=True, QMP_quit_requested=True, session=session, installed=J.INSTALLED, probe=J.PROBE, restored=fields, preservation=preservation)
    r['outputs'] = dict(status='PASS_DURABLE_PERL5423_DATA_ONLY', VM_acceptance=None, Root_acceptance=None, native_acceptance=False,
                        files={n: R.digest(raw) for n, raw in result.items()}, ELF16K={p: dict(machine=183, LOAD_segments=1, minimum_alignment=65536) for p in c['paths']})
    c.update(packet_pin=R.digest(R.canonical(p)), source_pin=p['Source_lock'], prepared_pin=R.digest(R.canonical(prepared)), boot_directory='/FENCED/boot',
             source_directory='/FENCED/source', packet_directory='/FENCED/packet', prepared_directory='/FENCED/prepared')
    auth = dict(kind='ROOT_PERL5423_VM_ACTOR_AUTHORITY_V1', issued_by='Root', accepted=True, operation=J.OP, phase='boot', packet=c['packet_pin'],
                source_lock=c['source_pin'], prepared=c['prepared_pin'], output=c['boot_directory'], docker_cli=r['docker_cli'], uid=1000,
                image='sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a')
    c['boot_authority'] = auth;c['boot_authority_pin'] = R.digest(R.canonical(auth))
    data = {'results/' + n: raw for n, raw in result.items()}
    data.update({'report.json': R.canonical(r), 'preservation.json': R.canonical(preservation), 'qemu.json': R.canonical(natural(J.qemu_argv(prepared, c['resource'], epoch))),
                 'qemu-argv.json': R.canonical(dict(argv=J.qemu_argv(prepared, c['resource'], epoch))), 'host-epoch.json': R.canonical(dict(nonce=NONCE, utc_ns=epoch * 10**9)),
                 'serial.redacted.log': frame(session, BASE_NONCE, 'LOGIN') + frame(J.INSTALLED, NONCE, 'INSTALLED') + frame(J.PROBE, NONCE, 'PROBE') + frame(fields, NONCE, 'RESTORED'),
                 'container.cid': r['container_id'].encode()})
    inspection = dict(Id=r['container_id'], State=dict(Running=False, ExitCode=0, OOMKilled=False), Image='sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a',
                      Config=dict(Labels={'org.cachy-asahi.perl5423-nonce': NONCE, 'org.cachy-asahi.perl5423-authority': c['boot_authority_pin']['sha256'], 'org.cachy-asahi.perl5423-owner': '1000'}, Entrypoint=['/usr/bin/python3'], Cmd=['-I', '-B', '/code/actor.py', 'boot']),
                      HostConfig=dict(ReadonlyRootfs=True, NetworkMode='none', CapDrop=['ALL'], CapAdd=[], Privileged=False, Devices=[], Init=False, SecurityOpt=['no-new-privileges'],
                                      Memory=c['resource']['owner_memory_bytes'], MemorySwap=c['resource']['owner_memory_bytes'], NanoCpus=2*10**9, PidsLimit=128),
                      Mounts=[dict(Destination=dst, Source=src, RW=rw) for dst, src, rw in [('/code', c['source_directory'], False), ('/packet', c['packet_directory'], False), ('/prepared', c['prepared_directory'], False), ('/work', c['boot_directory'], True)]])
    for i, (argv, stdout) in enumerate([(['docker', 'container', 'inspect', r['container_id']], R.canonical([inspection])),
                                         (['docker', 'container', 'rm', '--force', r['container_id']], r['container_id'].encode() + b'\n'),
                                         (['docker', 'container', 'ls'], b'')]):
        data['owned-docker-%06d.stdout' % i] = stdout;data['owned-docker-%06d.json' % i] = R.canonical(natural(argv))
    selected_receipts = receipts(packet_data)
    required, pairs, _ = J.export_receipt_names(c['runtime'])
    all_receipts = {n: selected_receipts.get(n, b'') for n in required}
    for pair in pairs:all_receipts[next(n for n in pair if n.endswith('.absent'))] = b''
    manifest = dict(schema=1, nonce=NONCE, case_packet=c['packet_pin'], Source_lock=c['source_pin'],
                    files={n: dict(R.digest(raw), mode=0o600) for n, raw in data.items() if n.startswith('results/')})
    manifest['files'].update({'receipts/' + n: dict(R.digest(raw), mode=0o600) for n, raw in all_receipts.items()})
    data['retained-data-manifest.json'] = R.canonical(manifest)
    preservation['retained_DATA'] = dict(manifest=R.digest(data['retained-data-manifest.json']), files=len(manifest['files']),
                                         bytes=sum(row['bytes'] for row in manifest['files'].values()), VM_acceptance=None, Root_acceptance=None)
    data['preservation.json'] = R.canonical(preservation);r['preservation'] = preservation;data['report.json'] = R.canonical(r)
    return c, p, packet_data, prepared, data, outer('boot', r['status'])


class Controls(unittest.TestCase):
    def test_cli_unissued_templates_refuse_without_creating_report(self):
        import sys
        with tempfile.TemporaryDirectory() as name:
            root = Path(name);output = root / 'not-created.json';argv = ['reader.py', '--execute-passive-reader', '--output', str(output)]
            for role in ('request', 'grant'):
                raw = (HERE / (role + '.TEMPLATE.json')).read_bytes();p = root / (role + '.json');p.write_bytes(raw);p.chmod(0o600)
                argv += ['--' + role, str(p), '--' + role + '-sha256', R.digest(raw)['sha256']]
            with patch.object(sys, 'argv', argv), patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000):
                with self.assertRaises(ValueError):R.main()
            self.assertFalse(output.exists())

    def test_controller_guest_bytes_are_never_imported_or_evaluated(self):
        _, p, data, source, _, _, _ = fixture()
        source['guest/root.sh'] = data['root.sh'] = b'raise RuntimeError("FICTION MUST NEVER EXECUTE")\n'
        context = J.case_context(p, data, source, p['Source_lock'], NONCE, R.parse, R.digest)
        self.assertEqual(len(context['paths']), 54)

    def test_complete_export_manifest_and_selected_receipts(self):
        c, p, packet, _, data, _ = boot_fixture()
        selection = {n: dict(R.digest(raw), mode=0o600) for n, raw in data.items()}
        J.retained_manifest(c, p, data, selection, R.parse, R.digest)
        selected = receipts(packet);rows = {n: dict(R.digest(raw), mode=0o600) for n, raw in selected.items()}
        J.selected_receipts(c, rows, selected, R.digest)

    def test_manifest_wrong_case_mode_count_or_unlisted_body_refuses(self):
        for kind in ('case', 'mode', 'count', 'body'):
            c, p, _, _, data, _ = boot_fixture();selection = {n: dict(R.digest(raw), mode=0o600) for n, raw in data.items()}
            value = R.parse(data['retained-data-manifest.json'])
            if kind == 'case':value['nonce'] = '0' * 32
            if kind == 'mode':value['files']['results/0.elf']['mode'] = 0o644
            if kind == 'count':del value['files']['receipts/final.lock']
            if kind == 'body':data['results/0.elf'] += b'CHANGED'
            if kind != 'body':data['retained-data-manifest.json'] = R.canonical(value)
            with self.assertRaises(ValueError):J.retained_manifest(c, p, data, selection, R.parse, R.digest)

    def test_whole_fiction_review_returns_missing_boot_hold_and_no_acceptance(self):
        c, packet, data, source, native, prepared, observed = fixture()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            def write_tree(directory, rows):
                directory.mkdir()
                for n, raw in rows.items():
                    p = directory / n;p.parent.mkdir(parents=True, exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
                return {n: dict(R.digest(raw), mode=0o644) for n, raw in rows.items()}
            source_lock = R.canonical(dict(kind='ARM16K_PERL5423_CASE_SOURCE_LOCK_V1', operation=J.OP, actual=dict(VM=None), files={n: dict(R.digest(raw), mode=0o644) for n, raw in source.items()}))
            source['source.lock.json'] = source_lock;write_tree(root / 'source', source)
            packet['Source_lock'] = R.digest(source_lock);data['source-lock-selection.json'] = R.canonical(R.digest(source_lock))
            packet['files'] = {n: dict(R.digest(raw), mode=0o644) for n, raw in data.items()}
            packet_raw = R.canonical(packet);data['case-packet.json'] = packet_raw;write_tree(root / 'packet', data)
            prepared['packet'] = R.digest(packet_raw)
            def operand(n, value):
                p = root / n;raw = R.canonical(value);p.write_bytes(raw);p.chmod(0o600)
                return dict(path=str(p), pin=R.digest(raw))
            request = dict(source=dict(directory=str(root / 'source'), lock=R.digest(source_lock)),
                           packet=dict(directory=str(root / 'packet'), pin=R.digest(packet_raw)), nonce=NONCE,
                           prepared=operand('prepared.json', prepared), prepare_report=operand('prepare-report.json', report('prepare', 'PREPARED_NOT_BOOTED')),
                           native_pair=operand('native.json', native), prepare_provider_observation=operand('providers.json', observed),
                           prepare_outer=operand('outer.json', outer('prepare', 'PREPARED_NOT_BOOTED')), boot=None, boot_outer=None, boot_authority=None, receipts=None)
            value = R.review(R.Inputs(), request)
            self.assertEqual(value['status'], 'HOLD_MISSING_BOOT_EVIDENCE');self.assertIsNone(value['runtime_acceptance']);self.assertIsNone(value['actual_installed_ELF'])

    def test_reader_closed_source_and_templates_remain_unissued(self):
        self.assertEqual(R.closed_reader(R.Inputs()), R.digest((HERE / 'source.lock.json').read_bytes()))
        grant = R.parse((HERE / 'grant.TEMPLATE.json').read_bytes())
        self.assertIsNone(grant['issued_by']);self.assertFalse(grant['allow_passive_read'])
        self.assertTrue(all(v is None for v in R.parse((HERE / 'request.TEMPLATE.json').read_bytes())['actual'].values()))

    def test_complete_fiction_boot_checks54_actual_byte_headers(self):
        c, p, packet, prepared, data, custody = boot_fixture()
        value = J.boot(c, p, packet, prepared, data, custody, R.parse, R.digest)
        self.assertEqual(len(value['actual_installed_ELF']), 54)
        self.assertEqual(value['preservation_scope'], 'HOST_SUMMARY_ONLY_UNTIL_SELECTED_RECEIPTS_JOIN')

    def test_missing_corrupt_or_unselected_installed_binary_refuses(self):
        for action in ('missing', 'corrupt', 'extra'):
            c, p, packet, prepared, data, custody = boot_fixture()
            if action == 'missing':del data['results/0.elf']
            if action == 'corrupt':data['results/0.elf'] += b'CHANGED'
            if action == 'extra':data['results/54.elf'] = elf()
            with self.assertRaises(ValueError):J.boot(c, p, packet, prepared, data, custody, R.parse, R.digest)

    def test_wrong_runtime_output_or_manifest_refuses(self):
        for name in ('functional.log', 'json.log', 'sha.log', 'paths.log', 'outputs.sha256'):
            c, p, packet, prepared, data, custody = boot_fixture();data['results/' + name] = b'FENCED_BAD_OUTPUT'
            with self.assertRaises(ValueError):J.boot(c, p, packet, prepared, data, custody, R.parse, R.digest)

    def test_qemu_acceleration_forced_exit_or_changed_nonce_refuses(self):
        for name in ('argv', 'exit', 'nonce'):
            c, p, packet, prepared, data, custody = boot_fixture()
            if name == 'argv':
                q = R.parse(data['qemu.json']);q['argv'][q['argv'].index('tcg,thread=multi')] = 'kvm';data['qemu.json'] = R.canonical(q)
            elif name == 'exit':
                q = R.parse(data['qemu.json']);q['signals'] = [9];data['qemu.json'] = R.canonical(q)
            else:data['serial.redacted.log'] = data['serial.redacted.log'].replace(NONCE.encode(), b'c' * 32)
            with self.assertRaises(ValueError):J.boot(c, p, packet, prepared, data, custody, R.parse, R.digest)

    def test_container_network_writable_source_wrong_cid_or_oom_refuses(self):
        for name in ('network', 'mount', 'cid', 'oom', 'authority'):
            c, p, packet, prepared, data, custody = boot_fixture();row = R.parse(data['owned-docker-000000.stdout'])[0]
            if name == 'network':row['HostConfig']['NetworkMode'] = 'host'
            if name == 'mount':row['Mounts'][0]['RW'] = True
            if name == 'cid':row['Id'] = 'd' * 64
            if name == 'oom':row['State']['OOMKilled'] = True
            if name == 'authority':row['Config']['Labels']['org.cachy-asahi.perl5423-authority'] = '0' * 64
            data['owned-docker-000000.stdout'] = R.canonical([row])
            with self.assertRaises(ValueError):J.boot(c, p, packet, prepared, data, custody, R.parse, R.digest)

    def test_fiction_complete_case_native_prepare_joins(self):
        c, p, _, _, native, prepared, observation = fixture()
        J.lineage(c, p, prepared['packet'], prepared, report('prepare', 'PREPARED_NOT_BOOTED'), native, observation, outer('prepare', 'PREPARED_NOT_BOOTED'), R.digest)

    def test_old_candidate_and_wrong_native_tuple_refuse(self):
        for key in ('version', 'archive'):
            _, p, data, source, _, _, _ = fixture();case = R.parse(data['case-inputs.json']);case['package'][key] = 'FICTION_WRONG'
            data['case-inputs.json'] = R.canonical(case);p['case'] = R.digest(data['case-inputs.json'])
            with self.assertRaises(ValueError):J.case_context(p, data, source, p['Source_lock'], NONCE, R.parse, R.digest)

    def test_packet_guest_code_is_data_and_must_match_source(self):
        _, p, data, source, _, _, _ = fixture();data['root.sh'] = b'FENCED_CHANGED_BODY'
        with self.assertRaises(ValueError):J.case_context(p, data, source, p['Source_lock'], NONCE, R.parse, R.digest)

    def test_provider_observation_requires_actual_hash_mode_and_owner(self):
        for field, value in [('sha256', '0' * 64), ('mode', 0o777), ('owner', 'FICTION_OTHER')]:
            c, p, _, _, native, prepared, observed = fixture();next(iter(observed['files'].values()))[field] = value
            with self.assertRaises(ValueError):J.lineage(c, p, prepared['packet'], prepared, report('prepare', 'PREPARED_NOT_BOOTED'), native, observed, outer('prepare', 'PREPARED_NOT_BOOTED'), R.digest)

    def test_installed_pair_reference_cannot_be_swapped(self):
        c, p, _, _, native, prepared, observed = fixture();c['native_pair_pin']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):J.lineage(c, p, prepared['packet'], prepared, report('prepare', 'PREPARED_NOT_BOOTED'), native, observed, outer('prepare', 'PREPARED_NOT_BOOTED'), R.digest)

    def test_expected_projection_cannot_claim_actual_runtime(self):
        _, p, data, source, _, _, _ = fixture();rt = R.parse(data['runtime_certificate.json']);rt['actual_guest_hashes'] = {};data['runtime_certificate.json'] = R.canonical(rt)
        with self.assertRaises(ValueError):J.case_context(p, data, source, p['Source_lock'], NONCE, R.parse, R.digest)

    def test_geometry_and_dynamic_gnu_requirements(self):
        self.assertEqual(J.elf(elf())['minimum_alignment'], 65536)
        parsed = J.elf(elf(True));self.assertEqual(parsed['needed'], ['libc.so.6']);self.assertEqual(parsed['version_needs'], {'libc.so.6': ['GLIBC_2.17']})

    def test_wrong_arch_page_alignment_and_truncation_refuse(self):
        for offset, value in [(18, 62), (64 + 48, 4096)]:
            raw = bytearray(elf());struct.pack_into('<H' if offset == 18 else '<Q', raw, offset, value)
            with self.assertRaises(ValueError):J.elf(bytes(raw))
        with self.assertRaises(ValueError):J.elf(elf()[:100])

    def test_dynamic_cycle_and_unmapped_address_refuse(self):
        for offset, fmt, value in [(640 + 12, '<I', 16), (256 + 8, '<Q', 1 << 63)]:
            raw = bytearray(elf(True));struct.pack_into(fmt, raw, offset, value)
            with self.assertRaises(ValueError):J.elf(bytes(raw))

    def test_phase_nonce_duplicate_and_field_injection_refuse(self):
        good = frame(J.PROBE, NONCE, 'PROBE');self.assertEqual(J.frame(good, NONCE, 'PROBE'), J.PROBE)
        for bad in (good + good, good.replace(b'UID=1000', b'UID=1000\nUID=0'), good.replace(NONCE.encode(), b'0' * 32)):
            with self.assertRaises(ValueError):J.frame(bad, NONCE, 'PROBE')

    def test_normal_custody_and_cleanup_fiction(self):
        J.custody(outer('boot', 'PASS'), 'boot', 'PASS')
        J.cleanup(report('boot', 'PASS'), 'boot', 'PASS')

    def test_custody_refuses_unlock_replaced_inode_signal_or_forced_retirement(self):
        for mutation in ('unlock', 'inode', 'signal', 'forced'):
            row = outer('boot', 'PASS')
            if mutation == 'unlock':row['close_only'] = False
            if mutation == 'inode':row['final_lease']['identity']['inode'] += 1
            if mutation == 'signal':row['signals'] = [15]
            if mutation == 'forced':row['producer_retirement']['forced_retirement'] = True
            with self.assertRaises(ValueError):J.custody(row, 'boot', 'PASS')

    def test_normal_selected_transaction_and_preservation_fiction(self):
        c, _, data, _, _, _, _ = fixture();r = receipts(data)
        proof = dict(normal_install_date=None, pacman_log='ABSENCE_RESTORED_WITH_RETAINED_NORMAL_TRANSACTION_LOG')
        self.assertEqual(J.restoration(c, data, r, proof, R.digest)['inventory_counts'], [111, 112, 113, 111])

    def test_unrelated_payload_user_db_or_inventory_change_refuses(self):
        for n in ('after.hash', 'after.db', 'user-current.hash', 'final.lock'):
            c, _, data, _, _, _, _ = fixture();r = receipts(data);r[n] += b'FENCED_CHANGE'
            with self.assertRaises(ValueError):J.restoration(c, data, r, {}, R.digest)

    def test_expanded_or_reordered_package_transactions_refuse(self):
        for changed in (b'[ALPM] installed other (1)\n', b'[ALPM] reinstalled perl (5.42.3-1.3)\n'):
            c, _, data, _, _, _, _ = fixture();r = receipts(data);r['pacman-log-after'] += changed
            with self.assertRaises(ValueError):J.restoration(c, data, r, {}, R.digest)

    def test_only_procfs_nlink_is_normalized(self):
        good = b'/proc/\x0041ed\x000\x000\x002\x00quoted\x00'
        self.assertEqual(J.metadata_view(good), J.metadata_view(good.replace(b'\x002\x00', b'\x0071\x00')))
        self.assertNotEqual(J.metadata_view(good), J.metadata_view(good.replace(b'41ed', b'41ff')))
        with self.assertRaises(ValueError):J.metadata_view(good + good)

    def test_exact_receipt_and_boot_whitelists(self):
        J.receipt_names({n: None for n in J.RECEIPTS})
        with self.assertRaises(ValueError):J.receipt_names({})
        for name in ('guest.raw', 'overlay.qcow2', 'credentials.json', '../outside'):
            with self.assertRaises(ValueError):J.boot_names({n: None for n in J.BOOT_REQUIRED | {name}})

    def test_parser_rejects_duplicate_nonfinite_json(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):R.parse(raw)

    def test_regular_singlelink_alias_and_mutation_guards(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name);p = root / 'data.json';p.write_bytes(b'{}');p.chmod(0o600);inputs = R.Inputs();inputs.read(p)
            p.write_bytes(b'[]')
            with self.assertRaises(ValueError):inputs.recheck()
            alias = root / 'alias';alias.symlink_to(p)
            with self.assertRaises(ValueError):R.Inputs().read(alias)
            alias.unlink();os.link(p, alias)
            with self.assertRaises(ValueError):R.Inputs().read(p)

    def test_size_and_total_count_and_deadline_guards(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'data';p.write_bytes(b'1234');p.chmod(0o600)
            for flag in ('total', 'files', 'time'):
                inp = R.Inputs()
                if flag == 'total':inp.total = R.MAX_TOTAL
                if flag == 'files':inp.rows = {str(i): None for i in range(R.MAX_FILES)}
                if flag == 'time':inp.end = 0
                with self.assertRaises(ValueError):inp.read(p)

    def test_explicit_grant_refuses_unissued_template_before_review(self):
        request = {n: None for n in ('source', 'packet', 'prepared', 'prepare_report', 'prepare_provider_observation', 'native_pair', 'prepare_outer', 'boot_outer', 'boot_authority', 'boot', 'receipts')}
        request.update(schema=1, kind='PERL5423_ARM16K_PASSIVE_REQUEST_V1', operation=J.OP, nonce=NONCE, actual=dict(issued_by=None, decision_time=None, runtime_acceptance=None))
        raw = R.canonical(request);pin = R.digest(b'FENCED_READER')
        grant = dict(schema=1, kind='ROOT_PERL5423_ARM16K_PASSIVE_GRANT_V1', issued_by='Root', allow_passive_read=True,
                     operation=J.OP, request=R.digest(raw), reader_source=pin, uid=1000, created_utc=100, expires_utc=200,
                     output='/FENCED/report.json', controller_source_reviewed=True)
        R.authority(raw, request, grant, pin, Path('/FENCED/report.json'), 101, 1000)
        for field, wrong in [('issued_by', None), ('allow_passive_read', False), ('uid', 0), ('expires_utc', 100), ('reader_source', {})]:
            bad = dict(grant, **{field: wrong})
            with self.assertRaises(ValueError):R.authority(raw, request, bad, pin, Path('/FENCED/report.json'), 101, 1000)


if __name__ == '__main__':
    unittest.main()
