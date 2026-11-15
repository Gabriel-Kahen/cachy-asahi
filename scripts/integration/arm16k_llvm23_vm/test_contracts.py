# SPDX-License-Identifier: MIT
"""MODELED certificates only: no actual Root facts, trust, package, or VM acceptance."""
import copy
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm23_vm_contract_controls', HERE / 'contracts.py')
K = importlib.util.module_from_spec(spec); spec.loader.exec_module(K)
def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'fcntl.flock'):
        raise RuntimeError('modeled DATA controls refuse operations: ' + event)
sys.addaudithook(fence)


def p(label, size=32):
    return dict(bytes=size, sha256=hashlib.sha256(('MODEL_ONLY_' + label).encode()).hexdigest())


def seal(c, base, runtime, resources, decision, report):
    c['evidence']['baseline_certificate'] = K.json_pin(base)
    for value in (runtime, resources):
        value['baseline_certificate'] = c['evidence']['baseline_certificate']
        value['package'] = c['package']['archive']
    for name, value in [('runtime_certificate', runtime), ('resource_certificate', resources), ('Reader4_report', report)]:
        c['evidence'][name] = K.json_pin(value)
    decision.update(source=copy.deepcopy(c['source']), native=copy.deepcopy(c['native']), package=copy.deepcopy(c['package']),
                    trust=copy.deepcopy(c['trust']), evidence={n: copy.deepcopy(c['evidence'][n]) for n in K.EVIDENCE if n != 'Root_decision'})
    c['evidence']['Root_decision'] = K.json_pin(decision)
    observed = {n: copy.deepcopy(c['package'][n] if n in K.MATERIALS else c['evidence'][n]) for n in K.MATERIALS + K.EVIDENCE}
    return c, observed, base, runtime, resources, decision, report


def modeled():
    """Synthetic eight-package baseline and tiny files; never actual qualification."""
    c = K.load(HERE / 'case.TEMPLATE.json')
    c['native'] = dict(run='101', job='102', artifact='103')
    for n, size in zip(K.MATERIALS, (100, 20, 30, 40)): c['package'][n] = p(n, size)
    now = int(time.time())
    c['trust'] = dict(fingerprint='A' * 40, created_utc=now-100, expires_utc=now+3600, evaluated_utc=now,
                      public_only=True, signature_valid=True, revoked=False)
    inv = {n: 'MODEL-1' for n in K.PACKAGE['depends']}; inv.update({'base-tools': 'MODEL-1', 'binutils': 'MODEL-1', 'linux-api-headers': 'MODEL-1'})
    base = dict(kind='ROOT_ACCEPTED_ARM16K_PAM_BASELINE_V1', issued_by='Root', accepted=True, architecture='aarch64', page_bytes=16384,
                raw=p('raw', 1024), prepared=p('prepared'), inventory=inv, ownership=p('ownership'), report=p('PAM-report'),
                normal_PAM_logout_observed=True, owned_container_absence_verified=True, baseline_count=len(inv))
    ns = {n: dict(kind='d', mode=0o755, uid=0, gid=0) for n in ('/opt', '/opt/cachy-asahi', K.PREFIX, K.PREFIX+'/bin')}
    for n in ('clang', 'ld.lld', 'llvm-config', 'llvm-ar'):
        ns[K.PREFIX+'/bin/'+n] = dict(kind='f', mode=0o755, uid=0, gid=0, **p(n))
    for n, target in [('clang++', 'clang'), ('llvm-ranlib', 'llvm-ar')]:
        ns[K.PREFIX+'/bin/'+n] = dict(kind='l', mode=0o777, uid=0, gid=0, link_target=target)
    ns[K.PREFIX+'/empty'] = dict(kind='f', mode=0o644, uid=0, gid=0, bytes=0, sha256=hashlib.sha256(b'').hexdigest())
    files = {}
    def file(path, owner='glibc', mode=0o644, size=32, resolved=None):
        row = p(path, size); row.update(mode=mode, owner=owner, version=inv[owner], resolved=resolved or path); files[path] = row
    tools = ['/usr/bin/'+n for n in K.TOOLS]
    for path in tools: file(path, 'base-tools', 0o755)
    loader = '/lib/ld-linux-aarch64.so.1'; file(loader, mode=0o755, resolved='/usr/lib/ld-linux-aarch64.so.1')
    crt = '/usr/lib/Scrt1.o'; file(crt)
    libc = '/usr/lib/libc.so.6'; file(libc)
    header = '/usr/include/empty-model.h'; file(header, size=0); files[header]['sha256'] = hashlib.sha256(b'').hexdigest()
    elfs = {}
    for path, row in ns.items():
        if row['kind'] == 'f' and path.startswith(K.PREFIX+'/bin/'):
            elfs[path] = dict(sha256=row['sha256'], **{'class': 64}, byte_order='little', machine=183, interpreter=loader,
                              needed=['libc.so.6'], version_needs={'libc.so.6': ['GLIBC_MODEL']},
                              providers={'libc.so.6': dict(path=libc, version_definitions=['GLIBC_MODEL'])}, static_16k_geometry=True)
    runtime = dict(kind='ROOT_REVIEWED_LLVM23_VM_RUNTIME_V1', issued_by='Root', accepted=True, baseline_certificate=None, package=None,
                   namespace_coverage='ALL_PACKAGE_OWNED_PATHS', candidate_namespace=ns, elf_inventory=p('full-ELF-inventory'),
                   full_payload_elf_coverage=True, elfs=elfs, files=files, tools=tools, crt=[crt], loader=loader, runtime=[libc],
                   gcc_driver_selection=dict(mode='EXPLICIT_COMPILER_RT', gcc_prefix=None, headers=[header], libraries=[libc], startfiles=[crt]),
                   dependency_versions={n: inv[n] for n in K.PACKAGE['depends']})
    resources = {n: 1 for n in K.LIMITS}
    resources.update(kind='ROOT_REVIEWED_LLVM23_VM_RESOURCES_V1', issued_by='Root', accepted=True, baseline_certificate=None, package=None,
        package_expanded_bytes=128, case_staging_bytes=512, fixture_source_bytes=128, baseline_raw_bytes=1024, baseline_allocated_bytes=256,
        prepared_raw_bytes=8192, guest_filesystem_free_bytes=4096, guest_output_cap_bytes=128, clone_allocated_cap_bytes=2048,
        overlay_cap_bytes=512, readback_allocated_cap_bytes=2048, logs_cap_bytes=1024, reserve_bytes=1024, physical_free_bytes=8192,
        quota_initial_headroom_bytes=8192, quota_live_reserve_bytes=1024, guest_memory_bytes=1024, owner_memory_bytes=4096,
        host_reserve_bytes=1024, host_MemAvailable_bytes=8192, cpus=2, pids=64, prepare_seconds=180, boot_seconds=400,
        cleanup_seconds=10, boot_overhead_seconds=10, output_device=1, host_uid=1000, gpg_seconds=5, install_seconds=10, probe_wait_seconds=200,
        remove_seconds=10, compile_seconds=20, run_seconds=10, sync_seconds=5, log_bytes=1024)
    resources['quota_guard'] = dict(issued_by='Root', method='READ_ONLY_Q_GETQUOTA', whole_actor=True, read_only=True, uid=1000, device=1,
        initial_headroom_bytes=8192, live_reserve_bytes=1024, on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
    decision = dict(kind='ROOT_ACCEPTED_LLVM23_NATIVE_INPUT_FOR_VM_V1', issued_by='Root', accepted=True, operation=K.OP,
                    accepted_for_vm_input=True, package_signature_authenticated=True)
    report = dict(status='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_PUBLISHED256_DATA_ONLY', source_tree=K.SOURCE['tree'], source_files=256,
                   verified_historical_inverse=[253, 251, 248], package=c['package']['archive'],
                   actual=dict(source=K.SOURCE['sha'], ref=K.SOURCE['ref'], **c['native']),
                   native_acceptance=False, Root_authentication=False, Root_acceptance=None)
    return seal(c, base, runtime, resources, decision, report)


def reseal(args):
    return seal(args[0], *args[2:])


class Controls(unittest.TestCase):
    def test_modeled_only_success_has_no_assumed_baseline_count_and_copies(self):
        args = modeled(); result = K.validate(*args)
        self.assertEqual(result, args[0]); self.assertIsNot(result, args[0]); self.assertEqual(args[2]['baseline_count'], 8)
        self.assertNotIn('gcc', args[2]['inventory'])

    def test_unissued_template_and_all_nine_null_pins_refuse(self):
        with self.assertRaises(ValueError): K.validate(K.load(HERE/'case.TEMPLATE.json'), {}, None, None, None, None, None)
        for n in K.MATERIALS + K.EVIDENCE:
            args = modeled(); (args[0]['package'] if n in K.MATERIALS else args[0]['evidence'])[n] = None
            with self.subTest(pin=n), self.assertRaises(ValueError): K.validate(*args)

    def test_unknown_fields_and_observed_material_tampering_refuse(self):
        args = modeled(); args[0]['extra'] = 'UNREVIEWED'
        with self.assertRaises(ValueError): K.validate(*args)
        for n in K.MATERIALS + K.EVIDENCE:
            args = modeled(); args[1][n]['sha256'] = '0'*64
            with self.subTest(pin=n), self.assertRaises(ValueError): K.validate(*args)

    def test_source_native_Reader_format_and_Root_decision_joins(self):
        for kind in ('source', 'run', 'package-format', 'Reader-status', 'Root-acceptance'):
            args = modeled()
            if kind == 'source': args[0]['source']['sha'] = 'f'*40
            elif kind == 'run': args[6]['actual']['run'] = '999'
            elif kind == 'package-format': args[6]['package'] = dict(args[6]['package'], version='not-in-actual-Reader-format')
            elif kind == 'Reader-status': args[6]['status'] = 'OTHER'
            else: args[5]['accepted_for_vm_input'] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_expired_revoked_and_untrusted_public_TEST_evidence_refuse(self):
        for kind in ('expired', 'revoked', 'private', 'signature'):
            args = modeled(); trust = args[0]['trust']
            if kind == 'expired': trust['expires_utc'] = int(time.time())-1
            elif kind == 'revoked': trust['revoked'] = True
            elif kind == 'private': trust['public_only'] = False
            else: trust['signature_valid'] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_dependency_GNU_version_development_selection_and_tool_refusals(self):
        for kind in ('dependency', 'GNU-version', 'GCC', 'tool', 'root-only-tool'):
            args = modeled(); runtime = args[3]
            if kind == 'dependency': runtime['dependency_versions']['glibc'] = 'WRONG'
            elif kind == 'GNU-version': next(iter(runtime['elfs'].values()))['providers']['libc.so.6']['version_definitions'] = []
            elif kind == 'GCC': runtime['gcc_driver_selection']['mode'] = 'AUTO_GCC'
            elif kind == 'tool': del runtime['files']['/usr/bin/gpg']
            else: runtime['files']['/usr/bin/gpg']['mode'] = 0o700
            with self.subTest(kind=kind), self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_zero_byte_files_and_headers_and_safe0777_tool_aliases(self):
        args = modeled(); self.assertEqual(args[3]['candidate_namespace'][K.PREFIX+'/empty']['bytes'], 0)
        self.assertEqual(K.candidate_target(args[3]['candidate_namespace'], K.PREFIX+'/bin/clang++'), K.PREFIX+'/bin/clang')
        K.validate(*args)

    def test_prefix_escape_cycle_SUID_world_write_and_unowned_payload_refuse(self):
        for kind in ('escape', 'cycle', 'SUID', 'world-write', 'outside'):
            args = modeled(); ns = args[3]['candidate_namespace']
            if kind == 'escape': ns[K.PREFIX+'/bin/clang++']['link_target'] = '/usr/bin/clang'
            elif kind == 'cycle': ns[K.PREFIX+'/bin/clang++']['link_target'] = 'clang++'
            elif kind == 'SUID': ns[K.PREFIX+'/bin/clang']['mode'] = 0o4755
            elif kind == 'world-write': ns[K.PREFIX+'/bin/clang']['mode'] = 0o777
            else: ns['/usr/bin/clang'] = ns.pop(K.PREFIX+'/empty')
            with self.subTest(kind=kind), self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_physical_staging_peak_RAM_quota_and_phase_cap_refusals(self):
        for kind in ('staging', 'physical', 'RAM', 'quota', 'phase', 'bool', 'raw'):
            args = modeled(); r = args[4]
            if kind == 'staging': r['case_staging_bytes'] = sum(args[0]['package'][n]['bytes'] for n in K.MATERIALS)
            elif kind == 'physical': r['physical_free_bytes'] = 1
            elif kind == 'RAM': r['host_MemAvailable_bytes'] = r['owner_memory_bytes']
            elif kind == 'quota': r['quota_guard']['whole_actor'] = False
            elif kind == 'phase': del r['gpg_seconds']
            elif kind == 'bool': r['pids'] = True
            else: r['prepared_raw_bytes'] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_guest_scalar_grammar_rejects_values_the_actual_parser_refuses(self):
        for field, value in [('log_bytes', 1023), ('log_bytes', 16777217), ('guest_output_cap_bytes', 1000000000),
                             ('gpg_seconds', 1000000000), ('compile_seconds', 1000000000)]:
            args = modeled(); args[4][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'case.env'):
                K.validate(*reseal(args))
        for field in ('created_utc', 'expires_utc', 'evaluated_utc'):
            for value in (99999999, 1000000000000):
                args = modeled(); args[0]['trust'][field] = value
                with self.subTest(epoch=field, value=value), self.assertRaisesRegex(ValueError, 'epochs'):
                    K.validate(*reseal(args))

    def test_exact_probe_and_Root_call_multiplicities_fit_explicit_envelopes(self):
        args = modeled(); r = args[4]
        probe = 2*r['compile_seconds'] + 6*r['run_seconds'] + r['sync_seconds']
        r['probe_wait_seconds'] = probe - 1
        with self.assertRaisesRegex(ValueError, 'probe wait'): K.validate(*reseal(args))
        r['probe_wait_seconds'] = probe
        root = 6*r['gpg_seconds'] + r['install_seconds'] + probe + r['remove_seconds'] + 2*r['run_seconds'] + 2*r['sync_seconds'] + r['cleanup_seconds'] + r['boot_overhead_seconds']
        r['boot_seconds'] = root - 1
        with self.assertRaisesRegex(ValueError, 'envelopes'): K.validate(*reseal(args))
        r['boot_seconds'] = root; K.validate(*reseal(args))
        del r['boot_overhead_seconds']
        with self.assertRaises(ValueError): K.validate(*reseal(args))

    def test_pure_load_hash_zero_bytes_JSON_refusals_and_no_operations(self):
        with tempfile.TemporaryDirectory(prefix='llvm23-contract-model-') as tmp:
            root = Path(tmp); f = root/'empty'; f.write_bytes(b''); self.assertEqual(K.pin(f)['bytes'], 0)
            for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.5}', b'{} '):
                f.write_bytes(body)
                with self.assertRaises(ValueError): K.load(f)
            link = root/'alias'; link.symlink_to('empty')
            with self.assertRaises(ValueError): K.pin(link)
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen', 'fcntl.flock'):
            with self.assertRaises(RuntimeError): sys.audit(event)


if __name__ == '__main__': unittest.main(verbosity=2)
