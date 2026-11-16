# SPDX-License-Identifier: MIT
"""Pure proposed-policy joins against committed guards; no Root grants or actors."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FAMILY = HERE.parents[1]
POLICY = HERE/'owned_current_v3.policy.PROPOSAL.json'


def fence(event, args):
    if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit'):
        raise RuntimeError('pure policy DATA only: '+event)


sys.addaudithook(fence)


def load(name):
    spec = importlib.util.spec_from_file_location('policy_contract_'+name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load('delegated_context_v3')
I = load('image_current_v3')
E = load('owned_executor_current_v3')
FRAGMENT = json.loads((FAMILY/'owned-executor-current-v3.policy.PROPOSAL.json').read_bytes())


def need(ok, why):
    if not ok:
        raise ValueError(why)


def validate(value):
    """Check composition only. No observation, approval or runtime fixture is made."""
    need(value['schema'] == 3 and value['kind'] == 'CURRENT_ONBOARDING_FULL_POLICY_PROPOSAL_V3'
         and value['review_state'] == 'PROPOSED_REQUIRES_SEPARATE_ROOT_DELEGATION', 'unissued proposal only')
    for key in ('Root_issuance', 'Root_final_acceptance', 'independent_component_acceptance',
                'hardware_acceptance', 'release_acceptance', 'runtime', 'actual_binding', 'actual_images'):
        need(value[key] is None, 'no runtime or authority in policy DATA')
    for key in ('executor_current_v3', 'image_domains', 'image_endpoint_template', 'image_steps',
                'image_storage_bytes', 'stage_capability_proposals'):
        need(value[key] == FRAGMENT[key], 'exact committed executor proposal, no budget drift: '+key)
    need(value['stage_capabilities'] == value['stage_capability_proposals'], 'explicit stage ceiling projection')
    need(value['context'] == dict(metadata_query_seconds=30, metadata_max_bytes=1024**2,
         max_context_age_seconds=7560, max_delegation_seconds=7560), 'finite exact context-only policy')
    limits = value['context']
    H.integer(limits['metadata_query_seconds'], high=30)
    H.integer(limits['metadata_max_bytes'], high=1024**2)
    H.integer(limits['max_context_age_seconds'], high=limits['max_delegation_seconds'])
    need(value['image_alpm_capabilities'] == I.CAPS, 'exact current normal-ALPM capabilities')
    need(set(value['stage_capabilities']) == {'backend', 'ui', 'lifecycle'}, 'all three stages')
    for stage, cap in value['stage_capabilities'].items():
        need(set(cap) == set(H.LIMITS), 'exact context/image/executor numeric capability fields')
        for field in H.LIMITS:
            H.integer(cap[field])
        E.validate_policy(value, dict(capability=cap))  # Actual committed pure guard, no delegation approval.
        need(cap == dict(builder_cpus=4, builder_memory_bytes=4*1024**3, builder_pids=512,
                         command_rows=512, max_command_seconds=1800, total_seconds=7200), 'exact proposed stage limits')
    p = value['executor_current_v3']
    memory = sum(int(row['memory.max']) for row in [p['controller'], *value['image_domains'].values()])
    need(memory == 8704*1024**2 and p['minimum_available_bytes'] >= memory+p['host_reserve_bytes'],
         'controller plus owner plus aggregate daemon, counted once')
    need(p['stage_seconds']+p['setup_seconds']+p['cleanup_seconds'] == p['controller_seconds'] == 7560
         and p['service_seconds'] == 7380, 'new wrapper deadline arithmetic')
    need(p['controller_command_rows'] >= math.ceil(7200/p['owner_poll_seconds'])+256
         and p['controller_receipt_bytes'] >= p['controller_command_rows']*(2*E.MAX_OUTPUT+65536), 'bounded polling/output reserve')
    need(p['minimum_disk_bytes'] >= value['image_storage_bytes']+p['host_reserve_bytes']
         +p['controller_receipt_bytes']+p['public_evidence_bytes'], 'finite aggregate disk admission')
    for role, domain in value['image_domains'].items():
        I.kernel_limits(dict(pid=1, starttime=1, cgroup='/MODEL/'+('a'*64)+'/'+role, limits=domain), domain, 'a'*64)
    need(value['frozen_stage_limits'] == dict(build_seconds=180, admission_total_seconds=1800,
         owned_session_seconds=600, retirement_reserve_seconds=60, builder_cpus=4,
         builder_memory_bytes=4*1024**3, builder_memory_swap_bytes=4*1024**3,
         builder_pids=512, builder_tmpfs_bytes=4*1024**3, command_rows=512,
         lifecycle_capabilities=['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID']), 'frozen actor limits unchanged')
    need(value['normal_ALPM'] == dict(local_archives_only=True, dependencies_checked=True,
         scriptlets=True, hooks=True, package_code_suppression=False), 'normal local ALPM without bypass')
    need(value['signature_policy'] == dict(Architecture='aarch64', SigLevel='Required', LocalFileSigLevel='Required',
         offline_verifier=True, public_certificates_only=True, Root_trust_admission=None), 'strict separately admitted public trust')
    need(value['private_stage'] == dict(test=dict(fingerprint='D9D7A9FC25B9914CF6F2CE55952AEDD8A209B4C0',
         public_key_role='setup8_current_public_key')), 'observed public Setup8 key selection only')
    need(type(value['pending_interfaces']) is list and len(value['pending_interfaces']) == 7
         and 'REAL_COMMITTED_CONTEXT_V4_AUTHENTICATED_CROSS_RUN_ADOPTION_CONTRACT' in value['pending_interfaces'],
         'unimplemented interface requirements stay explicit')
    return value


class Controls(unittest.TestCase):
    def policy(self):
        return json.loads(POLICY.read_bytes())

    def test_all_three_stage_contracts_use_actual_committed_pure_guards(self):
        value = self.policy()
        self.assertEqual(validate(value), value)
        self.assertEqual(value['image_steps']['cleanup_seconds'], 90)

    def test_unissued_policy_cannot_be_used_as_Root_delegation(self):
        raw = POLICY.read_bytes()
        with self.assertRaises(ValueError):H.validate_delegation(raw, H.pin(raw)['sha256'], now=1)
        for key in ('Root_issuance', 'Root_final_acceptance', 'runtime', 'actual_binding', 'actual_images',
                    'independent_component_acceptance', 'hardware_acceptance', 'release_acceptance'):
            value = self.policy();value[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):validate(value)

    def test_missing_stage_widened_frozen_caps_and_boolean_budget_refuse(self):
        for change in ('missing_stage', 'frozen_command', 'frozen_session', 'builder_memory', 'boolean', 'rows'):
            value = self.policy()
            if change == 'missing_stage':del value['stage_capabilities']['ui']
            if change == 'frozen_command':value['frozen_stage_limits']['build_seconds'] = 181
            if change == 'frozen_session':value['frozen_stage_limits']['owned_session_seconds'] = 7200
            if change == 'builder_memory':value['stage_capabilities']['backend']['builder_memory_bytes'] += 1
            if change == 'boolean':value['stage_capabilities']['backend']['max_command_seconds'] = True
            if change == 'rows':value['stage_capabilities']['lifecycle']['command_rows'] = 513
            with self.subTest(change=change), self.assertRaises(ValueError):validate(value)

    def test_domain_storage_deadline_and_reserve_drift_refuse(self):
        for change in ('swap', 'daemon_memory', 'controller_memory', 'storage', 'receipt', 'public', 'deadline', 'cleanup'):
            value = self.policy()
            if change == 'swap':value['image_domains']['daemon']['memory.swap.max'] = 'max'
            if change == 'daemon_memory':value['image_domains']['daemon']['memory.max'] = str(7*1024**3)
            if change == 'controller_memory':value['executor_current_v3']['controller']['memory.max'] = 'max'
            if change == 'storage':value['image_storage_bytes'] += 1
            if change == 'receipt':value['executor_current_v3']['controller_receipt_bytes'] = 1
            if change == 'public':value['executor_current_v3']['public_evidence_bytes'] = 0
            if change == 'deadline':value['executor_current_v3']['controller_seconds'] += 1
            if change == 'cleanup':value['image_steps']['cleanup_seconds'] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):validate(value)

    def test_metadata_budget_and_context_age_cannot_silently_expand(self):
        for key in self.policy()['context']:
            value = self.policy();value['context'][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):validate(value)

    def test_actual_image_budget_reserves_cleanup_inside_the_stage_total(self):
        value = self.policy()
        for stage, cap in value['stage_capabilities'].items():
            with self.subTest(stage=stage), patch.object(I.time, 'monotonic', return_value=1):
                build = I.Build(None, dict(capability=cap), None, value, Path('/MODEL-NOT-CREATED'))
            self.assertEqual(build.cleanup_end, 1+cap['total_seconds'])
            self.assertEqual(build.cleanup_end-build.end, value['image_steps']['cleanup_seconds'])
            self.assertFalse(build.cleaning)

    def test_normal_ALPM_GPG_path_semantics_and_no_policy_bypass(self):
        self.assertIn('pacman --config /current-inputs/pacman.conf --gpgdir "$work" --noconfirm -U', I.DRIVER)
        self.assertIn('SigLevel = Required', I.DRIVER)
        for bypass in ('--noscriptlet', '--nodeps', '--assume-installed', 'HookDir'):
            self.assertNotIn(bypass, I.DRIVER)
        for key in ('scriptlets', 'hooks', 'dependencies_checked'):
            value = self.policy();value['normal_ALPM'][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):validate(value)
        value = self.policy();value['signature_policy']['SigLevel'] = 'Never'
        with self.assertRaises(ValueError):validate(value)

    def test_frozen_owner_route_source_pins_support_recorded_limits(self):
        value = self.policy()
        for role, member in (('frozen_owner', 'payload/native/owner_current_v2.py'), ('frozen_route', 'successor_v2/owned_route.py')):
            raw = (FAMILY/member).read_bytes()
            self.assertEqual(dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()), value['reference_basis'][role])
        self.assertIn("min(g['resources']['total_seconds'],600)", (HERE/'owner_current_v2.py').read_text())
        self.assertIn("cap['build_seconds'] <= 180", (FAMILY/'successor_v2/owned_route.py').read_text())

    def test_public_Setup8_key_fact_never_issues_current_trust(self):
        value = self.policy()
        self.assertIsNone(value['signature_policy']['Root_trust_admission'])
        spec = importlib.util.spec_from_file_location('policy_material_aliases', FAMILY/'successor_v4_source/prepare.py')
        constructor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(constructor)
        self.assertEqual(value['private_stage']['test']['public_key_role'], constructor.ALIASES['Setup8/current_public_key'])
        for key in ('fingerprint', 'public_key_role'):
            bad = self.policy();bad['private_stage']['test'][key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):validate(bad)


if __name__ == '__main__':
    unittest.main()
