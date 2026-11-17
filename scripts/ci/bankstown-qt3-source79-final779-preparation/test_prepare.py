# SPDX-License-Identifier: MIT
"""Focused binding/refusal MODEL controls; no genuine trust, mount or authority."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
spec = importlib.util.spec_from_file_location('final779_controls',HERE/'prepare.py')
M = importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
A = M.bootstrap(REPO)
LOCK = A.decode(A.read(HERE/'inputs.lock.json',M.LOCK_PIN,{}))
N = A.module(REPO,M.HOSTED,LOCK['helpers'][M.HOSTED],{})
R = A.module(REPO,M.READER,LOCK['helpers'][M.READER],{})


class Controls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='final779-MODEL-')
        self.addCleanup(tmp.cleanup);self.root = Path(tmp.name)
        self.fingerprint = 'A'*40

    def ref(self,name,value):
        body = A.encoded(value) if not isinstance(value,bytes) else value
        path = self.root/name;path.write_bytes(body);path.chmod(0o600)
        return dict(path=str(path),**A.pin(body))

    def trust(self):
        public = self.ref('public',b'MODEL_PUBLIC_DATA_NOT_A_REAL_CERTIFICATE')
        admission = dict(kind='MODEL_ONLY_NO_REAL_AUTHORITY',issuer='Root',approved=True,
            scope=M.TRUST_SCOPE,public_key=public,fingerprint=self.fingerprint,issued_epoch=900,expires_epoch=1100)
        return dict(public_key=public,Root_admission=self.ref('admission',admission),fingerprint=self.fingerprint),admission

    def custody(self):
        expected = dict(source='b'*40,source_map=A.pin(b'MODEL_SOURCE'),owner_inputs_pin=A.pin(b'MODEL_INPUTS'),staged_root=str(self.root))
        mount = dict(kind='EXTERNAL_ROOT_RETAINED_READONLY_MOUNT_OBSERVATION_V1',path=str(self.root),mount_id='1',
            parent_mount_id='2',device='1:2',mount_root='/',filesystem='MODEL',st_dev=1,st_ino=2,uid=1000,
            filesystem_bytes=1024,filesystem_inodes=100,retirement_owner='Root',retirement_observed_here=False,Root_acceptance=None)
        record = dict(schema=1,kind='ROOT_SOURCE79_RETAINED_INPUT_SELECTION_V1',issuer='Root',approved=True,
            **expected,issued_epoch=900,expires_epoch=1100,launcher_uid=1000,mount_observation=mount)
        return record,expected

    def owner_model(self):
        groups = {}
        for group,count in A.GROUPS.items():
            groups[group] = {str(i):dict(path=str(self.root/(group+str(i))),**A.pin(b'')) for i in range(count)}
        owner = dict(groups,**{k:dict(path=str(self.root/k),**A.pin(b''))
            for k in ('base_lock','bootstrap_profile','baseline_inventory','catalog')},official_trust=None)
        return owner

    def test_exact777_then779_unique_file_roles(self):
        owner = self.owner_model()
        self.assertEqual(len(M.distinct_roles(N,owner,777)),777)
        owner['official_trust'] = dict(public_key=dict(path=str(self.root/'public'),**A.pin(b'x')),
            Root_admission=dict(path=str(self.root/'admission'),**A.pin(b'x')),fingerprint=self.fingerprint)
        self.assertEqual(len(M.distinct_roles(N,owner,779)),779)

    def test_duplicate_metadata_path_cannot_masquerade_as779(self):
        owner = self.owner_model();owner['catalog'] = copy.deepcopy(owner['baseline_inventory'])
        with self.assertRaisesRegex(ValueError,'DISTINCT_FILE_ROLES'):
            M.distinct_roles(N,owner,777)

    def test_missing_explicit_baseline_cannot_be_counted(self):
        owner = self.owner_model();del owner['baseline_inventory']
        with self.assertRaises(KeyError):M.distinct_roles(N,owner,777)

    def test_zero_byte_public_revoked_role_is_preserved(self):
        owner = self.owner_model()
        refs = M.distinct_roles(N,owner,777)
        self.assertTrue(any(ref['bytes'] == 0 and ref['sha256'] == A.pin(b'')['sha256'] for ref in refs))

    def test_fresh_external_audio_trust_data_join(self):
        trust,_ = self.trust()
        self.assertEqual(M.bind_trust(A,N,trust,self.fingerprint,1000,{}),trust)

    def test_wrong_scope_cannot_reuse_onboarding_admission(self):
        trust,admission = self.trust();admission['scope'] = 'CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY'
        trust['Root_admission'] = self.ref('wrong-scope',admission)
        with self.assertRaisesRegex(ValueError,'FRESH_EXTERNAL_AUDIO_TRUST'):
            M.bind_trust(A,N,trust,self.fingerprint,1000,{})

    def test_expired_future_or_boolean_trust_time_refuses(self):
        trust,admission = self.trust()
        for change in ({'expires_epoch':1000},{'issued_epoch':1001},{'issued_epoch':True}):
            with self.subTest(change=change):
                bad = dict(admission,**change);trust['Root_admission'] = self.ref('bad-time',bad)
                with self.assertRaisesRegex(ValueError,'FRESH_EXTERNAL_AUDIO_TRUST'):
                    M.bind_trust(A,N,trust,self.fingerprint,1000,{})

    def test_fingerprint_and_full_public_descriptor_must_join(self):
        trust,admission = self.trust();admission['public_key'] = dict(trust['public_key'],path=str(self.root/'other'))
        trust['Root_admission'] = self.ref('wrong-public',admission)
        with self.assertRaisesRegex(ValueError,'FRESH_EXTERNAL_AUDIO_TRUST'):
            M.bind_trust(A,N,trust,self.fingerprint,1000,{})
        with self.assertRaisesRegex(ValueError,'EXACT_OFFICIAL_TRUST'):
            M.bind_trust(A,N,trust,'B'*40,1000,{})

    def test_unissued_root_trust_is_not_promoted(self):
        trust,admission = self.trust();admission['approved'] = None
        trust['Root_admission'] = self.ref('unissued',admission)
        with self.assertRaisesRegex(ValueError,'FRESH_EXTERNAL_AUDIO_TRUST'):
            M.bind_trust(A,N,trust,self.fingerprint,1000,{})

    def test_private_key_and_empty_public_selection_refuse(self):
        trust,_ = self.trust();trust['public_key'] = self.ref('private',b'MODEL PRIVATE KEY DATA')
        with self.assertRaisesRegex(ValueError,'PUBLIC_CERTIFICATE'):
            M.bind_trust(A,N,trust,self.fingerprint,1000,{})
        trust['public_key'] = self.ref('empty',b'')
        with self.assertRaisesRegex(ValueError,'WHOLE_AUDIO_FILE_REFERENCE'):
            M.bind_trust(A,N,trust,self.fingerprint,1000,{})

    def test_external_custody_model_is_data_only(self):
        record,expected = self.custody();ref = self.ref('custody',record)
        checked = M.bind_custody(A,ref,expected,1000,{})
        self.assertIsNone(checked['mount_observation']['Root_acceptance'])
        self.assertFalse(checked['mount_observation']['retirement_observed_here'])

    def test_uid0_mount_does_not_satisfy_existing_launcher_gate(self):
        record,expected = self.custody();record['launcher_uid'] = 0;record['mount_observation']['uid'] = 0
        with self.assertRaisesRegex(ValueError,'CALLER_OWNED_MOUNT'):
            M.bind_custody(A,self.ref('root-uid',record),expected,1000,{})

    def test_boolean_mount_uid_and_missing_or_extra_observation_fields_refuse(self):
        original,expected = self.custody()
        for case in ('bool','missing','extra'):
            record = copy.deepcopy(original)
            if case == 'bool':record['launcher_uid'] = 1;record['mount_observation']['uid'] = True
            elif case == 'missing':del record['mount_observation']['Root_acceptance']
            else:record['mount_observation']['foreign'] = 'claim'
            with self.subTest(case=case),self.assertRaisesRegex(ValueError,'CALLER_OWNED_MOUNT'):
                M.bind_custody(A,self.ref('bad-mount',record),expected,1000,{})

    def test_custody_cannot_bind_another_source_or_owner_request(self):
        original,expected = self.custody()
        for key in ('source','source_map','owner_inputs_pin','staged_root'):
            changed = dict(expected);changed[key] = 'OTHER'
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'EXACT_CUSTODY_INPUT'):
                M.bind_custody(A,self.ref('custody',original),changed,1000,{})

    def test_custody_expiry_and_filesystem_caps_remain_finite(self):
        original,expected = self.custody()
        for case in ('expired','wide','bytes','inodes'):
            record = copy.deepcopy(original)
            if case == 'expired':record['expires_epoch'] = 999
            elif case == 'wide':record['expires_epoch'] = 10000
            elif case == 'bytes':record['mount_observation']['filesystem_bytes'] = 32*1024**3+1
            else:record['mount_observation']['filesystem_inodes'] = 20001
            with self.subTest(case=case),self.assertRaises(ValueError):
                M.bind_custody(A,self.ref('bad-bound',record),expected,1000,{})

    def test_only_staged_or_exact_source_metadata_is_confined(self):
        materials,source = self.root/'materials',self.root/'source'
        ref = dict(path=str(source/'catalog'),**A.pin(b'MODEL'))
        rows = {'catalog':dict(A.pin(b'MODEL'),mode=0o644)}
        self.assertTrue(M.confined_references([ref],source,rows,materials,materials/'proposal'))
        self.assertFalse(M.confined_references([ref],source,{},materials,materials/'proposal'))
        self.assertFalse(M.confined_references([ref],source,rows,materials,self.root/'outside'))

    def test_retained_provider_pin_substitution_refuses_before_read(self):
        ref = dict(path=str(self.root/'does-not-exist'),**A.pin(b'SUBSTITUTION'))
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_DATA_PIN'):
            M.required_ref(A,ref,LOCK['seed_provider'],{})

    def test_changed_bootstrap_code_is_never_executed(self):
        path = self.root/M.ADOPTER;path.parent.mkdir(parents=True)
        raw = (REPO/M.ADOPTER).read_bytes();path.write_bytes(raw[:-1]+b'X');path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'WHOLE_STABLE_BOOTSTRAP'):M.bootstrap(self.root)

    def source_map_model(self):
        mapping = A.decode((REPO/'scripts/ci/bankstown-qt3-hosted-v1/source72-map.DATA.json').read_bytes())
        template = A.decode((REPO/'scripts/ci/bankstown-qt3-source79-adoption-data/Root-delegation.UNISSUED.template.json').read_bytes())
        for row in template['materials'].values():
            mapping['files'].setdefault(row['member'],dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644))
        raw = A.encoded(mapping);self.assertEqual(A.pin(raw),R.SOURCE79['source_map'])
        return raw

    def test_exact_source79_map_mode_is_required(self):
        source = self.root/'source';source.mkdir();path = source/'source-map.json';path.write_bytes(self.source_map_model());path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE79_MAP_PIN'):R.source_readiness(source)

    def test_source79_map_body_substitution_refuses(self):
        source = self.root/'source';source.mkdir();path = source/'source-map.json';raw = self.source_map_model();path.write_bytes(raw[:-1]+b'X');path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE79_MAP_PIN'):R.source_readiness(source)

    def test_actor_entry_is_refused(self):
        for event in ('subprocess.Popen','socket.connect','ctypes.dlopen','os.system','fcntl.flock'):
            with self.assertRaisesRegex(ValueError,'DATA_ONLY_NO_ACTORS'):M.no_actors(event,())

    def templates(self):
        prefix = REPO/'scripts/ci/bankstown-qt3-source79-adoption-data'
        return (A.decode((prefix/'Root-delegation.UNISSUED.template.json').read_bytes()),
                A.decode((prefix/'Root-request.UNISSUED.template.json').read_bytes()))

    def test_actual_source79_templates_remain_unissued(self):
        delegation,request = self.templates()
        self.assertEqual(delegation['binding']['source'],LOCK['source']['source'])
        M.require_unissued(delegation,request)

    def test_root_authority_cannot_be_promoted_by_preparation(self):
        for target,key,value in (('d','approved',True),('d','nonce','a'*64),('r','issuer','Root'),
                                 ('r','trusted_main_commit','c'*40)):
            delegation,request = self.templates()
            (delegation if target == 'd' else request)[key] = value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'AUTHORITY_MUST_REMAIN_UNISSUED'):
                M.require_unissued(delegation,request)


if __name__ == '__main__':unittest.main()
