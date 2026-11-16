# SPDX-License-Identifier: MIT
"""Inert temporary DATA fixtures; no metadata requests, actors or trust issuance."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('delegated_context_v3', HERE/'delegated_context_v3.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
NOW = 1800000000


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='delegated-context-inert-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'source'
        self.root.mkdir()
        self.ceilings = dict(max_command_seconds=600, total_seconds=3600, builder_cpus=4,
                             builder_memory_bytes=2*1024**3, builder_pids=512, command_rows=400)
        self.limits = dict(metadata_query_seconds=30, metadata_max_bytes=1024**2,
                           max_context_age_seconds=300, max_delegation_seconds=7200)
        self.files = {'programs/context.py': (HERE/'delegated_context_v3.py').read_bytes(),
                      'programs/owner.py': b'# inert owner fixture\n',
                      'programs/image.py': b'# inert image fixture\n',
                      'programs/executor.py': b'# inert executor fixture\n',
                      'inputs/public-test.asc': b'INERT PUBLIC TEST KEY FIXTURE\n',
                      'inputs/archive.pkg': b'INERT ARCHIVE DATA\n',
                      'inputs/policy.json': M.encoded(dict(context=self.limits,
                          stage_capabilities={s: self.ceilings for s in ('backend', 'ui', 'lifecycle')}))}
        self.reseal()
        def desc(name):
            return dict(member=name, **M.pin(self.files[name]))
        self.d = dict(schema=3, kind=M.DELEGATION, issuer='Root', approved=True,
                      scope='CURRENT_PRIVATE_STAGE_ONLY', stage='backend', nonce='a'*64,
                      binding=dict(source='b'*40, ref='refs/heads/codex/inert-source', run=None,
                                   job=None, attempt=1, source_lock=M.pin(self.map_raw)),
                      issued_epoch=NOW-10, expires_epoch=NOW+3600,
                      programs=dict(context=desc('programs/context.py'), owner=desc('programs/owner.py'),
                                    image=desc('programs/image.py'), image_executor=desc('programs/executor.py')),
                      policy=desc('inputs/policy.json'),
                      materials=dict(test_public_key=desc('inputs/public-test.asc'), archive=desc('inputs/archive.pkg')),
                      capability=dict(operation=M.OPERATION, stage='backend', allow_provisional_context=True,
                                      allow_provisional_image_checks=True, allow_pair_adoption=False, **self.ceilings),
                      context_limits=self.limits, image_ids=dict(backend=None, ui=None, lifecycle=None),
                      hosted=dict(repository='example/inert', workflow_ref='example/inert/.github/workflows/test.yml@refs/heads/inert',
                                  workflow_sha='c'*40, job_key='backend', job_name='Inert backend fixture',
                                  runner_environment='github-hosted', runner_os='Linux', runner_arch='ARM64'), **M.FINAL)
        self.env = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY='example/inert', GITHUB_SHA='b'*40,
                        GITHUB_REF='refs/heads/codex/inert-source', GITHUB_RUN_ID='12345', GITHUB_RUN_ATTEMPT='1',
                        GITHUB_JOB='backend', GITHUB_WORKFLOW_REF=self.d['hosted']['workflow_ref'],
                        GITHUB_WORKFLOW_SHA='c'*40, GITHUB_WORKSPACE=str(self.root), RUNNER_ENVIRONMENT='github-hosted',
                        RUNNER_OS='Linux', RUNNER_ARCH='ARM64', RUNNER_NAME='Hosted Inert Runner')
        self.jobs = dict(total_count=1, jobs=[dict(id=67890, run_id=12345, run_attempt=1, head_sha='b'*40,
                         status='in_progress', conclusion=None, name='Inert backend fixture', runner_name='Hosted Inert Runner',
                         run_url='https://api.github.com/repos/example/inert/actions/runs/12345',
                         url='https://api.github.com/repos/example/inert/actions/jobs/67890',
                         html_url='https://github.com/example/inert/actions/runs/12345/job/67890')])

    def reseal(self):
        for name, body in self.files.items():
            path = self.root/name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes(body)
            path.chmod(0o644)
        self.map_raw = M.encoded(dict(schema=1, kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3', operation=M.OPERATION,
                                     actual=dict(source=None, ref=None, run=None, job=None),
                                     files={n: dict(M.pin(b), mode=0o644) for n, b in self.files.items()}))
        for name in ('source-map.json', 'source.lock.json'):
            (self.root/name).write_bytes(self.map_raw)
            (self.root/name).chmod(0o644)

    def response(self):
        return dict(url='https://api.github.com/repos/example/inert/actions/runs/12345/jobs?filter=latest&per_page=100',
                    status=200, body=M.encoded(self.jobs), received_epoch=NOW, elapsed_ms=2)

    def capture(self, d=None, env=None, response=None, now=NOW):
        raw = M.encoded(self.d if d is None else d)
        return M.capture_context(raw, M.pin(raw)['sha256'], self.root,
                                 environ=self.env if env is None else env,
                                 jobs_response=self.response() if response is None else response, now=now)

    def refuses(self, callback):
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            callback()

    def test_capture_and_replay_keep_authority_unset(self):
        c = self.capture()
        self.assertEqual(c['binding'], dict(self.d['binding'], run='12345', job='67890'))
        self.assertEqual(M.validate_context(self.d, c, now=NOW+1), c)
        self.assertEqual({k: c[k] for k in M.FINAL}, M.FINAL)
        self.assertEqual(c['issuer'], M.ISSUER)
        self.assertEqual(self.d['binding']['run'], None)
        self.assertEqual(c['program_pin'], M.pin(self.files['programs/context.py']))

    def test_no_secret_environment_access(self):
        allowed = self.env
        class OnlyAllowed:
            def get(self, key):
                if key not in M.ENV:
                    raise AssertionError('secret/unrelated environment access')
                return allowed.get(key)
            def __iter__(self):
                raise AssertionError('environment enumeration')
        self.capture(env=OnlyAllowed())

    def test_unset_or_forged_hosted_selectors(self):
        for key in M.ENV:
            with self.subTest(key=key):
                env = dict(self.env)
                del env[key]
                self.refuses(lambda: self.capture(env=env))
        for key, value in dict(GITHUB_SHA='d'*40, GITHUB_REF='refs/heads/wrong', GITHUB_JOB='ui',
                               GITHUB_RUN_ATTEMPT='2', GITHUB_WORKFLOW_SHA='d'*40,
                               RUNNER_ENVIRONMENT='self-hosted', RUNNER_ARCH='X64',
                               GITHUB_WORKSPACE='/home/inert/private-source').items():
            with self.subTest(key=key):
                self.refuses(lambda: self.capture(env=dict(self.env, **{key: value})))

    def test_delegation_hash_canonicality_and_future_ids(self):
        raw = M.encoded(self.d)
        self.refuses(lambda: M.validate_delegation(raw, '0'*64, NOW))
        compact = raw.replace(b'  ', b'')
        self.refuses(lambda: M.validate_delegation(compact, M.pin(compact)['sha256'], NOW))
        for key, value in dict(run='12345', job='67890', attempt=True, source=None).items():
            d = copy.deepcopy(self.d)
            d['binding'][key] = value
            self.refuses(lambda: self.capture(d))
        d = copy.deepcopy(self.d)
        d['image_ids']['backend'] = 'sha256:'+'a'*64
        self.refuses(lambda: self.capture(d))

    def test_stale_delegation_context_metadata(self):
        self.refuses(lambda: self.capture(now=NOW-11))
        self.refuses(lambda: self.capture(now=NOW+3601))
        c = self.capture()
        self.refuses(lambda: M.validate_context(self.d, c, now=NOW+301))
        self.refuses(lambda: M.validate_context(self.d, c, now=NOW-1))
        for response in (dict(self.response(), received_epoch=NOW-31), dict(self.response(), received_epoch=NOW+1),
                         dict(self.response(), elapsed_ms=30001)):
            self.refuses(lambda: self.capture(response=response))

    def test_exact_metadata_url_complete_body_and_real_job_id(self):
        for key, value in dict(url=self.response()['url']+'&token=secret', status=True, body=b'{"jobs":[]}').items():
            self.refuses(lambda: self.capture(response=dict(self.response(), **{key: value})))
        for key, value in dict(id=True, run_id=999, run_attempt=2, head_sha='d'*40,
                               status='completed', conclusion='success', runner_name='wrong',
                               name='wrong', url='https://example.invalid/job',
                               html_url='https://github.com/other/repo/actions/runs/12345/job/67890').items():
            with self.subTest(key=key):
                jobs = copy.deepcopy(self.jobs)
                jobs['jobs'][0][key] = value
                self.refuses(lambda: self.capture(response=dict(self.response(), body=M.encoded(jobs))))
        for jobs in (dict(self.jobs, total_count=2), dict(self.jobs, jobs=self.jobs['jobs']*2, total_count=2)):
            self.refuses(lambda: self.capture(response=dict(self.response(), body=M.encoded(jobs))))
        self.refuses(lambda: self.capture(response=dict(self.response(), body=b'{"total_count":1,"total_count":1}')))
        self.refuses(lambda: self.capture(response=dict(self.response(), body=b'x'*(1024**2+1))))

    def test_context_binding_and_issuer_cannot_be_relabelled(self):
        c = self.capture()
        for key, value in dict(issuer='Root', Root_final_acceptance=True, hardware_acceptance=True,
                               nonce='d'*64, jobs_response_pin=M.pin(b'wrong')).items():
            bad = dict(c, **{key: value})
            self.refuses(lambda: M.validate_context(self.d, bad, now=NOW))
        bad = copy.deepcopy(c)
        bad['binding']['job'] = '999'
        self.refuses(lambda: M.validate_context(self.d, bad, now=NOW))
        bad = copy.deepcopy(c)
        bad['jobs_response']['body'] = '{}'
        self.refuses(lambda: M.validate_context(self.d, bad, now=NOW))

    def test_finite_policy_bounds_without_new_builder_ceiling(self):
        self.assertEqual(self.capture()['binding']['job'], '67890')  # 600s fixture command is permitted.
        for key in M.LIMITS:
            for value in (True, 0, -1, self.ceilings[key]+1):
                d = copy.deepcopy(self.d)
                d['capability'][key] = value
                self.refuses(lambda: self.capture(d))
        d = copy.deepcopy(self.d)
        d['context_limits']['metadata_query_seconds'] = 31
        self.refuses(lambda: self.capture(d))
        d = copy.deepcopy(self.d)
        d['capability']['allow_provisional_context'] = False
        self.refuses(lambda: self.capture(d))

    def test_source_bodies_modes_aliases_and_namespace(self):
        for name in ('inputs/archive.pkg', 'programs/context.py', 'inputs/policy.json', 'source.lock.json'):
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            self.refuses(self.capture)
            path.write_bytes(original)
        extra = self.root/'extra'
        extra.write_bytes(b'unmapped')
        self.refuses(self.capture)
        extra.unlink()
        path = self.root/'inputs/archive.pkg'
        path.chmod(0o666)
        self.refuses(self.capture)
        path.chmod(0o644)
        target = self.root/'inputs/public-test.asc'
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(target)
        self.refuses(self.capture)
        path.unlink()
        os.link(target, path)
        self.refuses(self.capture)
        path.unlink()
        path.write_bytes(original)
        os.mkfifo(self.root/'fifo')
        self.refuses(self.capture)

    def test_path_policy_and_portable_material_reference(self):
        ref = M.material_reference(self.d, self.root, 'archive')
        self.assertEqual(ref, dict(path=str(self.root/'inputs/archive.pkg'), **M.pin(self.files['inputs/archive.pkg'])))
        for member in ('/home/inert/archive', '../archive', 'inputs/../archive', 'inputs//archive', 'inputs\\archive'):
            d = copy.deepcopy(self.d)
            d['materials']['archive']['member'] = member
            self.refuses(lambda: self.capture(d))
        self.refuses(lambda: M.resolve_material(self.d, self.root, 'not_reviewed'))
        other = Path(self.tmp.name)/'alias'
        other.symlink_to(self.root, target_is_directory=True)
        self.refuses(lambda: M.resolve_material(self.d, other, 'archive'))

    def test_read_atime_does_not_change_security_identity(self):
        path = self.root/'inputs/archive.pkg'
        before = path.stat()
        os.utime(path, ns=(1, before.st_mtime_ns))
        security = M.identity(path.stat())
        self.capture()
        self.assertEqual(M.identity(path.stat()), security)
        # A noatime test filesystem need not update atime. Exercise that change
        # explicitly without presenting a synthetic stat as a host observation.
        original_fstat = os.fstat
        calls = []
        def atime_only(fd):
            info = original_fstat(fd)
            calls.append(True)
            values = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
            values['st_atime_ns'] = len(calls)*1000000000
            return SimpleNamespace(**values)
        with patch.object(M.os, 'fstat', side_effect=atime_only):
            self.assertEqual(M.read(path)[0], self.files['inputs/archive.pkg'])

    def test_real_mtime_and_content_mutation_during_read_refused(self):
        target = self.root/'inputs/archive.pkg'
        original_read = os.read
        for content in (False, True):
            fired = []
            def mutating(fd, size):
                result = original_read(fd, size)
                if not fired:
                    fired.append(True)
                    if content:
                        target.write_bytes(b'different body')
                    else:
                        info = target.stat()
                        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns+1))
                return result
            with patch.object(M.os, 'read', side_effect=mutating):
                self.refuses(lambda: M.read(target))

    def pair_fixture(self):
        producer_raw = M.encoded(self.d)
        pc = self.capture()
        d = copy.deepcopy(self.d)
        d['stage'] = d['capability']['stage'] = 'ui'
        d['capability']['allow_pair_adoption'] = True
        d['nonce'] = 'd'*64
        d['pair_policy'] = dict(producer_delegation_pin=M.pin(producer_raw), test_fingerprint='E'*40,
                                test_public_key_role='test_public_key')
        # Separate genuine job observation, same actual Source/run.
        env = dict(self.env, GITHUB_JOB='ui')
        d['hosted']['job_key'] = 'ui'
        d['hosted']['job_name'] = 'Inert ui fixture'
        jobs = copy.deepcopy(self.jobs)
        jobs['jobs'][0].update(id=67891, name='Inert ui fixture',
                              url='https://api.github.com/repos/example/inert/actions/jobs/67891',
                              html_url='https://github.com/example/inert/actions/runs/12345/job/67891')
        c = self.capture(d, env=env, response=dict(self.response(), body=M.encoded(jobs)))
        common = dict(schema=3, issuer='DELEGATED_CURRENT_OWNER_V3', binding=pc['binding'], nonce=self.d['nonce'],
                      program_pin=M.descriptor(self.d['programs']['owner']), policy_pin=M.descriptor(self.d['policy']), **M.FINAL)
        archive = M.pin(b'inert matching package')
        pair = dict(common, kind='DELEGATED_CURRENT_ONBOARDING_PAIR_V3', archives=[archive, archive], matching_pair=True)
        pair_raw = M.encoded(pair)
        natural = dict(reaped=True, ownership='REAPED', group_census='EMPTY_TWICE', output_complete=True,
                       timeout=False, signals=[], error=None, exit=0)
        row = dict(archive=archive, signature=M.pin(b'inert detached signature'), supervision=natural,
                   status='[GNUPG:] VALIDSIG '+'E'*40+' 2027-01-15 1 0 4 0 1 10 00 '+'E'*40+'\n[GNUPG:] TRUST_ULTIMATE\n')
        proof = dict(common, kind='DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3', pair_pin=M.pin(pair_raw),
                     public_test_key_pin=M.descriptor(d['materials']['test_public_key']), fingerprint='E'*40,
                     trust_scope='TEST_ONLY', verifications=[copy.deepcopy(row), copy.deepcopy(row)])
        return d, c, producer_raw, pc, pair, proof

    def test_pair_adoption_has_actual_distinct_jobs_and_no_final_authority(self):
        d, c, raw, pc, pair, proof = self.pair_fixture()
        result = M.adopt_pair(d, c, producer_delegation_raw=raw, producer_context=pc,
                              pair_raw=M.encoded(pair), test_raw=M.encoded(proof), now=NOW)
        self.assertEqual(result['binding']['job'], '67891')
        self.assertEqual(result['producer_binding']['job'], '67890')
        self.assertEqual({k: result[k] for k in M.FINAL}, M.FINAL)
        self.assertEqual(result['issuer'], M.ISSUER)

    def test_pair_wrong_source_program_policy_bytes_and_test_refusals(self):
        for change in ('producer_pin', 'wrong_context', 'root_issuer', 'program', 'policy', 'different_pair',
                       'pair_pin', 'key', 'fingerprint', 'signature', 'timeout', 'bad_status', 'root_acceptance'):
            with self.subTest(change=change):
                d, c, raw, pc, pair, proof = self.pair_fixture()
                if change == 'producer_pin': raw += b'\n'
                if change == 'wrong_context': pc['binding']['source'] = 'f'*40
                if change == 'root_issuer': pair['issuer'] = 'Root'
                if change == 'program': pair['program_pin'] = M.pin(b'other program')
                if change == 'policy': proof['policy_pin'] = M.pin(b'other policy')
                if change == 'different_pair': pair['archives'][1] = M.pin(b'other archive')
                if change == 'pair_pin': proof['pair_pin'] = M.pin(b'other pair')
                if change == 'key': proof['public_test_key_pin'] = M.pin(b'other key')
                if change == 'fingerprint': proof['fingerprint'] = 'F'*40
                if change == 'signature': proof['verifications'][0]['signature'] = None
                if change == 'timeout': proof['verifications'][0]['supervision']['timeout'] = True
                if change == 'bad_status': proof['verifications'][0]['status'] += '[GNUPG:] BADSIG bad\n'
                if change == 'root_acceptance': proof['Root_final_acceptance'] = True
                self.refuses(lambda: M.adopt_pair(d, c, producer_delegation_raw=raw, producer_context=pc,
                                                  pair_raw=M.encoded(pair), test_raw=M.encoded(proof), now=NOW))


if __name__ == '__main__':
    unittest.main()
