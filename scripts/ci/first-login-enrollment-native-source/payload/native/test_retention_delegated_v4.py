# SPDX-License-Identifier: MIT
"""FENCED selector models over real pinned pure helpers/encoder; no native claims."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import io
import tempfile
import unittest


def fence(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        raise AssertionError('FENCED no actors/network/GPG')


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('FENCED_'+name, HERE/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


V = module('retention_delegated_v4')
R = module('retention_current_v3')
ENCODER = HERE.parents[2]/'log_evidence.py'
assert V.pin((HERE/'retention_current_v3.py').read_bytes())['sha256'] == V.LEGACY_SHA
assert V.pin(ENCODER.read_bytes())['sha256'] == V.ENCODER_SHA
E = V.load_body(ENCODER.read_bytes(), 'FENCED_actual_encoder')


def natural():
    return dict(reaped=True, ownership='REAPED', group_census='EMPTY_TWICE', output_complete=True,
                timeout=False, signals=[], error=None, exit=0, seconds=.01, passed=True)


class Fixture:
    """Small wholly synthetic package bytes; never actual authority/source/actors."""
    def __init__(self, base, stage):
        self.base, self.stage = base, stage
        self.source = base/'source'; self.source.mkdir()
        parent = base/'work'
        self.output = parent/'stage' if stage != 'lifecycle' else parent/'lifecycle-output/stage'
        self.output.mkdir(parents=True)
        self.image_root = parent/'image'; self.image_root.mkdir()
        self.destination = base/'public'
        self.refs = []
        self.binding = dict(source='a'*40, ref='refs/heads/codex/FENCED', run='101', job='102',
                            attempt=1, source_lock=V.pin(b'FENCED NOT A REAL SOURCE'))
        self.nonce = 'b'*64; self.fingerprint = 'F'*40
        self.d = dict(schema=4, kind='FENCED_MODEL_NOT_ROOT_AUTHORITY', stage=stage, nonce=self.nonce,
                      materials={}, programs={}, capability=dict(allow_selected_pair_adoption=True,max_command_seconds=1800,total_seconds=7200))
        self.inputs = dict(image_inputs={}, stage_inputs=dict(setup8={}, products={}))
        policy = V.encode(dict(private_stage=dict(test=dict(fingerprint=self.fingerprint, public_key_role='key'))))
        self.write(self.source/'policy.json', policy)
        self.d['policy'] = dict(member='policy.json', **V.pin(policy))
        self.material('key', b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nFENCED NOT A KEY\n')
        for field in ('archive', 'signature', 'decision', 'verification'):
            raw = V.encode(dict(FENCED=field)) if field in ('decision', 'verification') else ('FENCED '+field).encode()
            self.material(field, raw); self.inputs['stage_inputs']['setup8'][field+'_role'] = field
        for kind in (() if stage=='backend' else ('first-login',) if stage=='ui' else ('enrollment','first-login','ui')):
            product=dict(kind='ROOT_SELECTED_PRODUCT_INPUT_REFS_V4',selection_role='FENCED-'+kind)
            for field in ('producer_delegation','producer_context','pair','completion','root_component','root_test'):
                ref=self.write(base/'public-inputs'/(kind+'-'+field+'.json'),V.encode(dict(FENCED=field)));self.refs.append(ref);product[field]=ref
            for field in ('archives','signatures'):
                product[field]=[]
                for i in range(2):
                    ref=self.write(base/'public-inputs'/(kind+'-'+field+'-'+str(i)),b'FENCED INERT '+field.encode());self.refs.append(ref);product[field].append(ref)
            self.inputs['stage_inputs']['products'][kind]=product
        self.c = dict(schema=4, issuer='DELEGATED_CONTEXT_PROGRAM_V4', stage=stage, nonce=self.nonce,
                      binding=self.binding, delegation_pin=V.pin(V.encode(self.d)))
        self.facts = dict(api='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3', binding=self.binding, stage=stage,
            nonce=self.nonce, native_architecture='aarch64', daemon_pidfd_held=True,
            whole_owner_deadline_enforced=True, daemon_deadline_enforced=True, exclusive_daemon=True,
            code_pin=V.pin(b'FENCED executor'), domain_policy_pin=V.pin(policy), engine_id='FENCED-engine',
            supervision_program_pin=V.pin(b'FENCED supervisor'), **V.FINAL)
        for role, memory, pids, cpus in [('owner_domain', 2*1024**3, 256, 1), ('daemon_domain', 6*1024**3, 768, 4)]:
            self.facts[role] = dict(pid=123, starttime=456, cgroup='/FENCED/'+role, executable='/FENCED/PRIVATE/tool',
                limits={'memory.max':str(memory), 'memory.swap.max':'0', 'pids.max':str(pids), 'cpu.max':str(cpus*100000)+' 100000'})
        self.facts['storage'] = dict(kernel_enforced=True, scope='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES',
            quota_bytes=32*1024**3, device=123, private_mount='/FENCED/PRIVATE/storage')
        inventory = self.inventory(350 if stage == 'backend' else 374 if stage == 'ui' else 372)
        inv = self.write(self.image_root/('facts-'+stage)/'inventory.lock', inventory)
        self.image_rows = []
        self.command(self.image_rows, self.image_root, 'image', 'native-daemon-info', b'FENCED_PRIVATE_INSPECTION_MUST_NOT_OPEN')
        self.command(self.image_rows, self.image_root, 'image', 'verify-000', self.status())
        self.image = dict(status='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY', binding=self.binding,
            stage=stage, delegation_pin=self.c['delegation_pin'], owner_executor_facts=self.facts,
            Root_final_acceptance=None, independent_image_qualification=None, image_id='sha256:'+'c'*64,
            inventory_pin=inv, packages={'FENCED':'0-1'}, payload_files={},
            cleanup=dict(errors=[], retired_containers=['FENCED']),
            private_retirement=dict(homes_retired=True, no_sockets=True, private_directory_absent=True, failures=[]),
            protected_before=dict(FENCED=V.pin(b'protected')), protected_after=dict(FENCED=V.pin(b'protected')),
            commands=self.image_rows, selected_pair_adoptions_v4=[])
        self.profile = dict(setup8=self.recipe('setup8'), packages={k:self.recipe(k) for k in ('enrollment', 'first-login', 'ui')})
        for kind, product in self.inputs['stage_inputs']['products'].items():
            descriptor=lambda ref:{k:ref[k]for k in ('bytes','sha256')}
            recipe=self.profile['packages'][kind]
            adoption=dict(schema=4,kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4',issuer='DELEGATED_CONTEXT_PROGRAM_V4',
                binding=self.binding,nonce=self.nonce,delegation_pin=self.c['delegation_pin'],current_stage_gpg_required=True,
                component=dict(name=recipe['name'],version=recipe['version'],architecture='any'),archives=[descriptor(r)for r in product['archives']],
                signatures=[descriptor(r)for r in product['signatures']],pair_pin=descriptor(product['pair']),completion_pin=descriptor(product['completion']),
                root_component_decision_pin=descriptor(product['root_component']),root_test_decision_pin=descriptor(product['root_test']),
                public_test_key_pin=descriptor(self.d['materials']['key']),test_fingerprint=self.fingerprint,**V.FINAL)
            self.write(self.output/'adopted'/(kind+'-selected-adoption.json'),V.encode(adoption))
            if stage=='ui':
                self.command(self.image_rows,self.image_root,'image','verify-001',self.status())
                self.command(self.image_rows,self.image_root,'image','verify-selected-001-1',self.status())
                self.image['selected_pair_adoptions_v4'].append(dict(adoption=adoption,current_stage_gpg_steps=['verify-001','verify-selected-001-1']))
        self.rows = []
        self.route = dict(schema=4, kind='DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4', issuer='DELEGATED_CURRENT_OWNER_V3',
            stage=stage, binding=self.binding, nonce=self.nonce, context_pin=V.pin(V.encode(self.c)),
            delegation_pin=self.c['delegation_pin'], image_pin=V.pin(V.encode(self.image)),
            status='PROVISIONAL_CURRENT_'+stage.upper()+'_DATA_ONLY', commands=self.rows,
            owner_facts=dict(architecture='aarch64', page_size=4096),
            owner_cleanup=dict(status='PASS_DELEGATED_CURRENT_STAGE_RETIREMENT', binding=self.binding, nonce=self.nonce,
                stage=stage, natural_retirement=True, owned_container_absence_verified=True, protected_state_unchanged=True, **V.FINAL), **V.FINAL)
        if stage == 'lifecycle': self.lifecycle()
        else: self.builds()
        self.flush()
        # These files are deliberately forbidden to selectors, even if ordinary.
        for name in ('inside.json', 'signature-config.txt', 'owner/secret.json'):
            self.write(self.output/name, b'FENCED_PRIVATE_MUST_NOT_OPEN')

    @staticmethod
    def inventory(count): return ''.join('fiction%03d 0-1\n'%i for i in range(count)).encode()
    def status(self):
        return ('[GNUPG:] VALIDSIG '+self.fingerprint+' 2026-11-16 1 0 4 0 1 10 00 '+self.fingerprint+'\n[GNUPG:] TRUST_ULTIMATE\n').encode()
    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        return dict(path=str(path), **V.pin(raw))
    def material(self, role, raw):
        self.write(self.source/(role+'.data'), raw)
        self.d['materials'][role] = dict(member=role+'.data', **V.pin(raw))
    def recipe(self, kind):
        return dict(name='FENCED-'+kind, version='0-1', archive=kind+'.pkg.tar.zst',
                    files={'PKGBUILD':dict(mode=420, **V.pin(b'FENCED recipe'))},
                    payload_files={'usr/share/FENCED/'+kind:dict(mode=420, **V.pin(b'FENCED payload'))})
    def command(self, rows, root, style, step, raw=b'', errors=b''):
        row = dict(step=step, argv=['/FENCED/PRIVATE/argv'], expected=0, exit=0,
                   output_pin=V.pin(raw), stderr_pin=V.pin(errors), supervision=natural(),
                   timeout_seconds=60, supervision_cap_seconds=59)
        if style == 'local':
            row.update(success=True, log='%03d-%s.log'%(len(rows),step), log_pin=V.pin(raw),
                       channels='stdout+stderr combined in pipe order',cwd='/FENCED/PRIVATE/cwd')
            row.pop('output_pin'); row.pop('stderr_pin'); row.pop('exit'); self.write(root/row['log'], raw)
            held={k:v for k,v in row.items()if k not in ('timeout_seconds','supervision_cap_seconds')}
            request=dict(schema=1,kind='DELEGATED_LOCAL_COMMAND_INVOCATION_REQUEST_V1',step=step,argv_pin=V.pin(V.encode(row['argv'])),
                timeout_seconds=row['timeout_seconds'],deadline_monotonic=1000,max_output_bytes=1024**2)
            selected=dict(schema=1,kind='DELEGATED_LOCAL_SUPERVISION_REQUEST_V1',step=step,request_pin=V.pin(V.encode(request)),
                cap_seconds=row['supervision_cap_seconds'],retirement_seconds=1,grace_seconds=.2,max_output_bytes=1024**2)
            row.update(retirement_seconds=1,grace_seconds=.2,max_output_bytes=1024**2,held_receipt=held,
                local_invocation_v1=dict(schema=1,kind='DELEGATED_LOCAL_COMMAND_INVOCATION_V1',request=request,request_pin=V.pin(V.encode(request)),
                    supervision_request=selected,supervision_request_pin=V.pin(V.encode(selected)),held_receipt_pin=V.pin(V.encode(held)),
                    supervision_result_pin=V.pin(V.encode(row['supervision']))))
            self.write(root/(step+'.invocation-request.json'),V.encode(request));self.write(root/(step+'.supervision-request.json'),V.encode(selected))
        else:
            suffix = '.log' if style == 'image' else '.stdout'
            self.write(root/(step+suffix), raw)
            self.write(root/(step+('.stderr.log' if style == 'image' else '.stderr')), errors)
            if style == 'owner':
                row.update(success=True, log_pin=V.pin(raw), executor_receipt=copy.deepcopy(row))
                self.write(root/(step+'.json'),V.encode(row))
        rows.append(row)
        if style=='owner':self.write(root/'commands.json',V.encode(rows))
        return row
    def builds(self):
        self.route['builds'] = dict(pairs={}, artifacts={})
        status = self.status(); sig = self.command(self.rows, self.output/'commands', 'owner', 'private-signature-setup8', status)
        verified = dict(setup8=dict(status=status.decode(), fingerprint=self.fingerprint, command=sig,
                        archive=V.pin(b'FENCED archive'), signature=V.pin(b'FENCED signature'), trust_scope='TEST_ONLY'))
        if self.stage == 'ui':
            for i in range(2):
                key='first-login-selected-'+str(i)
                row = self.command(self.rows, self.output/'commands', 'owner', 'private-signature-'+key, status)
                verified[key] = dict(verified['setup8'], command=row)
        for kind in V.KINDS[self.stage]:
            recipe = self.profile['packages'][kind]; archive = ('FENCED INERT ARCHIVE '+kind).encode()
            self.route['builds']['artifacts'][kind] = {label:V.pin(archive) for label in ('a','b')}
            for label in ('a','b'):
                prefix = self.output/'builds'/(kind+'-'+label); errors=b'FENCED stderr\n'; log=b'Starting check()\nFENCED PASS\n'
                self.command(self.rows,self.output/'commands','owner','build-'+kind+'-'+label+'-attach',log,errors)
                content={name:(log+errors if name=='build.log' else b'FENCED text\n')for name in R.BUILD_FILES}
                content['validation.json']=V.encode(dict(errors=[],artifacts=[dict(artifact=recipe['archive'],sha256=V.pin(archive)['sha256'],errors=[])]))
                self.command(self.rows,self.output/'commands','owner','validate-'+kind+'-'+label,V.encode(dict(
                    status='PASS_DELEGATED_BUILD_STATIC_VALIDATION',validation_pin=V.pin(content['validation.json']),artifacts={recipe['archive']:V.pin(archive)['sha256']})))
                content['artifacts/'+recipe['archive']]=archive
                content['build-log-components.json']=V.encode(dict(stdout=V.pin(log),stderr=V.pin(errors),composition='stdout followed by stderr; no cross-channel ordering claim'))
                for name, body in content.items(): self.write(prefix/name,body)
                self.write(prefix/'inputs/PKGBUILD',b'FENCED recipe')
                provenance=dict(status='built-package-static-pass',mode='native',builder_host_arch='aarch64',network='none',exit_code=0,
                    artifacts={recipe['archive']:V.pin(archive)['sha256']},
                    files={n:V.pin(b)['sha256']for n,b in content.items()},recipe_inputs={'PKGBUILD':V.pin(b'FENCED recipe')['sha256']},
                    command=['FENCED_PRIVATE_CREATE_MUST_NOT_EXPORT'])
                self.write(prefix/'provenance.json',V.encode(provenance))
            comparison=dict(status='contents-reproduced',errors=[],packages={recipe['archive']:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
            self.route['builds']['pairs'][kind]=comparison
            row=self.command(self.rows,self.output/'commands','owner','current-'+kind+'-compare',V.encode(comparison))
            self.write(self.output/(kind+'-pair.json'),V.encode(dict(binding=self.binding,nonce=self.nonce,archives=[V.pin(archive)]*2,matching_pair=True,comparison_receipt=row,**V.FINAL)))
        retired=[dict(status='REMOVED_AND_ABSENT',cid=('%064x'%(i+1)),name='FENCED-'+str(i),inspection=dict(Id='%064x'%(i+1),State=dict(Running=False,ExitCode=0,OOMKilled=False),Config='FENCED_PRIVATE_INSPECTION'))for i in range(1+2*len(V.KINDS[self.stage]))]
        self.clean=dict(binding=self.binding,stage=self.stage,nonce=self.nonce,failures=[],protected_before={},protected_after={},retired=retired,signature_verifications=verified,**V.FINAL)
        self.write(self.output/'owner-cleanup.json',V.encode(self.clean))
    def lifecycle(self):
        life=dict(status='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY',inventories={},payloads={})
        self.route.update(signed={},protected_before={},protected_after={},lifecycle=life)
        for kind in ('setup8','enrollment','first-login','ui'):
            row={}
            for field in ('archive','signature'):
                raw=('FENCED '+kind+field).encode();self.write(self.output/'signed'/(kind+'.'+field),raw);row[field+'_pin']=V.pin(raw)
            self.route['signed'][kind]=row
            self.command(self.rows,self.output/'commands','local','current-signature-'+kind,self.status())
            self.command(self.rows,self.output/'commands','local','current-pkginfo-'+kind,b'FENCED package metadata')
        steps=('current-baseline','current-dependency-inventory','current-install-inventory','current-after-remove-install','current-reinstall-inventory','current-after-remove-reinstall','current-final-inventory')
        for step,count in zip(steps,(372,373,376,373,376,373,372)):
            raw=self.inventory(count);self.command(self.rows,self.output/'commands','local',step,raw)
            if step!='current-baseline':life['inventories'][step]=V.pin(raw)
        def payload(label,recipe):
            names=[label+'-file-list']+[label+'-'+field+'-0'for field in ('owner','stat','sha256')]
            for name in names:self.command(self.rows,self.output/'commands','local',name,b'FENCED ownership DATA')
            return dict(verified=True,files=recipe['payload_files'])
        life['payloads']['setup8']=payload('current-setup8',self.profile['setup8'])
        for cycle in ('install','reinstall'):
            life['payloads'][cycle]={kind:payload('current-'+cycle+'-'+kind,self.profile['packages'][kind])for kind in ('enrollment','first-login','ui')}
            for step in (cycle,'remove-'+cycle):self.command(self.rows,self.output/'commands','local','current-'+step)
            for kind in ('enrollment','first-login','ui'):self.command(self.rows,self.output/'commands','local','current-'+cycle+'-help-'+kind)
        for label,count in [('install',3),('reinstall',3),('setup8',1)]:
            for i in range(count):
                for flag in ('-e','-L'):self.command(self.rows,self.output/'commands','local','current-absent-'+label+'-'+str(i)+flag)
        outer_rows=[]
        for step in ['private-lifecycle-'+s for s in ('fresh','create','created','attach','terminal')]+['retire-5-'+s for s in ('query','inspect','remove','after-0','after-1')]:
            self.command(outer_rows,self.output/'outer-owner/commands','owner',step,b'FENCED_PRIVATE_INSPECTION_MUST_NOT_OPEN')
        self.route['outer_retirement']=dict(retired=True,cid='d'*64,retirement=dict(status='REMOVED_AND_ABSENT',cid='d'*64,name='FENCED-outer'),command_receipts=outer_rows,
            created=dict(Id='d'*64),terminal=dict(Id='d'*64,State=dict(Running=False,ExitCode=0,OOMKilled=False)))
        for step in ('current-install-setup8','current-remove-setup8'):self.command(self.rows,self.output/'commands','local',step)
        local=dict(body_success=True,protected_state_unchanged=True,failures=[],private_retirement=dict(homes_retired=True,no_sockets=True,private_directory_absent=True))
        self.write(self.output/'owner-local.json',V.encode(local))
        admin=[];self.command(admin,self.output/'owner-admin/commands','local','import-root-test-public',b'FENCED_PRIVATE_MUST_NOT_OPEN')
        self.write(self.output/'owner-admin/commands/commands.json',V.encode(admin))
        self.inputs['stage_inputs']['retention']={}
        for role in ('prior_backend','prior_ui'):
            ref=self.write(self.base/(role+'.capsule'),b'FENCED PRIOR PUBLIC CAPSULE '+role.encode());self.refs.append(ref);self.inputs['stage_inputs']['retention'][role]=ref
    def flush(self):
        self.write(self.image_root/'image-provisional.json',V.encode(self.image))
        self.write(self.output/'route.json',V.encode(self.route))
        if self.stage=='lifecycle':self.write(self.output/'commands/commands.json',V.encode(self.rows))
    def collect(self):
        return V.collect(R,stage=self.stage,output=self.output,source_root=self.source,delegation=self.d,context=self.c,
            image_report=self.image,stage_report=self.route,profile=self.profile,inputs=self.inputs,executor_facts=self.facts,approved_refs=self.refs)


class Controls(unittest.TestCase):
    def fixture(self,stage='backend'):
        t=tempfile.TemporaryDirectory(prefix='FENCED-delegated-retention-');self.addCleanup(t.cleanup)
        return Fixture(Path(t.name),stage)
    def test_three_stage_exact_bodies_real_encoder_and_no_private_reads(self):
        for stage in V.KINDS:
            with self.subTest(stage=stage):
                f=self.fixture(stage);original=R.read_file
                def read(path,*args,**kwargs):
                    name=Path(path).name
                    self.assertNotIn(name,('inside.json','signature-config.txt','secret.json','native-daemon-info.log','private-lifecycle-inspect.stdout'))
                    return original(path,*args,**kwargs)
                from unittest.mock import patch
                with patch.object(R,'read_file',side_effect=read):bodies,origins=f.collect()
                from types import SimpleNamespace
                # Only external Source authentication is replaced by this explicit
                # MODEL seam; real selection, manifest, files and encoder run.
                with patch.object(V,'request',return_value=(R,E.bundle,f.refs)):
                    result=V.retain_delegated_stage(stage=stage,output=f.output,destination=f.destination,
                        source_root=f.source,delegation=f.d,context=f.c,image_report=f.image,stage_report=f.route,
                        profile=f.profile,inputs=f.inputs,executor=SimpleNamespace(facts=f.facts))
                self.assertEqual(result['evidence_state'],'COMPLETE');self.assertIsNone(result['Root_final_acceptance'])
                self.assertEqual(result['manifest']['kind'],V.KIND)
                self.assertEqual(Path(result['capsule_path']).read_bytes(),result['capsule'])
                with tarfile.open(fileobj=io.BytesIO(result['capsule']),mode='r:gz')as archive:
                    exported=b''.join(archive.extractfile(m).read()for m in archive.getmembers()if m.isfile())
                for marker in (b'FENCED_PRIVATE',b'/FENCED/PRIVATE'):
                    self.assertNotIn(marker,exported)
                if stage=='lifecycle':self.assertIn('prior/prior_ui.capsule',bodies)
                else:self.assertTrue(any(n.endswith('.pkg.tar.zst')for n in bodies))
    def test_source_loader_refuses_missing_or_modified_pure_basis(self):
        f=self.fixture();path=f.source/V.LEGACY;path.parent.mkdir(parents=True);path.write_bytes(b'FENCED changed')
        with self.assertRaisesRegex(ValueError,'immutable pure'):V.request(f.source,f.d,f.c,f.inputs,f.profile)
        path.unlink();path.symlink_to(HERE/'retention_current_v3.py')
        with self.assertRaisesRegex(ValueError,'ordinary closed'):V.request(f.source,f.d,f.c,f.inputs,f.profile)
    def test_hundreds_of_image_gpg_bodies_preserve_pins_inside_existing_member_cap(self):
        import base64
        f=self.fixture()
        for i in range(1,250):f.command(f.image_rows,f.image_root,'image','verify-%03d'%i,f.status(),b'')
        f.route['image_pin']=V.pin(V.encode(f.image));f.flush();bodies,_=f.collect()
        frames=[json.loads(raw)for name,raw in bodies.items()if name.startswith('streams/image/bodies-')]
        streams=[row for frame in frames for row in frame['streams']]
        self.assertEqual(len(streams),250);self.assertLess(len(bodies),V.MAX_MEMBERS)
        for row in streams:
            for field in ('stdout','stderr'):
                self.assertEqual(V.pin(base64.b64decode(row[field]['base64'],validate=True)),row[field]['pin'])
    def test_exact_public_pass_elapsed_bounds_retirement_and_stream_index_joins(self):
        f=self.fixture();row=f.image_rows[1];row['supervision']['emergency_retirement']=False
        f.route['image_pin']=V.pin(V.encode(f.image));f.flush();bodies,_=f.collect()
        index=json.loads(bodies['streams/image/commands.public.json']);self.assertEqual(index['count'],len(f.image_rows))
        self.assertEqual(index['kind'],'DELEGATED_PUBLIC_COMMAND_INDEX_V4')
        self.assertEqual(index['source']['report_pin'],V.pin((f.image_root/'image-provisional.json').read_bytes()))
        public=index['rows'][1]
        for key in ('timeout_seconds','supervision_cap_seconds','exit','expected'):self.assertEqual(public[key],row[key])
        for key in ('passed','seconds','emergency_retirement','ownership','group_census','reaped'):
            self.assertEqual(public['supervision'][key],row['supervision'][key])
        self.assertNotIn('success',public);self.assertNotIn('argv',public);self.assertNotIn('executed_argv',public)
        self.assertEqual(public['original_receipt_pin'],V.pin(V.encode(row)))
        frame=json.loads(bodies[public['body_frame']]);self.assertEqual(frame['streams'][0]['stdout']['pin'],public['output_pin'])
    def test_expected_nonzero_preserves_false_zero_exit_pass_without_relabelling(self):
        f=self.fixture();row=f.command(f.image_rows,f.image_root,'image','no-agent-private-0',b'',b'gpg-connect-agent: no gpg-agent running in this session\n')
        row['expected']=row['exit']=row['supervision']['exit']=2;row['supervision']['passed']=False
        f.route['image_pin']=V.pin(V.encode(f.image));f.flush();bodies,_=f.collect()
        value=json.loads(bodies['streams/image/commands.public.json'])['rows'][-1]
        self.assertFalse(value['supervision']['passed']);self.assertEqual(value['exit'],2)
        self.assertNotIn('success',value)
    def test_missing_or_false_or_unbounded_original_observations_refuse(self):
        f=self.fixture();original=f.image_rows[1]
        for change in ('passed','seconds','timeout_seconds','supervision_cap_seconds','false-pass','nan','infinite',
                       'negative','late','over-request','over-delegation','forced','bool-seconds'):
            row=copy.deepcopy(original)
            if change in ('passed','seconds'):del row['supervision'][change]
            elif change in ('timeout_seconds','supervision_cap_seconds'):del row[change]
            elif change=='false-pass':row['supervision']['passed']=False
            elif change=='nan':row['supervision']['seconds']=float('nan')
            elif change=='infinite':row['supervision_cap_seconds']=float('inf')
            elif change=='negative':row['supervision']['seconds']=-1
            elif change=='late':row['supervision']['seconds']=row['supervision_cap_seconds']
            elif change=='over-request':row['supervision_cap_seconds']=row['timeout_seconds']+1
            elif change=='over-delegation':row['timeout_seconds']=1801
            elif change=='forced':row['supervision']['emergency_retirement']=True
            else:row['supervision']['seconds']=True
            with self.subTest(change=change),self.assertRaises(ValueError):V.command_observations(row,1800)
    def test_current_local_callback_missing_original_bounds_is_specific_hold(self):
        f=self.fixture('lifecycle')
        # Exact omission observed in committed developer_workflow.Commands rows.
        for row in f.rows:
            row.pop('timeout_seconds');row.pop('supervision_cap_seconds')
        f.flush()
        with self.assertRaisesRegex(ValueError,'HOLD_MISSING_ORIGINAL_COMMAND_BOUND:timeout_seconds'):f.collect()
        self.assertFalse(f.destination.exists())
    def test_local_request_and_retirement_bodies_are_original_pinned_public_frames(self):
        import base64
        f=self.fixture('lifecycle');bodies,_=f.collect()
        index=json.loads(bodies['streams/stage/commands.public.json']);public=index['rows'][0];original=f.rows[0]
        for key in ('retirement_seconds','grace_seconds','max_output_bytes','success'):
            self.assertEqual(public[key],original[key])
        self.assertNotIn('exit',public);self.assertNotIn('held_receipt',public)
        self.assertEqual(public['local_invocation_v1'],original['local_invocation_v1'])
        frame=json.loads(bodies[public['invocation_frame']]);record=next(r for r in frame['rows']if r['step']==public['step'])
        for role,suffix in [('request','.invocation-request.json'),('supervision_request','.supervision-request.json')]:
            raw=base64.b64decode(record[role]['base64'],validate=True)
            self.assertEqual(raw,(f.output/'commands'/(public['step']+suffix)).read_bytes());self.assertEqual(V.pin(raw),record[role]['pin'])
        streams=json.loads(bodies[public['body_frame']]);body=next(r for r in streams['streams']if r['step']==public['step'])
        self.assertEqual(base64.b64decode(body['combined']['base64'],validate=True),(f.output/'commands'/original['log']).read_bytes())
    def test_lifecycle_original_request_missing_or_forged_refuses(self):
        for change in ('missing-proof','request-body','request-pin','held-receipt'):
            f=self.fixture('lifecycle');row=f.rows[0]
            if change=='missing-proof':row.pop('local_invocation_v1')
            elif change=='request-body':(f.output/'commands'/(row['step']+'.supervision-request.json')).write_bytes(b'{}\n')
            elif change=='request-pin':row['local_invocation_v1']['request_pin']=V.pin(b'wrong')
            else:row['held_receipt']['argv']=['/FENCED/tampered']
            f.flush()
            with self.subTest(change=change),self.assertRaises(ValueError):f.collect()
    def test_actual_profile_sized_lifecycle_stays_inside_unchanged_member_caps(self):
        f=self.fixture('lifecycle');profile=json.loads((HERE.parents[1]/'successor_v2/profile.json').read_bytes())
        counts={'setup8':len(profile['setup8']['payload_files'])}|{k:len(r['payload_files'])for k,r in profile['packages'].items()}
        for kind,count in counts.items():
            recipe=f.profile['setup8']if kind=='setup8'else f.profile['packages'][kind]
            files=recipe['payload_files']
            for i in range(1,count):files['usr/share/FENCED/'+kind+'-'+str(i)]=dict(mode=420,**V.pin(b'FENCED payload'))
            labels=['current-setup8']if kind=='setup8'else['current-'+cycle+'-'+kind for cycle in ('install','reinstall')]
            for label in labels:
                for i in range(1,count):
                    for field in ('owner','stat','sha256'):f.command(f.rows,f.output/'commands','local',label+'-'+field+'-'+str(i),b'FENCED profile-sized DATA')
        for label,before,count in [('setup8',1,counts['setup8']),('install',3,sum(counts[k]for k in ('enrollment','first-login','ui'))),('reinstall',3,sum(counts[k]for k in ('enrollment','first-login','ui')))]:
            for i in range(before,count):
                for flag in ('-e','-L'):f.command(f.rows,f.output/'commands','local','current-absent-'+label+'-'+str(i)+flag)
        f.flush();bodies,_=f.collect()
        self.assertGreater(len(f.rows),350);self.assertLessEqual(len(f.rows),512);self.assertLess(len(bodies),V.MAX_MEMBERS)
        local=json.loads(bodies['streams/stage/commands.public.json']);self.assertEqual(local['count'],len(f.rows))
    def test_owner_public_bounds_must_match_original_executor_receipt(self):
        f=self.fixture();row=f.rows[0];row['supervision_cap_seconds']-=1
        f.write(f.output/'commands'/(row['step']+'.json'),V.encode(row))
        f.write(f.output/'commands/commands.json',V.encode(f.rows));f.flush()
        with self.assertRaisesRegex(ValueError,'original executor command/timing/channel'):f.collect()
    def test_actual_base_provenance_keeps_all_pins_and_excludes_private_reference_paths(self):
        image={};value=dict(factory_profile_pin=V.pin(b'FENCED factory'),original_package_count=341,
            supplemental_package_count=8,final_package_count=349,materials=[])
        for key in ('base_lock','bootstrap_profile','baseline_inventory'):
            image[key]=dict(path='/FENCED/PRIVATE/'+key,**V.pin(key.encode()));value[key]=image[key]
        for group,count in [('base_materials',249),('supplemental_materials',8)]:
            image[group]={}
            for i in range(count):
                filename=group+'-%03d.pkg'%i;archive=dict(path='/FENCED/PRIVATE/'+filename,**V.pin(filename.encode()))
                sig=dict(path='/FENCED/PRIVATE/'+filename+'.sig',**V.pin(b'FENCED sig'));image[group][filename]=archive;image[group][filename+'.sig']=sig
                value['materials'].append(dict(name=filename,version='FENCED',arch='aarch64',filename=filename,archive=archive,
                    signature=sig,source_group=group,metadata_pin=V.pin(b'FENCED metadata')))
        public=V.base_provenance_public(value,image);self.assertEqual(len(public['materials']),257)
        self.assertNotIn(b'/FENCED/PRIVATE',V.encode(public));self.assertNotIn(b'"path"',V.encode(public))
        bad=copy.deepcopy(value);bad['materials'][-1]['signature']['sha256']='0'*64
        with self.assertRaises(ValueError):V.base_provenance_public(bad,image)
    def test_unknown_actual_job_and_wrong_context_report_hold(self):
        for change in ('job','nonce','binding','context_pin','image_pin','Root_final_acceptance'):
            f=self.fixture()
            if change=='job':f.binding['job']=None
            elif change=='nonce':f.route[change]='f'*64
            elif change=='binding':f.route[change]=dict(f.binding,run='999')
            elif change=='Root_final_acceptance':f.route[change]=True
            else:f.route[change]=V.pin(b'wrong')
            f.flush()
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):f.collect()
    def test_uncertain_cleanup_image_trust_and_domain_limits_hold(self):
        for change in ('owner','image','private','limits','storage'):
            f=self.fixture()
            if change=='owner':f.route['owner_cleanup']['owned_container_absence_verified']=False
            elif change=='image':f.image['cleanup']['errors']=['FENCED failure']
            elif change=='private':f.image['private_retirement']['homes_retired']=False
            elif change=='limits':f.facts['daemon_domain']['limits']['memory.max']='max'
            else:f.facts['storage']['kernel_enforced']=False
            f.route['image_pin']=V.pin(V.encode(f.image));f.flush()
            with self.subTest(change=change),self.assertRaises(ValueError):f.collect()
    def test_missing_pair_archive_compare_channel_and_static_bodies_hold(self):
        for change in ('archive','compare','stderr','validation','recipe','pair'):
            f=self.fixture();prefix=f.output/'builds/enrollment-a'
            if change=='archive':(prefix/'artifacts/enrollment.pkg.tar.zst').unlink()
            elif change=='compare':f.route['builds']['pairs']['enrollment']['errors']=['FENCED']
            elif change=='stderr':(f.output/'commands/build-enrollment-a-attach.stderr').write_bytes(b'changed')
            elif change=='validation':(prefix/'validation.json').unlink()
            elif change=='recipe':(prefix/'inputs/PKGBUILD').write_bytes(b'changed')
            else:(f.output/'enrollment-pair.json').unlink()
            f.flush()
            with self.subTest(change=change),self.assertRaises((ValueError,FileNotFoundError)):f.collect()
    def test_gpg_bad_status_or_missing_original_command_refuses(self):
        for change in ('bad','command','body'):
            f=self.fixture();row=f.clean['signature_verifications']['setup8']
            if change=='bad':row['status']+='[GNUPG:] EXPKEYSIG FENCED\n'
            elif change=='command':row['command']=dict(row['command'],step='forged')
            else:(f.output/'commands/private-signature-setup8.stdout').unlink()
            f.write(f.output/'owner-cleanup.json',V.encode(f.clean));f.flush()
            with self.subTest(change=change),self.assertRaises((ValueError,FileNotFoundError)):f.collect()
    def test_both_selected_image_signatures_and_original_owner_adoption_are_required(self):
        for change in ('second-status','image-receipt','owner-receipt','pair-pin'):
            f=self.fixture('ui')
            if change=='second-status':(f.image_root/'verify-selected-001-1.log').unlink()
            elif change=='image-receipt':f.image['selected_pair_adoptions_v4']=[]
            elif change=='owner-receipt':(f.output/'adopted/first-login-selected-adoption.json').unlink()
            else:f.image['selected_pair_adoptions_v4'][0]['adoption']['pair_pin']=V.pin(b'FENCED wrong pair')
            f.route['image_pin']=V.pin(V.encode(f.image));f.flush()
            with self.subTest(change=change),self.assertRaises((ValueError,FileNotFoundError)):f.collect()
    def test_credential_shaped_json_refuses_before_publish(self):
        for key in ('GITHUB_TOKEN','Authorization','api_token','private_key'):
            f=self.fixture();f.route['unknown']={key:'FENCED_INERT_CREDENTIAL_MARKER'};f.flush()
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'credential-shaped'):f.collect()
            self.assertFalse(f.destination.exists())
    def test_credential_json_cannot_hide_inside_base64_image_stream(self):
        f=self.fixture();row=f.image_rows[1];raw=V.encode(dict(nested=[dict(Authorization='FENCED_INERT_MARKER')]))
        row['output_pin']=V.pin(raw);f.write(f.image_root/(row['step']+'.log'),raw)
        f.route['image_pin']=V.pin(V.encode(f.image));f.flush()
        with self.assertRaisesRegex(ValueError,'credential-shaped'):f.collect()
    def test_original_index_drift_alias_or_unapproved_product_refuses(self):
        for change in ('index','symlink','hardlink','unapproved','missing-signature'):
            f=self.fixture('ui')
            if change=='index':f.write(f.output/'commands/private-signature-setup8.json',V.encode(dict(FENCED='forged')))
            elif change in ('symlink','hardlink'):
                path=f.output/'commands/private-signature-setup8.stdout';old=f.base/'public-status';path.rename(old)
                if change=='symlink':path.symlink_to(old)
                else:os.link(old,path)
            elif change=='unapproved':f.refs.clear()
            else:f.inputs['stage_inputs']['products']['first-login']['signatures'].pop()
            with self.subTest(change=change),self.assertRaises((ValueError,OSError)):f.collect()
    def test_lifecycle_missing_prior_signed_gpg_payload_or_outer_hold(self):
        for change in ('prior','signed','gpg','payload','outer','local'):
            f=self.fixture('lifecycle')
            if change=='prior':f.inputs['stage_inputs'].pop('retention')
            elif change=='signed':(f.output/'signed/ui.signature').unlink()
            elif change=='gpg':(f.output/'commands'/next(r['log']for r in f.rows if r['step']=='current-signature-ui')).unlink()
            elif change=='payload':f.route['lifecycle']['payloads']['install']['ui']['verified']=False
            elif change=='outer':f.route['outer_retirement']['retired']=False
            else:f.write(f.output/'owner-local.json',V.encode(dict(body_success=False)))
            f.flush()
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError,FileNotFoundError)):f.collect()
    def test_publication_rejects_existing_destination_and_encoder_mutation(self):
        f=self.fixture();bodies,_=f.collect();manifest=dict(stage=f.stage)
        f.destination.mkdir()
        with self.assertRaisesRegex(ValueError,'fresh public'):V.publish(R,E.bundle,f.destination,bodies,manifest)
        other=f.base/'new-public'
        def mutate(root):
            path=root/'unexpected';path.write_bytes(b'FENCED');return b'FENCED CAPSULE'
        with self.assertRaisesRegex(ValueError,'staging drift'):V.publish(R,mutate,other,bodies,manifest)
    def test_audit_fence_and_retained_caps_unchanged(self):
        for event in ('socket.connect','subprocess.Popen','os.system','os.fork','fcntl.flock'):
            with self.subTest(event=event),self.assertRaises(AssertionError):sys.audit(event)
        self.assertEqual((V.MAX_FILE,V.MAX_TOTAL,V.MAX_MEMBERS,V.MAX_COMPRESSED),(R.MAX_FILE,R.MAX_TOTAL,R.MAX_MEMBERS,R.MAX_COMPRESSED))


if __name__=='__main__':unittest.main()
