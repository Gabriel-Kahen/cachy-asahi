# SPDX-License-Identifier: MIT
"""Portable MODEL rebind controls; no historical inputs, actors or Git children."""
import copy
import ctypes # Initialize the standard module before the actor fence.
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.fork','os.exec','os.posix_spawn','resource.setrlimit','fcntl.flock'):
        raise AssertionError('v5 MODEL DATA: no actor boundary '+event)


sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('diagnostic_v5_DATA_controls',HERE/'prepare.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class Controls(unittest.TestCase):
    def setUp(self):
        self.V4,self.P,self.C,self.H=M.load_helpers();C=self.C;V4=self.V4
        original={'carrier/MODEL-public.DATA':(b'INERT PUBLIC DATA\n',0o644),'recipes/MODEL.PKGBUILD':(b'# MODEL NEVER BUILD\n',0o644)}
        source=dict(schema=1,kind=C.KIND,operation=C.OPERATION,files=C.descriptors(original),actual=dict(Source=None))
        mapping=(C.encoded(source),0o644);original['source-map.json']=original['source.lock.json']=mapping
        self.original=dict(original);files=dict(original);roles={}
        roster=(*V4.ROLES,*V4.PREREQUISITE_FILES,*V4.STAGING_FILES)
        for role in roster:
            member=M.REPLACEMENTS[role]['member']if role in M.REPLACEMENTS else'MODEL-programs/'+role+'.py'
            raw=('MODEL INERT OLD '+role+'\n').encode();files[member]=(raw,0o644);roles[role]=dict(member=member,**C.pin(raw))
        member,_,_=V4.BUILD_VALIDATOR;files[member]=((HERE.parents[3]/member).read_bytes(),0o644)
        materials={}
        for index in range(64):
            member='carrier/MODEL-material-%02d.DATA'%index;raw=('MODEL PUBLIC MATERIAL %02d\n'%index).encode();files[member]=(raw,0o644)
            materials['model_%02d'%index]=dict(member=member,**C.pin(raw))
        staging=dict(list(materials.items())[59:]);program=dict(schema=4,kind='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4',operation=V4.OP,
            roles=roles,delegation_programs=V4.delegation_programs(roles,files),staging_materials=staging,
            closure_commit='a'*40,actual=dict.fromkeys(V4.ACTUAL))
        files[M.OLD_PROGRAM]=(C.encoded(program),0o644)
        files['inputs/delegated-materials-v4.json']=(C.encoded(dict(materials=dict(list(materials.items())[:59]))),0o644)
        files[V4.PREFIX+'/prepare.py']=(b'# INERT OLD MODEL CONSTRUCTOR\n',0o644)
        files[V4.PREFIX+'/README.md']=(b'INERT OLD MODEL DOCUMENT\n',0o644)
        files['provenance/v4/v3-source-map.json']=mapping
        inverse=V4.PREFIX+'/inverse.json';remove=sorted([*(set(files)-set(original)),inverse])
        files[inverse]=(C.encoded(dict(schema=4,kind='DELEGATED_SOURCE_V4_TO_V3_INVERSE_DATA_ONLY',original_map=C.pin(mapping[0]),
            original_files=len(original),original_bytes=sum(len(v[0])for v in original.values()),remove=remove,actual_acceptance=None)),0o644)
        source['files']=C.descriptors({n:v for n,v in files.items()if n not in('source-map.json','source.lock.json')})
        files['source-map.json']=files['source.lock.json']=(C.encoded(source),0o644)
        self.files=files;self.assertEqual(V4.inverse_v3(files),self.original)
        self.basis=dict(files=len(files),bytes=sum(len(v[0])for v in files.values()),tree=self.H.tree(files),source_map=C.pin(files['source-map.json'][0]))
        self.replacements={role:(('MODEL INERT NEW '+role+'\n').encode(),0o644)for role in M.REPLACEMENTS}
        self.pins={role:dict(member=M.REPLACEMENTS[role]['member'],**C.pin(raw))for role,(raw,_)in self.replacements.items()}
        self.construction={name:((HERE/name).read_bytes(),0o644)for name in('prepare.py','README.md')}
        self.commit='b'*40
    def model(self):
        # Only the unavailable historical identity is modeled. All maintained
        # rebind, map, descriptor, cap and both inverse implementations run.
        return patch.multiple(M,SOURCE179=self.basis,REPLACEMENTS=self.pins,validate_basis=lambda files:None,
            load_helpers=lambda:(self.V4,self.P,self.C,self.H))
    def rebind(self,files=None,replacements=None,**kw):
        return M.rebind(self.files if files is None else files,self.replacements if replacements is None else replacements,
            commit=kw.get('commit',self.commit),constructor_files=kw.get('constructor_files',self.construction))
    def test_fixed_real_constructor_pins_roster_and_historical_identity_are_not_models(self):
        self.assertEqual(set(M.REPLACEMENTS),{'hosted_launcher','material_domain_executor','materials_stager'})
        self.assertEqual(M.SOURCE179,dict(files=179,bytes=45330627,tree='5128864b3c17f230d5045361014b41ce31b72767',
            source_map=dict(bytes=35107,sha256='063a34c64d9e9ad21e6c2bd5c4e0a147f88890061cd79fb13587bc1e37e9d7f4')))
        self.assertEqual({role:(row['bytes'],row['sha256'])for role,row in M.REPLACEMENTS.items()},dict(
            hosted_launcher=(66059,'5685fa9149242fd878ce81ddbe4368a0f6317de71c654962311de4fdb631fa14'),
            material_domain_executor=(40975,'da8e397a63e02c11758d08bf2c45ecf14d94029f6311f4fcb4a09ad420624c8b'),
            materials_stager=(35550,'58c5d0842c17a914239b5f24e9e1ac2987ad8ec9ce9e2a03e63a04f2e2e99282')))
        with self.assertRaises(ValueError):M.validate_basis(self.files)
    def test_exact_three_replacements_nine_additions_and_both_real_inverses(self):
        before=copy.deepcopy(self.files);operands=copy.deepcopy(self.replacements)
        with self.model():
            candidate,profile=self.rebind();self.assertEqual(M.inverse_v4(candidate),before);self.assertEqual(M.inverse_v3(candidate),self.original)
        changed={n for n in before if before[n]!=candidate[n]}
        self.assertEqual(changed,{'source-map.json','source.lock.json',*(row['member']for row in self.pins.values())})
        self.assertEqual(len(set(candidate)-set(before)),9);self.assertEqual(self.files,before);self.assertEqual(self.replacements,operands)
        for name in (M.OLD_PROGRAM,self.V4.PREFIX+'/inverse.json',self.V4.PREFIX+'/prepare.py',self.V4.PREFIX+'/README.md','provenance/v4/v3-source-map.json'):
            self.assertEqual(candidate[name],before[name])
        self.assertEqual(candidate[M.PROVENANCE+'/source179-map.json'],before['source-map.json'])
        for role,row in self.pins.items():self.assertEqual(candidate[M.PROVENANCE+'/original/'+row['member']],before[row['member']])
        mapping=self.C.decode(candidate['source-map.json'][0]);self.assertEqual(candidate['source-map.json'],candidate['source.lock.json'])
        self.assertEqual(mapping['files'],self.C.descriptors({n:v for n,v in candidate.items()if n not in('source-map.json','source.lock.json')}))
        self.assertEqual(profile['prospective_tree'],self.H.tree(candidate))
    def test_program_provenance_profile_are_closed_joined_unissued_data(self):
        with self.model():candidate,profile=self.rebind()
        C=self.C;old=C.decode(self.files[M.OLD_PROGRAM][0]);program=C.decode(candidate[M.PREFIX+'/program.json'][0]);provenance=C.decode(candidate[M.PROVENANCE+'/rebind.json'][0])
        self.assertEqual(program['schema'],5);self.assertEqual(program['kind'],'DELEGATED_CURRENT_DIAGNOSTIC_PROGRAM_REGISTRY_V5')
        self.assertNotIn('closure_commit',program);self.assertEqual(program['basis_closure_commit'],old['closure_commit']);self.assertEqual(program['diagnostics_commit'],self.commit)
        self.assertEqual(program['rebind_provenance'],dict(member=M.PROVENANCE+'/rebind.json',**C.pin(candidate[M.PROVENANCE+'/rebind.json'][0])))
        self.assertEqual(len(program['roles']),27);self.assertEqual(len(program['delegation_programs']),25);self.assertEqual(len(profile['materials'])+len(profile['staging_materials']),64)
        self.assertEqual({role for role in old['roles']if old['roles'][role]!=program['roles'][role]},set(self.pins))
        for role,row in self.pins.items():
            self.assertEqual(program['roles'][role],row);self.assertEqual(program['delegation_programs'][role],row)
            change=provenance['replacements'][role];self.assertEqual(change['replacement'],dict(C.pin(self.replacements[role][0]),mode=0o644));self.assertEqual(change['original'],dict(C.pin(self.files[row['member']][0]),mode=0o644))
        self.assertEqual(profile['delegation_programs'],program['delegation_programs']);self.assertEqual(profile['program'],dict(path=M.PREFIX+'/program.json',**C.pin(candidate[M.PREFIX+'/program.json'][0])))
        for value in (profile,program,provenance):self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertEqual(provenance['construction'],{M.PREFIX+'/'+n:dict(C.pin(v[0]),mode=v[1])for n,v in self.construction.items()})
    def test_unknown_partial_changed_body_mode_commit_and_constructor_refuse(self):
        for mode in ('missing','extra','body','mode','commit','constructor-missing','constructor-extra','constructor-mode','constructor-empty'):
            replacements=copy.deepcopy(self.replacements);construction=copy.deepcopy(self.construction);commit=self.commit
            role=next(iter(replacements));raw,_=replacements[role]
            if mode=='missing':del replacements[role]
            elif mode=='extra':replacements['unknown']=(b'MODEL',0o644)
            elif mode=='body':replacements[role]=(raw+b'DRIFT',0o644)
            elif mode=='mode':replacements[role]=(raw,0o755)
            elif mode=='commit':commit='HEAD'
            elif mode=='constructor-missing':del construction['README.md']
            elif mode=='constructor-extra':construction['unexpected.py']=(b'MODEL',0o644)
            elif mode=='constructor-mode':construction['README.md']=(b'MODEL',0o755)
            else:construction['README.md']=(b'',0o644)
            with self.subTest(mode=mode),self.model(),self.assertRaises(ValueError):self.rebind(replacements=replacements,commit=commit,constructor_files=construction)
    def test_collisions_registry_authority_and_caps_refuse(self):
        for mode in ('collision','role','program','material','authority','files-cap','bytes-cap','file-cap'):
            files=copy.deepcopy(self.files);registry=self.C.decode(files[M.OLD_PROGRAM][0]);limit=dict(MAX_FILES=self.C.MAX_FILES)
            if mode=='collision':files[M.PROVENANCE+'/rebind.json']=(b'FOREIGN MODEL DATA',0o644)
            elif mode=='role':registry['roles'].pop('context')
            elif mode=='program':registry['delegation_programs'].pop('context')
            elif mode=='material':registry['staging_materials'].pop(next(iter(registry['staging_materials'])))
            elif mode=='authority':registry['actual']['Root_delegation']='MODEL REFUSED AUTHORITY'
            elif mode=='files-cap':limit=dict(MAX_FILES=len(files))
            elif mode=='bytes-cap':limit=dict(MAX_TOTAL=1)
            else:limit=dict(MAX_FILE=1)
            files[M.OLD_PROGRAM]=(self.C.encoded(registry),0o644)
            with self.subTest(mode=mode),self.model(),patch.multiple(self.C,**limit),self.assertRaises(ValueError):self.rebind(files=files)
    def test_inverse_refuses_backup_map_manifest_or_untouched_body_drift(self):
        with self.model():candidate,_=self.rebind()
        for mode in ('backup','map','remove','restore','untouched','extra','basis'):
            files=copy.deepcopy(candidate);inverse=self.C.decode(files[M.PREFIX+'/inverse.json'][0])
            if mode=='backup':name=next(iter(inverse['restore'].values()));files[name]=(b'DRIFT',0o644)
            elif mode=='map':files[M.PROVENANCE+'/source179-map.json']=(b'DRIFT',0o644)
            elif mode=='remove':inverse['remove'].pop()
            elif mode=='restore':inverse['restore'].pop(next(iter(inverse['restore'])))
            elif mode=='untouched':files['carrier/MODEL-public.DATA']=(b'DRIFT',0o644)
            elif mode=='extra':files['FOREIGN.DATA']=(b'DRIFT',0o644)
            else:inverse['basis']['tree']='0'*40
            files[M.PREFIX+'/inverse.json']=(self.C.encoded(inverse),0o644)
            with self.subTest(mode=mode),self.model(),self.assertRaises(ValueError):M.inverse_v4(files)
    def test_assemble_reads_only_exact_committed_members_before_pure_rebind(self):
        helpers=(self.V4,self.P,self.C,self.H);calls=[]
        def blob(repo,revision,name,expected=None):
            calls.append((revision,name,expected))
            for role,row in self.pins.items():
                if row['member']==name:self.assertEqual(expected,dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644));return self.replacements[role]
            return self.construction[Path(name).name]
        with self.model(),patch.object(M,'load_helpers',return_value=helpers),patch.object(M,'load_basis',return_value=self.files),patch.object(self.P,'commit')as committed,patch.object(self.P,'blob',side_effect=blob),patch.object(M,'rebind',return_value=('MODEL FILES','MODEL PROFILE'))as rebind:
            self.assertEqual(M.assemble(Path('/MODEL/LOCAL-REPO'),Path('/MODEL/BASIS'),self.commit),('MODEL FILES','MODEL PROFILE'))
            committed.assert_called_once_with(Path('/MODEL/LOCAL-REPO'),self.commit);self.assertEqual(len(calls),5)
            rebind.assert_called_once_with(self.files,self.replacements,commit=self.commit,constructor_files=self.construction)
        bad=dict(self.construction);bad['README.md']=(b'UNCOMMITTED MODEL DRIFT',0o644)
        with self.model(),patch.object(M,'load_helpers',return_value=helpers),patch.object(M,'load_basis',return_value=self.files),patch.object(self.P,'commit'),patch.object(self.P,'blob',side_effect=blob),patch.object(self.C,'read',side_effect=lambda path:bad[path.name]),patch.object(M,'rebind',side_effect=AssertionError('no rebind after drift')):
            with self.assertRaises(ValueError):M.assemble(Path('/MODEL/LOCAL-REPO'),Path('/MODEL/BASIS'),self.commit)
    def test_global_fence_refuses_actor_network_privilege_and_lease_boundaries(self):
        for event in ('subprocess.Popen','socket.connect','ctypes.dlopen','os.system','os.fork','os.exec','os.posix_spawn','resource.setrlimit','fcntl.flock'):
            with self.subTest(event=event),self.assertRaises(AssertionError):fence(event,())


if __name__=='__main__':unittest.main(verbosity=2)
