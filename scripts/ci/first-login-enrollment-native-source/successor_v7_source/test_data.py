# SPDX-License-Identifier: MIT
"""Tiny MODEL Source196; real v7/v6/v5/v4 pure inverse implementations."""
import contextlib
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


M=load('transport_v7_constructor',HERE/'prepare.py')
B=load('transport_v7_v6_MODEL_basis',HERE.parent/'successor_v6_source/test_data.py')


class Controls(unittest.TestCase):
    def setUp(self):
        self.fixture=B.Controls();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        b=self.fixture;self.C,self.H=b.C,b.H;old=b.fixture
        self.basis196,_=b.rebind();self.basis188,self.basis179,self.basis139=b.basis188,b.basis179,b.basis139
        self.basis=dict(files=len(self.basis196),bytes=sum(len(v[0])for v in self.basis196.values()),
                        tree=self.H.tree(self.basis196),source_map=self.C.pin(self.basis196['source-map.json'][0]))
        self.real_pins,self.real_basis,self.real_helpers=M.REPLACEMENTS,M.SOURCE196,M.load_helpers
        self.replacements={role:(('MODEL INERT TRANSPORT '+role+'\n').encode(),0o644)for role in M.REPLACEMENTS}
        self.pins={role:dict(member=M.REPLACEMENTS[role]['member'],**self.C.pin(raw))for role,(raw,_)in self.replacements.items()}
        self.construction={name:((HERE/name).read_bytes(),0o644)for name in('prepare.py','README.md')}
        self.commit='d'*40
        self.model=contextlib.ExitStack();self.addCleanup(self.model.close)
        self.helpers=(B.M,B.B.M,old.V4,old.P,old.C,old.H)
        self.model.enter_context(patch.multiple(M,SOURCE196=self.basis,REPLACEMENTS=self.pins,load_helpers=lambda:self.helpers))

    def rebind(self,files=None,replacements=None,**kw):
        return M.rebind(self.basis196 if files is None else files,self.replacements if replacements is None else replacements,
            commit=kw.get('commit',self.commit),constructor_files=kw.get('constructor_files',self.construction))

    def test_fixed_source196_basis_and_operand_output_distinction(self):
        self.assertEqual(self.real_basis,dict(files=196,bytes=45726789,tree='e85302474308dbf579b79bd6d501f5ad86b66bbb',
            source_map=dict(bytes=38809,sha256='a8f5ab1c1ceee9f3450634e14dd172d7421d6fe49d8e17ce680cb4cfe43da86a')))
        self.assertEqual(set(self.real_pins),{'materials_stager','material_domain_executor','hosted_launcher'})
        self.assertEqual(M.OPERANDS,{role:M.PREFIX+'/payload/'+name for role,name in (
            ('materials_stager','stager.py'),('material_domain_executor','material_domain.py'),('hosted_launcher','hosted.py'))})
        for role,row in self.real_pins.items():
            self.assertNotEqual(M.OPERANDS[role],row['member'])
            self.assertGreater(row['bytes'],0)
            self.assertEqual(self.C.pin((HERE.parents[3]/M.OPERANDS[role]).read_bytes()),{k:row[k]for k in('bytes','sha256')})
        V6,*_=self.real_helpers()
        self.assertEqual(self.C.pin((HERE.parent/'successor_v6_source/prepare.py').read_bytes()),M.V6_PIN)
        self.assertEqual(V6.SOURCE188,dict(files=188,bytes=45544942,tree='50bf7aab34ee5497f12d078709354aa69b0cdb9d',
            source_map=dict(bytes=37091,sha256='ba06925244cd010ab2223325e2e324d4d3b469befbea5e7eb8e0de68383d4908')))

    def test_three_replacements_nine_additions_and_all_four_exact_inverses(self):
        before=copy.deepcopy(self.basis196);candidate,profile=self.rebind()
        for function,wanted in ((M.inverse_v6,before),(M.inverse_v5,self.basis188),
                                (M.inverse_v4,self.basis179),(M.inverse_v3,self.basis139)):
            self.assertEqual(function(candidate),wanted)
        self.assertEqual(len(set(candidate)-set(before)),9)
        self.assertEqual({name for name in before if before[name]!=candidate[name]},
            {'source-map.json','source.lock.json',*(row['member']for row in self.pins.values())})
        self.assertEqual(self.basis196,before)
        self.assertEqual(profile['prospective_tree'],self.H.tree(candidate))
        for name in (M.OLD_PROGRAM,B.M.PREFIX+'/inverse.json',B.M.PREFIX+'/prepare.py',
                     B.M.PREFIX+'/README.md','provenance/v6/source188-map.json'):
            self.assertEqual(candidate[name],before[name])
        for name in before:
            if name.startswith(('provenance/','scripts/ci/first-login-enrollment-native-source/successor_v5_source/')):
                self.assertEqual(candidate[name],before[name])
        mapping=self.C.decode(candidate['source-map.json'][0])
        self.assertEqual(candidate['source-map.json'],candidate['source.lock.json'])
        self.assertEqual(mapping['files'],self.C.descriptors({n:v for n,v in candidate.items()if n not in('source-map.json','source.lock.json')}))

    def test_registry_profile_provenance_preserve_historical_contract_and_no_authority(self):
        files,profile=self.rebind();C=self.C;old=C.decode(self.basis196[M.OLD_PROGRAM][0])
        new=C.decode(files[M.PREFIX+'/program.json'][0]);provenance=C.decode(files[M.PROVENANCE+'/rebind.json'][0])
        self.assertEqual((new['schema'],new['kind']),(7,'DELEGATED_CURRENT_TRANSPORT_PROGRAM_REGISTRY_V7'))
        self.assertEqual(new['transport_commit'],self.commit)
        for name in ('capture_commit','capture_rebind_provenance','diagnostics_commit','rebind_provenance','basis_closure_commit'):
            self.assertEqual(new[name],old[name])
        self.assertEqual(new['transport_rebind_provenance'],dict(member=M.PROVENANCE+'/rebind.json',**C.pin(files[M.PROVENANCE+'/rebind.json'][0])))
        self.assertEqual({role for role in old['roles']if old['roles'][role]!=new['roles'][role]},set(self.pins))
        self.assertEqual((len(new['roles']),len(new['delegation_programs']),len(new['staging_materials'])),(27,25,5))
        self.assertEqual(profile['staging_materials'],old['staging_materials'])
        self.assertEqual(len(profile['materials'])+len(profile['staging_materials']),64)
        self.assertEqual(profile['source196_basis'],self.basis)
        self.assertEqual(profile['source188_basis'],B.M.SOURCE188)
        for role,row in self.pins.items():
            self.assertEqual(new['roles'][role],row);self.assertEqual(new['delegation_programs'][role],row)
            self.assertEqual(provenance['replacements'][role]['operand'],M.OPERANDS[role])
            self.assertEqual(provenance['replacements'][role]['original'],dict(C.pin(self.basis196[row['member']][0]),mode=0o644))
        for value in (new,profile,provenance):self.assertTrue(all(v is None for v in value['actual'].values()))

    def test_basis_body_mode_maps_namespace_and_historical_inverse_drift_refuse(self):
        for kind in ('body','mode','map','alias','extra','missing','historical'):
            files=copy.deepcopy(self.basis196)
            if kind in ('body','mode'):
                name=next(iter(self.pins.values()))['member'];raw,mode=files[name]
                files[name]=(raw+b'DRIFT'if kind=='body'else raw,0o755 if kind=='mode'else mode)
            elif kind=='map':files['source-map.json']=(b'DRIFT',0o644)
            elif kind=='alias':files['source.lock.json']=(b'DRIFT',0o644)
            elif kind=='extra':files['FOREIGN.DATA']=(b'FOREIGN',0o644)
            elif kind=='missing':files.pop(next(iter(self.pins.values()))['member'])
            else:files['provenance/v6/source188-map.json']=(b'DRIFT',0o644)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.rebind(files)

    def test_replacement_commit_construction_authority_collisions_and_caps_refuse(self):
        for kind in ('missing','extra','body','mode','commit','constructor','collision','authority','files-cap','bytes-cap','file-cap'):
            replacements=copy.deepcopy(self.replacements);files=copy.deepcopy(self.basis196)
            construction=dict(self.construction);commit=self.commit;limit=dict(MAX_FILES=self.C.MAX_FILES)
            role=next(iter(replacements));raw,_=replacements[role]
            if kind=='missing':replacements.pop(role)
            elif kind=='extra':replacements['unknown']=(b'MODEL',0o644)
            elif kind=='body':replacements[role]=(raw+b'DRIFT',0o644)
            elif kind=='mode':replacements[role]=(raw,0o755)
            elif kind=='commit':commit='HEAD'
            elif kind=='constructor':construction.pop('README.md')
            elif kind=='collision':files[M.PROVENANCE+'/rebind.json']=(b'FOREIGN',0o644)
            elif kind=='authority':
                registry=self.C.decode(files[M.OLD_PROGRAM][0]);registry['actual']['Root_delegation']='REFUSED'
                files[M.OLD_PROGRAM]=(self.C.encoded(registry),0o644)
            elif kind=='files-cap':limit=dict(MAX_FILES=len(files))
            elif kind=='bytes-cap':limit=dict(MAX_TOTAL=1)
            else:limit=dict(MAX_FILE=1)
            with self.subTest(kind=kind),patch.multiple(self.C,**limit),self.assertRaises(ValueError):
                self.rebind(files,replacements,commit=commit,constructor_files=construction)

    def test_inverse_refuses_backup_mode_map_removal_restore_untouched_and_extra_drift(self):
        candidate,_=self.rebind()
        for kind in ('backup','backup-mode','map','remove','restore','untouched','extra','basis'):
            files=copy.deepcopy(candidate);inverse=self.C.decode(files[M.PREFIX+'/inverse.json'][0])
            backup=next(iter(inverse['restore'].values()))
            if kind=='backup':files[backup]=(b'DRIFT',0o644)
            elif kind=='backup-mode':files[backup]=(files[backup][0],0o755)
            elif kind=='map':files[M.PROVENANCE+'/source196-map.json']=(b'DRIFT',0o644)
            elif kind=='remove':inverse['remove'].pop()
            elif kind=='restore':inverse['restore'].pop(next(iter(inverse['restore'])))
            elif kind=='untouched':files[M.OLD_PROGRAM]=(b'DRIFT',0o644)
            elif kind=='extra':files['FOREIGN.DATA']=(b'FOREIGN',0o644)
            else:inverse['basis']['tree']='0'*40
            files[M.PREFIX+'/inverse.json']=(self.C.encoded(inverse),0o644)
            with self.subTest(kind=kind),self.assertRaises(ValueError):M.inverse_v6(files)

    def test_assemble_reads_distinct_committed_operands_and_exact_executing_closure(self):
        calls=[];P=self.helpers[3]
        def blob(repo,revision,name,expected=None):
            calls.append((revision,name,expected))
            for role,operand in M.OPERANDS.items():
                if operand==name:
                    self.assertEqual(expected,dict(bytes=self.pins[role]['bytes'],sha256=self.pins[role]['sha256'],mode=0o644))
                    return self.replacements[role]
            return self.construction[Path(name).name]
        with patch.object(M,'load_basis',return_value=self.basis196),patch.object(P,'commit')as commit,\
             patch.object(P,'blob',side_effect=blob),patch.object(M,'rebind',return_value=('MODEL FILES','MODEL PROFILE'))as rebind:
            self.assertEqual(M.assemble(Path('/MODEL/repo'),Path('/MODEL/source196'),self.commit),('MODEL FILES','MODEL PROFILE'))
            commit.assert_called_once_with(Path('/MODEL/repo'),self.commit);self.assertEqual(len(calls),5)
            self.assertEqual({name for _,name,_ in calls},{*M.OPERANDS.values(),M.PREFIX+'/prepare.py',M.PREFIX+'/README.md'})
            rebind.assert_called_once_with(self.basis196,self.replacements,commit=self.commit,constructor_files=self.construction)
        with patch.object(M,'load_basis',return_value=self.basis196),patch.object(P,'commit'),patch.object(P,'blob',side_effect=blob),\
             patch.object(self.C,'read',return_value=(b'UNCOMMITTED',0o644)),self.assertRaises(ValueError):
            M.assemble(Path('/MODEL/repo'),Path('/MODEL/source196'),self.commit)


if __name__=='__main__':unittest.main(verbosity=2)
