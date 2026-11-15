#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced exact3937 admission DATA controls; no operational module imports."""
import argparse
import ast
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--held-admission-root',type=Path,required=True)
parser.add_argument('--source-root',type=Path,required=True)
ARGS=parser.parse_args()


def fence(event,args):
    if event in('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','socket.__new__','ctypes.dlopen'):
        raise AssertionError('actor forbidden in admission DATA controls: '+event)
    if event=='open' and isinstance(args[0],str) and args[0].endswith('/shared-GUI-ancestor-collection.lock'):
        raise AssertionError('shared lock must never be opened in DATA controls')
sys.addaudithook(fence)


def data_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


C=data_module('_context_admission_DATA',HERE/'prepare.py');G=C.G
A,HELD=C.held(ARGS.held_admission_root);B=A.base()
PUB=B.obj(C.read(HERE/'Root-published-source-full200.json'))
ROWS={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode='100755'if r['mode']==493 else'100644',oid=r['oid'])for n,r in PUB['files'].items()}
PARENT=B.obj(C.read(HERE/'parent-full200.json'));PROFILE=B.obj(C.read(HERE/'source-profile.json'))
G.publication(PUB,C.read(HERE/'source.raw'),ROWS)
# The complete explicit real Source scan is never mocked; only historical DATA callbacks are modeled below.
SOURCE_BYTES=A.closed_source_tree(ARGS.source_root,ROWS,B)
H=data_module('_held_admission_DATA_models',A.BASE/'test_prepare.py')
FACTORY=B.obj(C.read(HERE/'factory-files.json'));FACTORY_RAW=C.read(HERE/'factory-files.json')


def model_data():
    basis=dict(templates={p.name:B.read(p)for p in(A.BASE/'templates').iterdir()},external={},binding=None,
               source_root='/MODELED/HISTORICAL6b',rows=H.obj('source-full200.json'),source_bytes=1)
    # This replaces historical retained169 DATA, not any new Source body/tree/namespace check.
    with patch.object(A,'base',return_value=NS(**dict(vars(B),inputs=lambda root:deepcopy(basis)))):
        return C.inputs(A,ARGS.source_root)


def model_binding():
    value=C.template_binding();value.update(approved=True,status='ROOT_BOUND_NAMESPACE_CONTEXT_FACTORY_CI_MAIN',
        pull_request=999,reviewed_factory='c'*40,factory_head='e'*40,factory_Main='d'*40,
        factory_files_sha256=G.pin(FACTORY_RAW)['sha256'],expected_CI_checks=75,
        factory_merge=dict(path='/MODELED/merge.json',bytes=1,sha256='a'*64),factory_CI=dict(path='/MODELED/ci.json',bytes=1,sha256='b'*64))
    return value


def qualification_model():
    q=H.QualificationModel();old_obj=q.obj;old_git=q.git
    q.binding=model_binding();q.factory_rows=deepcopy(FACTORY);q.before={'held/unchanged':dict(mode='100755',blob='f'*40)};q.after=dict(q.before);q.bodies={}
    changes={}
    for name,row in FACTORY.items():
        q.after[name]=dict(mode=row['mode'],blob=row['oid']);q.bodies['after',name]=C.read(HERE/Path(name).name)
        changes[name]=dict(before=None,after=row)
    q.merge=dict(main=q.binding['factory_Main'],tested_head=q.binding['factory_head'],premerge_main=G.BASELINE_MAIN,merge_PUTs=1,
                 all_unlisted_objects_modes_preserved=True,inverse_restores_actual_premerge_main=True,
                 correction_paths=sorted(FACTORY),reviewed_changes=changes)
    q.merged_raw=('tree '+'a'*40+'\nparent '+G.BASELINE_MAIN+'\nparent '+q.binding['factory_head']+'\nauthor Model <model@invalid> 1 +0000\ncommitter Model <model@invalid> 1 +0000\n\nMODELED merge\n').encode()
    q.binding['factory_Main']=q.merge['main']=G.oid('commit',q.merged_raw)
    q.ci.update(head=q.binding['factory_head'],checks=75,jobs=75)
    for index,j in enumerate(q.ci['feature_jobs'],1):
        j.update(id=index,run_id=1,run_attempt=1,head_sha=q.binding['factory_head'],steps=[dict(name=n,status='completed',conclusion='success')for n in(G.STEP,G.SOURCE_STEP)])
    q.rows=deepcopy(ROWS);q.parent=C.read(HERE/'parent.raw');q.mapping=C.read(HERE/'fixtures/source-map.json.data')
    q.workflow=C.read(HERE/'fixtures/workflow.yml.data');q.contract=B.obj(C.read(HERE/'fixtures/contract.json.data'))
    def obj(path):
        if path in(q.T/'source-publication.ACTUAL.json',q.PUB/'publication.json'):return deepcopy(PUB)
        if path==q.T/'source-profile.json':return deepcopy(PROFILE)
        if path==q.T/'parent-full200.json':return deepcopy(PARENT)
        return old_obj(path)
    def read(path):
        if path==q.T/'publication/source.raw':return C.read(HERE/'source.raw')
        if path==q.T/'source-profile.json':return C.read(HERE/'source-profile.json')
        if path==q.T/'factory-files.json':return FACTORY_RAW
        if str(path)in q.proofs:return q.proofs[str(path)]
        if path==q.T/'publication/parent.raw':return q.parent
        if path==q.SOURCE_ROOT/'native/source-map.json':return q.mapping
        raise AssertionError(('unmodeled DATA read',path))
    def git(role,*args):
        if role=='source-raw':return C.read(HERE/'source.raw')
        if role=='source-local':return G.SOURCE.encode()+b'\n'
        if role=='source-remote':return(G.SOURCE+'\trefs/heads/'+G.REF+'\n').encode()
        if role=='parent-full-map':return q.table({n:dict(mode=r['mode'],blob=r['oid'])for n,r in PARENT.items()})
        if role in('reviewed-factory-map','tested-factory-map'):return q.table(q.after)
        if role=='reviewed-factory-ancestor':return b''
        return old_git(role,*args)
    def closed(U,root,auth,modes):
        assert root==q.SOURCE_ROOT and auth=={n:{k:r[k]for k in('bytes','sha256')}for n,r in ROWS.items()}
        assert modes=={n:int(r['mode'],8)&511 for n,r in ROWS.items()}
        return G.TREE
    q.obj=obj;q.git=git;q.C=NS(closed_source_declared=closed);q.U=NS(read=read,obj=B.obj);q.sync();return q


class ContextAdmissionDataControls(unittest.TestCase):
    def test_exact_published3937_six_leaf194_parent_and_real_source(self):
        G.publication(PUB,C.read(HERE/'source.raw'),ROWS);G.source_delta(PROFILE,PARENT,ROWS)
        self.assertEqual(sum(PARENT[n]==ROWS[n]for n in ROWS),194);self.assertEqual(SOURCE_BYTES,sum(r['bytes']for r in ROWS.values()))
        self.assertEqual(set(FACTORY),G.FACTORY_PATHS);self.assertEqual(len(FACTORY),10)

    def test_old_source_reader_parent_extra_change_or_wrong1001_refuses(self):
        for key,value in(('source',G.PARENT),('ref','refs/heads/codex/old'),('Reader_calls',1)):
            bad=deepcopy(PUB);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):G.publication(bad,C.read(HERE/'source.raw'),ROWS)
        for name in(G.READER['path'],'native/common.py',G.HELPER['path']):
            bad=deepcopy(ROWS);bad[name]['sha256']='0'*64
            with self.subTest(name=name),self.assertRaises(ValueError):G.source_delta(PROFILE,PARENT,bad)
        bad=deepcopy(PROFILE);bad['alarm_identity']['uid']=1000
        with self.assertRaises(ValueError):G.source_delta(bad,PARENT,ROWS)

    def test_missing_factory_and_old_receipt_cannot_qualify(self):
        for value in(None,C.template_binding(),dict(approved=True,status='ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN')):
            with self.assertRaises(ValueError):G.factory(value)
        q=qualification_model();G.factory_proofs(q.binding,q.merge,q.ci)
        for change in('old_baseline','old_source','missing_step','duplicate_step','old_step','count','subset','head'):
            q=qualification_model()
            if change=='old_baseline':q.binding['baseline_main']='208bd08d7f14c76468ff4c8fb18c357f37120070'
            elif change=='old_source':q.binding['source']=G.PARENT
            elif change=='missing_step':q.ci['feature_jobs'][0]['steps'].pop()
            elif change=='duplicate_step':q.ci['feature_jobs'][0]['steps'].append(deepcopy(q.ci['feature_jobs'][0]['steps'][0]))
            elif change=='old_step':q.ci['feature_jobs'][0]['steps'][0]['name']='Check observable namespace source controls without actors'
            elif change=='count':q.ci['checks']=74
            elif change=='subset':q.merge['correction_paths'].pop()
            else:q.ci['feature_jobs'][0]['head_sha']='f'*40
            with self.subTest(change=change),self.assertRaises(ValueError):G.factory_proofs(q.binding,q.merge,q.ci)

    def test_complete_modeled_publication_factory_reviewed_tested_Main_join(self):
        q=qualification_model();self.assertEqual(G.qualify(q.namespace()),q.binding['factory_Main'])
        result=q.saved[str(q.OUT/'source-qualification.json')]
        self.assertEqual(result['source'],G.SOURCE);self.assertEqual(result['factory_correction_subset'],10)
        self.assertEqual(result['reader']['sha256'],G.READER['sha256']);self.assertFalse(result['reader_executed']);self.assertFalse(result['acceptance'])

    def test_full_join_refuses_wrong_uid_parent_map_manifest_or_changed_factory(self):
        for change in('uid','parent','map','manifest','reviewed_body','tested_table','hidden_batch'):
            q=qualification_model()
            if change=='uid':q.contract['uid']=1000
            elif change=='parent':q.parent+=b'changed'
            elif change=='map':q.mapping+=b'changed'
            elif change=='manifest':q.binding['factory_files_sha256']='f'*64
            elif change=='reviewed_body':q.bodies['after',next(iter(FACTORY))]+=b'changed'
            elif change=='hidden_batch':q.merge['reviewed_changes'].pop(next(iter(FACTORY)));q.sync()
            else:
                old=q.git
                def changed(role,*args):
                    if role=='tested-factory-map':return q.table({})
                    return old(role,*args)
                q.git=changed
            with self.subTest(change=change),self.assertRaises(ValueError):G.qualify(q.namespace())
            self.assertFalse(q.saved)

    def test_render_exact_source_reader_and_unissued_all_authorities(self):
        files=C.render(A,model_data(),Path('/MODELED/context3937'))
        facts=B.obj(files['facts.json']);authority=B.obj(files['Root-authority.TEMPLATE.json']);binding=B.obj(files['factory-binding.TEMPLATE.json'])
        self.assertEqual((facts['source'],facts['parent'],facts['map_sha256']),(G.SOURCE,G.PARENT,G.MAP))
        for key in('factory_binding','factory_reviewed_factory','runtime54_profile','Root_authority','actual_run','actual_job','artifact','body'):self.assertIsNone(facts[key])
        for key in('approved','issued_at'):self.assertIsNone(authority[key])
        self.assertTrue(all(v is None for v in authority['reviews'].values()));self.assertIsNone(authority['reservation']['held_by'])
        for key in('pull_request','reviewed_factory','factory_head','factory_Main','factory_files_sha256','expected_CI_checks'):self.assertIsNone(binding[key])
        self.assertEqual(B.obj(files['strict-reader-binding.TEMPLATE.json'])['reader']['sha256'],G.READER['sha256'])
        self.assertEqual(B.obj(files['matching-reader-closure.ACTUAL.json'])['files'],ROWS)
        self.assertTrue(B.obj(files['composition-provenance.json'])['complete_input_composer_inverse'])
        self.assertFalse(any('Source69455_parent6b' in k or 'tools17' in k or 'inode55' in k for k in authority['reviews']))

    def test_pending_factory_or_runtime_stops_before_any_role_output(self):
        with tempfile.TemporaryDirectory()as d:
            for factory_ready in(False,True):
                data=model_data()
                if factory_ready:data['binding']=model_binding()
                out=Path(d)/str(factory_ready);files=C.render(A,data,out);B.publish(files,out)
                node=next(n for n in ast.parse(files['ROOT-NATIVE-ONCE.py']).body if isinstance(n,ast.FunctionDef)and n.name=='verify_packet')
                scope=dict(Path=Path,json=json,T=out,SOURCE=G.SOURCE,TREE=G.TREE,MAP=G.MAP,REF=G.REF,INPUT_SEAL='bound',pin=G.pin,need=G.need)
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<pure pending packet guard>','exec'),scope)
                with self.assertRaisesRegex(ValueError,'runtime54 attestation pending'if factory_ready else'factory CI/Main binding pending'):
                    scope['verify_packet'](G.pin(files['seal.json'])['sha256'])
                self.assertFalse(any((out/n).exists()for n in('receipts','actual-native','Root-preflight-000')))
                with self.assertRaises(FileExistsError):B.publish(files,out)

    def test_complete_seals_and_runtime54_bytes_still_exact(self):
        files=C.render(A,model_data(),Path('/MODELED/context3937'));seal=B.obj(files['seal.json']);index=B.obj(files['input-seal.json'])
        for name,row in seal['files'].items():self.assertEqual(G.pin(files[name]),row)
        for name,row in index.items():
            if name.startswith('/MODELED/context3937/'):self.assertEqual(G.pin(files[Path(name).relative_to('/MODELED/context3937').as_posix()]),row)
        self.assertEqual(files['runtime54.py'],C.read(A.HERE/'runtime54.py'))
        runtime=C.module('_held_runtime54_DATA',HERE/'runtime54.py')
        self.assertEqual(runtime.EXACT['dev'],54);self.assertEqual(runtime.EXACT['uid'],1000)
        with self.assertRaises(ValueError):runtime.profile(dict(approved=None))
        profile=dict(schema=1,issuer='Root',status='ROOT_BOUND_EXACT_EXISTING_LOCK_RUNTIME54',approved=True,
                     attested_at=datetime.now(timezone.utc).isoformat(),identity=deepcopy(runtime.EXACT),resource_authority=False,lock_mutation=False)
        runtime.profile(profile)
        stale=deepcopy(profile);stale['attested_at']=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()
        with self.assertRaises(ValueError):runtime.profile(stale)
        wrong=deepcopy(profile);wrong['identity']['uid']=1001
        with self.assertRaises(ValueError):runtime.profile(wrong)

    def test_no_git_files_directories_symlinks_or_extra_source_entries(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d)
            for kind in('file','directory','broken_symlink'):
                p=root/'.git'
                if kind=='file':p.write_text('gitdir: elsewhere\n')
                elif kind=='directory':p.mkdir()
                else:p.symlink_to(root/'missing')
                with self.subTest(kind=kind),self.assertRaises(ValueError):A.closed_source_tree(root,ROWS,B)
                p.rmdir()if p.is_dir()else p.unlink()
            (root/'unlisted').write_text('DATA')
            with self.assertRaises(ValueError):A.closed_source_tree(root,ROWS,B)

    def test_held_once_metadata_CAS_retirement_and_dispatch_projection_ASTs(self):
        files=C.render(A,model_data(),Path('/MODELED/context3937'))
        checks={'ROOT-NATIVE-ONCE.py':['run','git','entries','main_guard','metadata_worker','execute'],
                'RUN-PINNED-9D.py':['guarded'],'ROOT-INDEPENDENT-PREFLIGHT.py':['metadata_template_only']}
        # Compare against the held templates, restoring only finite new source/status constants
        # and the already reviewed full-ref→short-ref original9d projection seam.
        for name,names in checks.items():
            raw=files[name].decode()
            if name=='ROOT-NATIVE-ONCE.py':
                projection="view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);save(view/'publication.json',dict(source=SOURCE,ref=REF))\n  save(OUT/'original9d-publication-projection.json',dict(Root_publication=pin(U.read(PUB/'publication.json')),Root_ref=obj(PUB/'publication.json')['ref'],dispatch_view=dict(source=SOURCE,ref=REF),Source_publication=False))"
                self.assertEqual(raw.count(projection),1);raw=raw.replace(projection,"view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);write(view/'publication.json',U.read(PUB/'publication.json'))")
            original=ast.parse(C.read(A.BASE/'templates'/name));adapted=ast.parse(raw)
            class Restore(ast.NodeTransformer):
                def visit_Constant(self,node):
                    if isinstance(node.value,str):
                        node.value=node.value.replace('NAMESPACE_CONTEXT','NAMESPACE_PREFLIGHT').replace(G.SOURCE,H.G.SOURCE).replace(G.REF,H.G.REF).replace(G.TREE,H.G.TREE).replace(G.MAP,H.G.MAP)
                        if node.value=='PUBLISHED_SOURCE_200_BODY_QUALIFIED_ACTORS_NOT_ADMITTED':node.value='PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION'
                    return node
            for fn in names:
                old=next(n for n in original.body if isinstance(n,ast.FunctionDef)and n.name==fn)
                new=next(n for n in adapted.body if isinstance(n,ast.FunctionDef)and n.name==fn)
                with self.subTest(file=name,function=fn):self.assertEqual(H.ast_bytes(old),H.ast_bytes(Restore().visit(new)))


if __name__=='__main__':unittest.main(argv=[sys.argv[0]],verbosity=2)
