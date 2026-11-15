#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observable admission DATA joins only; no Source/role import or actual gate entry."""
import ast
import contextlib
import io
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('observable_admission',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P);G=P.G
B=P.base()
# Reuse the existing in-memory model, not its test runner or any role.
spec=importlib.util.spec_from_file_location('held_admission_models',P.BASE/'test_prepare.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)

def fence(event,args):
    if event in('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','socket.__new__','ctypes.dlopen'):raise AssertionError('actor denied: '+event)
sys.addaudithook(fence)
PUB=B.obj(B.read(HERE/'Root-published-source-full200.json'))
ROWS={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=r['mode'],oid=r['blob'])for n,r in PUB['files'].items()}
PARENT=H.obj('source-full200.json')
PROFILE=B.obj(B.read(HERE/'source-profile.json'))


def model_data():
    data=dict(templates={p.name:B.read(p)for p in(P.BASE/'templates').iterdir()},external={},binding=None,source_root='/MODELED/parent6b',rows=deepcopy(PARENT),source_bytes=sum(r['bytes']for r in PARENT.values()))
    with patch.object(P,'base',return_value=SimpleNamespace(**dict(vars(B),inputs=lambda root:deepcopy(data),source_tree=lambda root,rows:sum(r['bytes']for r in rows.values())))):
        return P.inputs(Path('/MODELED/observable69455'))


def model_binding():
    value=H.binding_model();value.update(status='ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN',reviewed_factory='d6b86264d2fb6243e0ccde4a95e2a7f50804420e',pull_request=437,baseline_main='208bd08d7f14c76468ff4c8fb18c357f37120070');value.pop('reviewed_correction')
    return value


def qualification_model():
    q=H.QualificationModel();old_git=q.git;old_obj=q.obj
    q.binding=model_binding();q.merge['premerge_main']=q.binding['baseline_main'];q.merge['tested_head']=q.binding['factory_head']
    for name in q.merge['correction_paths'][9:]:
        q.merge['reviewed_changes'].pop(name);q.before.pop(name);q.after.pop(name)
    q.merge['correction_paths']=q.merge['correction_paths'][:9]
    q.factory_rows={n:r for n,r in q.factory_rows.items()if n in q.merge['correction_paths']}
    q.merged_raw=('tree '+'a'*40+'\nparent '+q.merge['premerge_main']+'\nparent '+q.binding['factory_head']+'\nauthor Model <model@invalid> 1 +0000\ncommitter Model <model@invalid> 1 +0000\n\nMODELED merge\n').encode()
    q.binding['factory_Main']=q.merge['main']=G.oid('commit',q.merged_raw)
    q.ci['head']=q.binding['factory_head']
    for j in q.ci['feature_jobs']:
        j.update(id=int(j['name'][-5:-1].replace('.','')),run_id=1,run_attempt=1,head_sha=q.binding['factory_head'])
        j['steps'][0]['name']=G.STEP
    q.rows=deepcopy(ROWS);q.parent=B.read(HERE/'parent.raw')
    mapping=H.P.obj(H.P.read(P.BASE/'fixtures/source-map.json.data'))
    mapping['files']={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=int(r['mode'],8)&511)for n,r in ROWS.items()if n!='native/source-map.json'}
    mapping['namespace_build_log_visibility']='UNQUIET_TOOLS_IIDFILE_V1'
    q.mapping=B.encoded(mapping);assert G.pin(q.mapping)['sha256']==G.MAP
    def obj(path):
        if path in(q.T/'source-publication.ACTUAL.json',q.PUB/'publication.json'):return deepcopy(PUB)
        if path==q.T/'source-profile.json':return deepcopy(PROFILE)
        if path==q.T/'parent-full200.json':return deepcopy(PARENT)
        return old_obj(path)
    def read(path):
        if path==q.T/'publication/source.raw':return B.read(HERE/'source.raw')
        if path==q.T/'source-profile.json':return B.read(HERE/'source-profile.json')
        if str(path)in q.proofs:return q.proofs[str(path)]
        if path==q.T/'publication/parent.raw':return q.parent
        if path==q.SOURCE_ROOT/'native/source-map.json':return q.mapping
        raise AssertionError(path)
    def git(role,*args):
        if role=='source-raw':return B.read(HERE/'source.raw')
        if role=='source-local':return G.SOURCE.encode()+b'\n'
        if role=='source-remote':return(G.SOURCE+'\trefs/heads/'+G.REF+'\n').encode()
        if role=='parent-full-map':return q.table({n:dict(mode=r['mode'],blob=r['oid'])for n,r in PARENT.items()})
        return old_git(role,*args)
    old_closed=q.C.closed_source_declared
    def closed(*args):
        assert old_closed(*args)==H.G.TREE;return G.TREE
    q.C=SimpleNamespace(closed_source_declared=closed)
    q.obj=obj;q.git=git;q.U=SimpleNamespace(read=read,obj=B.obj);q.sync();return q


class ObservableAdmissionData(unittest.TestCase):
    def test_exact_Root_publication_and_four_leaf_inverse(self):
        G.publication(PUB,B.read(HERE/'source.raw'),ROWS);G.source_delta(PROFILE,PARENT,ROWS)
        self.assertEqual(len(ROWS),200);self.assertEqual(sum(PARENT[n]==ROWS[n]for n in ROWS),196)

    def test_old_source_parent_reader_helper_and_extra_change_refuse(self):
        for key,value in(('source',G.PARENT),('ref','refs/heads/codex/old'),('Reader_calls',1)):
            bad=deepcopy(PUB);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):G.publication(bad,B.read(HERE/'source.raw'),ROWS)
        for name in(G.READER['path'],G.HELPER['path'],'native/common.py'):
            bad=deepcopy(ROWS);bad[name]['sha256']='0'*64
            with self.subTest(name=name),self.assertRaises(ValueError):G.source_delta(PROFILE,PARENT,bad)

    def test_new_family_factory_proofs_both_actual_steps(self):
        q=qualification_model();self.assertIs(G.factory_proofs(q.binding,q.merge,q.ci),q.binding)
        for change in('old_revision','old_step','missing_python','wrong_count','wrong_subset'):
            q=qualification_model()
            if change=='old_revision':q.binding['reviewed_factory']='8d4ec359bf05dda455eb772077b4edf37de53002'
            elif change=='old_step':q.ci['feature_jobs'][0]['steps'][0]['name']=H.G.STEP
            elif change=='missing_python':q.ci['feature_jobs'].pop()
            elif change=='wrong_count':q.ci['checks']=74
            else:q.merge['correction_paths'].pop()
            with self.subTest(change=change),self.assertRaises(ValueError):G.factory_proofs(q.binding,q.merge,q.ci)

    def test_complete_modeled_Source_factory_Reader_join(self):
        q=qualification_model();self.assertEqual(G.qualify(q.namespace()),q.binding['factory_Main'])
        result=q.saved[str(q.OUT/'source-qualification.json')]
        self.assertEqual(result['source'],G.SOURCE);self.assertEqual(result['factory_correction_subset'],9)
        self.assertEqual(result['factory_batch_changed'],12);self.assertEqual(result['reader']['bytes'],106215)
        self.assertFalse(result['reader_executed']);self.assertFalse(result['acceptance'])

    def test_full_join_refuses_wrong_parent_map_visibility_or_hidden_batch(self):
        for change in('parent','visibility','hidden_batch','factory_body'):
            q=qualification_model()
            if change=='parent':q.parent+=b'changed'
            elif change=='visibility':q.mapping=q.mapping.replace(b'UNQUIET_TOOLS_IIDFILE_V1',b'OLD_QUIET_TOOLS_MODE')
            elif change=='hidden_batch':q.merge['reviewed_changes'].pop('owned/new-11');q.sync()
            else:q.factory_rows[next(iter(q.factory_rows))]['sha256']='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):G.qualify(q.namespace())
            self.assertFalse(q.saved)

    def test_render_uses_new_selectors_and_unissued_runtime_resource(self):
        data=model_data();files=P.render(data,Path('/MODELED/fresh'))
        facts=B.obj(files['facts.json']);authority=B.obj(files['Root-authority.TEMPLATE.json'])
        self.assertEqual((facts['source'],facts['parent'],facts['map_sha256']),(G.SOURCE,G.PARENT,G.MAP))
        self.assertIsNone(facts['factory_binding']);self.assertIsNone(facts['runtime54_profile']);self.assertIsNone(facts['actual_run'])
        self.assertIsNone(authority['approved']);self.assertIsNone(authority['reservation']['held_by'])
        self.assertEqual(authority['active_run_certificates'],[]);self.assertTrue(all(v is None for v in authority['reviews'].values()))
        self.assertFalse(any('tools17'in k or 'parent97'in k or 'inode55'in k for k in authority['reviews']))
        self.assertEqual(B.obj(files['runtime54-binding.json']),dict(path=None,bytes=None,sha256=None))
        self.assertEqual(B.obj(files['strict-reader-binding.TEMPLATE.json'])['reader']['bytes'],106215)
        self.assertEqual(B.obj(files['matching-reader-closure.ACTUAL.json'])['files'],ROWS)
        self.assertIn(b'ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN',files['ROOT-NATIVE-ONCE.py'])
        self.assertIn(b'EXACT_NAMESPACE_OBSERVABLE_PUBLISHED_SOURCE200_AND_MERGED_FACTORY',files['RUN-PINNED-9D.py'])

    def test_pending_entry_stops_before_bootstrap_receipt_or_lease(self):
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary)/'fresh';files=P.render(model_data(),out);B.publish(files,out)
            scope=dict(Path=Path,json=json,T=out,SOURCE=G.SOURCE,TREE=G.TREE,MAP=G.MAP,REF=G.REF,INPUT_SEAL='bound',pin=G.pin,need=G.need)
            node=next(n for n in ast.parse(files['ROOT-NATIVE-ONCE.py']).body if isinstance(n,ast.FunctionDef)and n.name=='verify_packet')
            exec(compile(ast.Module(body=[node],type_ignores=[]),'pure verify_packet','exec'),scope)
            with self.assertRaisesRegex(ValueError,'factory CI/Main binding pending'):scope['verify_packet'](G.pin(files['seal.json'])['sha256'])
            # Modeled factory-ready packet still cannot enter without runtime attestation.
            data=model_data();data['binding']=model_binding();later=Path(temporary)/'factory-model';files=P.render(data,later);B.publish(files,later);scope['T']=later
            with self.assertRaisesRegex(ValueError,'runtime54 attestation pending'):scope['verify_packet'](G.pin(files['seal.json'])['sha256'])
            self.assertFalse((out/'receipts').exists());self.assertFalse((later/'receipts').exists())
            with self.assertRaises(FileExistsError):B.publish(files,later)

    def test_original9d_short_ref_view_preserves_actual_root_record(self):
        original=deepcopy(PUB);view=G.dispatch_view(original)
        self.assertEqual(original,PUB);self.assertEqual(view,dict(source=G.SOURCE,ref=G.REF))
        self.assertTrue(view['ref'].startswith('codex/'));self.assertFalse(original['ref'].startswith('codex/'))
        wrong=deepcopy(PUB);wrong['ref']='refs/heads/codex/closed-parent'
        with self.assertRaises(ValueError):G.dispatch_view(wrong)

    def test_explicit_source_root_is_required(self):
        self.assertFalse(hasattr(P,'SOURCE_ROOT'))
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:P.parser().parse_args([])
        self.assertEqual(caught.exception.code,2)
        self.assertEqual(P.parser().parse_args(['--source-root','/MODELED/export']).source_root,Path('/MODELED/export'))

    def test_physical_namespace_rejects_Git_file_directory_and_symlink(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);file=root/'declared';file.write_bytes(b'owned Source DATA\n');file.chmod(0o644)
            rows={'declared':dict(**G.pin(file.read_bytes()),mode='100644',oid=G.oid('blob',file.read_bytes()))}
            self.assertEqual(P.closed_source_tree(root,rows,B),len(file.read_bytes()))
            git=root/'.git'
            for kind in('file','directory','symlink'):
                if kind=='file':git.write_bytes(b'gitdir: /MODELED/metadata\n')
                elif kind=='directory':git.mkdir()
                else:git.symlink_to(root/'missing-metadata')
                with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'complete declared Source namespace'):
                    P.closed_source_tree(root,rows,B)
                self.assertTrue(os.path.lexists(git))
                if kind=='directory':git.rmdir()
                else:git.unlink()
            extra=root/'unexpected';extra.write_bytes(b'extra')
            with self.assertRaises(ValueError):P.closed_source_tree(root,rows,B)
            extra.unlink();extra.mkdir()
            with self.assertRaises(ValueError):P.closed_source_tree(root,rows,B)

    def test_runtime_profile_stale_or_unissued_refuses_without_lock_open(self):
        runtime=P.module('observable_runtime_model',HERE/'runtime54.py')
        profile=dict(schema=1,issuer='Root',status='ROOT_BOUND_EXACT_EXISTING_LOCK_RUNTIME54',approved=True,attested_at=datetime.now(timezone.utc).isoformat(),identity=runtime.EXACT,resource_authority=False,lock_mutation=False)
        self.assertIs(runtime.profile(profile),profile)
        for key,value in(('approved',None),('resource_authority',True),('attested_at',(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat())):
            bad=deepcopy(profile);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):runtime.profile(bad)

    def test_held_once_metadata_POST_guard_functions_remain_exact(self):
        files=P.render(model_data(),Path('/MODELED/fresh'))
        for name,functions in {'ROOT-NATIVE-ONCE.py':['run','git','entries','main_guard','metadata_worker','execute'],'RUN-PINNED-9D.py':['guarded'],'ROOT-INDEPENDENT-PREFLIGHT.py':['metadata_template_only']}.items():
            raw=files[name].decode()
            if name=='ROOT-NATIVE-ONCE.py':
                projected="view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);save(view/'publication.json',dict(source=SOURCE,ref=REF))\n  save(OUT/'original9d-publication-projection.json',dict(Root_publication=pin(U.read(PUB/'publication.json')),Root_ref=obj(PUB/'publication.json')['ref'],dispatch_view=dict(source=SOURCE,ref=REF),Source_publication=False))"
                self.assertEqual(raw.count(projected),1)
                raw=raw.replace(projected,"view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);write(view/'publication.json',U.read(PUB/'publication.json'))")
            old=ast.parse((P.BASE/'templates'/name).read_bytes());new=ast.parse(raw)
            for function in functions:
                a=next(n for n in old.body if isinstance(n,ast.FunctionDef)and n.name==function)
                b=next(n for n in new.body if isinstance(n,ast.FunctionDef)and n.name==function)
                class Restore(ast.NodeTransformer):
                    def visit_Constant(self,node):
                        if isinstance(node.value,str):
                            node.value=node.value.replace('NAMESPACE_OBSERVABLE','NAMESPACE_PREFLIGHT').replace(G.SOURCE,H.G.SOURCE).replace(G.REF,H.G.REF).replace(G.TREE,H.G.TREE).replace(G.MAP,H.G.MAP)
                            if node.value=='PUBLISHED_SOURCE_200_BODY_QUALIFIED_ACTORS_NOT_ADMITTED':node.value='PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION'
                        return node
                with self.subTest(file=name,function=function):self.assertEqual(H.ast_bytes(a),H.ast_bytes(Restore().visit(b)))


if __name__=='__main__':unittest.main()
