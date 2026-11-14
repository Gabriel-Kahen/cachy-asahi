#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""DATA controls only. No operator import, role, subprocess, network or resource lease."""
import ast
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import namespace_guard as G
import prepare as P


def fence(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','socket.__new__','ctypes.dlopen'):
        raise AssertionError('actor forbidden in DATA controls: '+event)
sys.addaudithook(fence)


def template(name):return P.read(HERE/'templates'/name)
def obj(name):return P.obj(template(name))
def functions(file,names,namespace):
    """Compile named pure guard definitions only, never module/role entry code."""
    tree=ast.parse(template(file));chosen=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert {n.name for n in chosen}==set(names)
    exec(compile(ast.Module(body=chosen,type_ignores=[]),file,'exec'),namespace)
    return namespace


def ast_bytes(node):
    # ast.dump defaults changed in Python3.13. Canonicalize fields independently.
    def value(item):
        if isinstance(item,ast.AST):
            return dict(type=type(item).__name__,fields={key:value(v) for key,v in ast.iter_fields(item) if v is not None and v!=[]})
        if isinstance(item,list):return [value(v) for v in item]
        if isinstance(item,bytes):return dict(bytes_hex=item.hex())
        return item
    return json.dumps(value(node),sort_keys=True,separators=(',',':')).encode()


def binding_model():
    row=dict(path='/MODELED/proof.json',bytes=1,sha256='a'*64)
    return dict(schema=1,issuer='Root',status='ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN',approved=True,
                reviewed_correction='8d4ec359bf05dda455eb772077b4edf37de53002',pull_request=433,
                baseline_main='295d838936371ce7376fc5b71c47232b155bd0b3',factory_Main='d'*40,factory_head='e'*40,
                expected_CI_checks=75,factory_merge=deepcopy(row),factory_CI=deepcopy(row))


def proof_model():
    b=binding_model()
    merge=dict(main=b['factory_Main'],tested_head=b['factory_head'],premerge_main=b['baseline_main'],merge_PUTs=1,
               all_unlisted_objects_modes_preserved=True,inverse_restores_actual_premerge_main=True,
               correction_paths=['owned/correction-'+str(i) for i in range(11)],reviewed_changes={})
    before={};after={};bodies={}
    for i in range(14):
        name=merge['correction_paths'][i] if i<11 else 'owned/new-'+str(i)
        sides={}
        for side in ('before','after'):
            if i>=11 and side=='before':sides[side]=None;continue
            raw=(side+' '+name+'\n').encode();row=dict(**G.pin(raw),mode='100644',oid=G.oid('blob',raw))
            sides[side]=row;bodies[(side,name)]=raw
            (before if side=='before' else after)[name]=dict(mode=row['mode'],blob=row['oid'])
        merge['reviewed_changes'][name]=sides
    # An unrelated tracked object must survive the whole integration inverse.
    before['held/unchanged']=after['held/unchanged']=dict(mode='100755',blob='f'*40)
    ci=dict(head=b['factory_head'],checks=75,jobs=75,check_job_bijection=True,failures=[],nonterminal=[],feature_jobs=[
        dict(name='Image lifecycle source controls ('+version+')',id=int(version.replace('.','')),run_id=1,run_attempt=1,head_sha=b['factory_head'],status='completed',conclusion='success',steps=[
             dict(name=G.STEP,status='completed',conclusion='success')]) for version in ('3.12','3.14')])
    return b,merge,ci,before,after,bodies


class QualificationModel:
    """In-memory callbacks with real Source DATA; no Git/role/resource execution."""
    def __init__(self):
        b,m,c,before,after,bodies=proof_model()
        self.before,self.after,self.bodies=before,after,bodies
        raw=('tree '+'a'*40+'\nparent '+m['premerge_main']+'\nparent '+b['factory_head']+'\nauthor Model <model@invalid> 1 +0000\ncommitter Model <model@invalid> 1 +0000\n\nMODELED merge\n').encode()
        b['factory_Main']=m['main']=G.oid('commit',raw);self.merged_raw=raw
        self.binding,self.merge,self.ci=b,m,c
        self.rows=obj('source-full200.json');self.calls=[];self.saved={}
        self.T=Path('/MODELED/packet');self.SOURCE_ROOT=Path('/MODELED/source');self.PUB=self.T/'publication';self.OUT=self.T/'receipts'
        self.WF='.github/workflows/native-arm-build.yml'
        self.parent=P.read(HERE.parent/'native-build-namespace-preflight/parent.raw')
        self.mapping=P.read(HERE/'fixtures/source-map.json.data')
        self.workflow=P.read(HERE/'fixtures/workflow.yml.data')
        self.contract=P.obj(P.read(HERE/'fixtures/contract.json.data'))
        self.U=SimpleNamespace(read=self.read,obj=P.obj)
        self.C=SimpleNamespace(closed_source_declared=self.closed)
        self.factory_rows={n:dict(**G.pin(bodies['after',n]),mode=after[n]['mode'],oid=after[n]['blob']) for n in m['correction_paths']}
        ns=dict(need=G.need)
        functions('ROOT-NATIVE-ONCE.py',['entries'],ns);self.entries=ns['entries']
        self.sync()

    def sync(self):
        self.proofs={'/MODELED/merge.json':P.encoded(self.merge),'/MODELED/ci.json':P.encoded(self.ci)}
        for key,path in [('factory_merge','/MODELED/merge.json'),('factory_CI','/MODELED/ci.json')]:
            self.binding[key]=dict(path=path,**G.pin(self.proofs[path]))

    def read(self,path):
        name=str(path)
        if name in self.proofs:return self.proofs[name]
        if path==self.T/'publication/source.raw':return template('source.raw')
        if path==self.T/'publication/parent.raw':return self.parent
        if path==self.SOURCE_ROOT/'native/source-map.json':return self.mapping
        raise AssertionError(('unmodeled DATA read',path))

    def obj(self,path):
        if path==self.T/'facts.json':return dict(factory_binding=self.binding)
        if path in (self.T/'source-publication.ACTUAL.json',self.PUB/'publication.json'):return obj('source-publication.ACTUAL.json')
        if path==self.T/'source-full200.json':return self.rows
        if path==self.T/'factory-files.json':return self.factory_rows
        if path==self.SOURCE_ROOT/'native/source-map.json':return P.obj(self.mapping)
        if path==self.SOURCE_ROOT/'native/build-tools-contract-v2.json':return self.contract
        raise AssertionError(('unmodeled JSON read',path))

    def closed(self,U,root,auth,modes):
        assert root==self.SOURCE_ROOT and len(auth)==len(modes)==200
        assert auth=={n:{k:r[k] for k in ('bytes','sha256')} for n,r in self.rows.items()}
        assert modes=={n:int(r['mode'],8)&511 for n,r in self.rows.items()}
        self.calls.append('closed200');return G.TREE

    def rowread(self,path,row):
        assert path in (self.SOURCE_ROOT/self.WF,self.SOURCE_ROOT/'.github/workflows/native-arm-developer-workflows.yml')
        assert G.pin(self.workflow)=={k:row[k] for k in ('bytes','sha256')}
        return self.workflow

    def main_guard(self):return self.binding['factory_Main']
    def save(self,path,value):self.saved[str(path)]=value
    @staticmethod
    def table(rows):return b''.join((r['mode']+' blob '+r['blob']+'\t'+n).encode()+b'\0' for n,r in rows.items())
    def git(self,role,*args):
        self.calls.append(role)
        if role=='source-full-map':return self.table({n:dict(mode=r['mode'],blob=r['oid']) for n,r in self.rows.items()})
        if role=='source-raw':return template('source.raw')
        if role=='parent-raw':return self.parent
        if role=='source-local':return G.SOURCE.encode()+b'\n'
        if role=='source-remote':return (G.SOURCE+'\trefs/heads/'+G.REF+'\n').encode()
        if role in ('factory-ancestor','factory-head-ancestor','baseline-main-ancestor'):return b''
        if role in ('current-main-full-map','merged-full-map'):return self.table(self.after)
        if role=='premerge-full-map':return self.table(self.before)
        if role=='merged-raw':return self.merged_raw
        if role.startswith('batch-') or role.startswith('factory-'):
            revision,name=args[1].split(':',1);side='before' if revision==self.merge['premerge_main'] else 'after'
            return self.bodies[side,name]
        raise AssertionError(('unmodeled Git callback',role,args))

    def namespace(self):
        return {key:getattr(self,key) for key in ('T','SOURCE_ROOT','PUB','OUT','WF','U','C','obj','entries','git','rowread','main_guard','save')}


class DataControls(unittest.TestCase):
    def test_exact_source_publication_and_complete_rows(self):
        G.publication(obj('source-publication.ACTUAL.json'),template('source.raw'),obj('source-full200.json'))
        self.assertEqual(len(obj('source-full200.json')),200)

    def test_old_source_parent_reader_and_helper_refused(self):
        p=obj('source-publication.ACTUAL.json');rows=obj('source-full200.json');raw=template('source.raw')
        for key,value in [('source','b659e3049d11ff160494dfc2d8881830c9aae7ac'),('native_run',1),('actual_reader_calls',1),('parent','0'*40)]:
            changed=deepcopy(p);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):G.publication(changed,raw,rows)
        for name in (G.READER['path'],G.HELPER['path']):
            changed=deepcopy(rows);changed[name]['sha256']='0'*64
            with self.subTest(name=name),self.assertRaises(ValueError):G.publication(p,raw,changed)
        with self.assertRaises(ValueError):G.publication(p,raw+b'changed',rows)

    def test_genuine_factory_shape_both_python_steps_exact_count(self):
        b,m,c,*_=proof_model();self.assertIs(G.factory_proofs(b,m,c),b)
        for alter in (
            lambda b,m,c:c.update(checks=74,jobs=74),
            lambda b,m,c:c['feature_jobs'].pop(),
            lambda b,m,c:c['feature_jobs'][1].update(name='Image lifecycle source controls (3.12)'),
            lambda b,m,c:c['feature_jobs'][0].update(name='Unrelated (3.12)'),
            lambda b,m,c:c['feature_jobs'][0].update(head_sha='0'*40),
            lambda b,m,c:c['feature_jobs'][0].update(id=None),
            lambda b,m,c:c['feature_jobs'][1].update(id=c['feature_jobs'][0]['id']),
            lambda b,m,c:c['feature_jobs'][1].update(run_id=2),
            lambda b,m,c:c['feature_jobs'][0]['steps'][0].update(name='unrelated check'),
            lambda b,m,c:c['feature_jobs'][0]['steps'][0].update(conclusion='skipped'),
            lambda b,m,c:c.update(check_job_bijection=False),
            lambda b,m,c:m.update(inverse_restores_actual_premerge_main=False),
            lambda b,m,c:m.update(merge_PUTs=2),
            lambda b,m,c:b.update(expected_CI_checks=None),
        ):
            b,m,c,*_=proof_model();alter(b,m,c)
            with self.assertRaises(ValueError):G.factory_proofs(b,m,c)

    def test_pending_binding_has_no_authority(self):
        with self.assertRaisesRegex(ValueError,'pending'):G.factory(obj('factory-binding.TEMPLATE.json'))
        a=obj('Root-authority.TEMPLATE.json')
        self.assertIsNone(a['approved']);self.assertIsNone(a['issued_at'])
        self.assertTrue(all(v is None for v in a['reviews'].values()))
        self.assertEqual(a['active_run_certificates'],[])
        self.assertEqual(a['scheduling_lane'],G.GROUP)
        for key in ('active','pending','held_by','heavy_kernel_signer_physical_serialization_preserved'):
            self.assertIsNone(a['reservation'][key])
        self.assertEqual(a['resources']['image_build']['daemon_resource_policy'],'UNKNOWN')
        self.assertFalse(a['resources']['image_build']['consumer_limits_bound_build'])

    def test_complete_batch_real_blob_shape_and_inverse(self):
        b,m,c,before,after,bodies=proof_model();G.factory_proofs(b,m,c)
        calls=[]
        def body(side,index,name):calls.append((side,index,name));return bodies[side,name]
        self.assertEqual(len(G.batch(m,before,after,body)),14)
        self.assertEqual(len(calls),25) # 11 changes + three additions, each actual body read.
        self.assertEqual(len(m['correction_paths']),11)

    def test_full_batch_addition_removal_mode_and_body_refusals(self):
        for mutation in ('omitted_addition','wrong_mode','wrong_hash','wrong_blob','false_absence','hidden_change','wrong_body'):
            _,m,_,before,after,bodies=proof_model();body=lambda side,index,name:bodies[side,name]
            name=m['correction_paths'][0]
            if mutation=='omitted_addition':m['reviewed_changes'].pop('owned/new-11')
            elif mutation=='wrong_mode':m['reviewed_changes'][name]['after']['mode']='100755'
            elif mutation=='wrong_hash':m['reviewed_changes'][name]['before']['sha256']='0'*64
            elif mutation=='wrong_blob':m['reviewed_changes'][name]['after']['oid']='0'*40
            elif mutation=='false_absence':m['reviewed_changes'][name]['before']=None
            elif mutation=='hidden_change':after['held/unchanged']=dict(mode='100644',blob='1'*40)
            else:body=lambda side,index,name:b'wrong body'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):G.batch(m,before,after,body)
        # A real removal also gets its old body joined and is restored by the inverse.
        _,m,_,before,after,bodies=proof_model();name='owned/removed';raw=b'removed\n'
        row=dict(**G.pin(raw),mode='100755',oid=G.oid('blob',raw));before[name]=dict(mode=row['mode'],blob=row['oid'])
        m['reviewed_changes'][name]=dict(before=row,after=None);bodies['before',name]=raw
        self.assertEqual(len(G.batch(m,before,after,lambda s,i,n:bodies[s,n])),15)

    def data(self):
        return dict(templates={p.name:P.read(p) for p in (HERE/'templates').iterdir()},external={},binding=None,
                    source_root='/MODELED/source-not-executed',rows=obj('source-full200.json'),source_bytes=40281721)

    def test_render_seals_all_operators_and_reader_without_issuing_roles(self):
        files=P.render(self.data(),Path('/MODELED/fresh-packet'));seal=P.obj(files['seal.json'])
        self.assertTrue(all(G.pin(files[n])==r for n,r in seal['files'].items()))
        self.assertNotIn('@INPUT_SEAL_SHA256@',files['ROOT-NATIVE-ONCE.py'].decode())
        self.assertNotIn('@ROOT_OPERATOR_SHA256@',files['ROOT-INDEPENDENT-PREFLIGHT.py'].decode())
        index=P.obj(files['input-seal.json']);self.assertNotIn('/MODELED/fresh-packet/ROOT-NATIVE-ONCE.py',index)
        self.assertEqual(index['/MODELED/fresh-packet/namespace_guard.py'],G.pin(files['namespace_guard.py']))
        facts=P.obj(files['facts.json']);self.assertIsNone(facts['factory_binding']);self.assertFalse(facts['acceptance'])
        commands=P.obj(files['root-commands.json']);self.assertTrue(commands['factory_CI_Main_pending'])
        self.assertIsNone(commands['native']['Root_resource_authority'])
        self.assertIn(None,commands['native']['argv'])
        reader=P.obj(files['strict-reader-binding.TEMPLATE.json']);self.assertFalse(reader['reader_executed'])
        self.assertIsNone(reader['expected_binding']['run'])
        self.assertEqual(P.obj(files['matching-reader-closure.ACTUAL.json'])['files'],obj('source-full200.json'))
        self.assertFalse(any(n.startswith(('receipts/','actual-native/')) for n in files))

    def test_pending_packet_refuses_before_bootstrap_or_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'new';files=P.render(self.data(),out);P.publish(files,out)
            ns=dict(Path=Path,json=json,T=out,SOURCE=G.SOURCE,TREE=G.TREE,MAP=G.MAP,REF=G.REF,INPUT_SEAL='bound',pin=G.pin,need=G.need)
            functions('ROOT-NATIVE-ONCE.py',['verify_packet'],ns)
            with self.assertRaisesRegex(ValueError,'before bootstrap'):ns['verify_packet'](G.pin(files['seal.json'])['sha256'])
            self.assertFalse((out/'receipts').exists());self.assertFalse((out/'actual-native').exists())
            (out/'facts.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'whole packet'):ns['verify_packet'](G.pin(files['seal.json'])['sha256'])
            with self.assertRaises(FileExistsError):P.publish(files,out)

    def test_reader_and_root_issuer_templates_are_independent(self):
        a=obj('Root-authority.TEMPLATE.json');r=obj('strict-reader-binding.TEMPLATE.json')
        self.assertEqual(a['source'],r['expected_binding']['source']);self.assertEqual(a['source'],G.SOURCE)
        self.assertEqual(a['map_sha256'],r['expected_binding']['map_sha256'])
        self.assertIsNone(r['Root_independent_image_engine_authority']);self.assertIsNone(r['actual_run'])
        self.assertEqual(r['reader']['sha256'],G.READER['sha256'])

    def test_original_critical_guard_bodies_retained(self):
        held=P.obj(P.read(HERE/'held-function-ast.json'))
        for key,digest in held.items():
            file,name=key.split(':');tree=ast.parse(template(file));node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
            if name=='certify_x86_run':
                removed=[n for n in node.body if isinstance(n,ast.AugAssign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='namespace_certificates']
                self.assertEqual(len(removed),1);node.body=[n for n in node.body if n not in removed]
            class Normalize(ast.NodeTransformer):
                def visit_Constant(self,node):
                    if isinstance(node.value,str):
                        node.value=node.value.replace('NAMESPACE_PREFLIGHT','DEVELOPER_TOOLS')
                        node.value={'PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION':'PUBLISHED_EXACT_DEVELOPER_QUIET_TOOLS_BUILD_SOURCE200_ROOT_GIT_REMOTE_VERIFIED',
                                    'native/build_tools_reader_v2.py':'native/developer_tools_reader_v1.py'}.get(node.value,node.value)
                    return node
            raw=ast_bytes(Normalize().visit(node))
            with self.subTest(guard=key):self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)

    def test_root_authority_pure_gate_requires_fresh_explicit_reservation(self):
        a=obj('Root-authority.TEMPLATE.json');base=deepcopy(a)
        base.update(approved=True,status='ROOT_ISSUED_EXACT_NAMESPACE_PREFLIGHT_CANONICAL_HEAVY',issued_at=datetime.now(timezone.utc).isoformat())
        base['reviews']={key:True for key in base['reviews']}
        base['reservation'].update(active=0,pending=0,held_by='Root',heavy_kernel_signer_physical_serialization_preserved=True)
        state={'body':P.encoded(base)}
        ns=dict(Path=Path,U=SimpleNamespace(read=lambda p:state['body'],obj=P.obj),pin=G.pin,need=G.need,
                obj=lambda p:a,T=Path('/MODELED'),SOURCE=G.SOURCE,GROUP=G.GROUP,OP=G.OPERATION,datetime=datetime,timezone=timezone)
        functions('ROOT-NATIVE-ONCE.py',['admission'],ns)
        self.assertEqual(ns['admission']('/MODELED/authority',G.pin(state['body'])['sha256']),base)
        for key,value in [('approved',None),('active_run_certificates',[{'not':'exempt'}]),('issued_at','2000-01-01T00:00:00+00:00')]:
            changed=deepcopy(base);changed[key]=value;state['body']=P.encoded(changed)
            with self.subTest(key=key),self.assertRaises(ValueError):ns['admission']('/MODELED/authority',G.pin(state['body'])['sha256'])
        changed=deepcopy(base);changed['reservation']['pending']=1;state['body']=P.encoded(changed)
        with self.assertRaises(ValueError):ns['admission']('/MODELED/authority',G.pin(state['body'])['sha256'])
        state['body']=P.encoded(a)
        with self.assertRaises(ValueError):ns['admission']('/MODELED/authority',G.pin(state['body'])['sha256'])

    def test_extra_x86_classifications_are_refs_only_not_permission(self):
        registry=obj('Root-namespace-x86-certificates.json');self.assertFalse(registry['resource_permission'])
        self.assertFalse(registry['native_permission']);self.assertEqual(len(registry['certificates']),3)
        self.assertEqual(registry['certificates'],obj('Root-authority.TEMPLATE.json')['namespace_x86_body_certificates'])
        ns=dict(json=json,re=re,HERE=HERE/'templates',need=G.need)
        functions('ci-adapter.py',['validate_namespace_certificate'],ns)
        c=obj('x86-body-certificate.template.json')
        c.update(schema=1,issuer='Root',status='ROOT_CLASSIFIED_EXACT_HOSTED_X86_WORKFLOW_BODY',independently_classified=True,
                 classification='AUTOMATIC_HOSTED_X86_CI_ONLY',approval_scope='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED',
                 native_permission=False,CI_success_claim=False,runner_literals=['ubuntu-24.04'],job_labels=['ubuntu-24.04'],closed_scope='MODELED only',workflow_id=1,
                 workflow=dict(path='.github/workflows/model.yml',bytes=1,sha256='a'*64,mode='100644',oid='b'*40),
                 reviewed_git_source=dict(source='c'*40,raw_commit=dict(bytes=1,sha256='d'*64)))
        self.assertIs(ns['validate_namespace_certificate'](c),c)
        for key,value in [('native_permission',True),('CI_success_claim',True),('runner_literals',['ubuntu-24.04-arm'])]:
            bad=deepcopy(c);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):ns['validate_namespace_certificate'](bad)

    def test_complete_source_factory_and_matching_reader_qualification_model(self):
        model=QualificationModel();main=G.qualify(model.namespace())
        self.assertEqual(main,model.binding['factory_Main'])
        receipt=model.saved[str(model.OUT/'source-qualification.json')]
        self.assertEqual(receipt['factory_batch_changed'],14);self.assertEqual(receipt['factory_correction_subset'],11)
        self.assertEqual(receipt['reader']['sha256'],G.READER['sha256'])
        self.assertFalse(receipt['reader_executed']);self.assertFalse(receipt['acceptance'])
        self.assertIn('closed200',model.calls);self.assertIn('merged-raw',model.calls)

    def test_whole_qualification_refuses_omitted_batch_and_false_merge(self):
        for change in ('omit','wrong_raw','wrong_final_correction','changed_contract'):
            model=QualificationModel()
            if change=='omit':model.merge['reviewed_changes'].pop('owned/new-11')
            elif change=='wrong_raw':model.merged_raw+=b'tampered'
            elif change=='wrong_final_correction':model.factory_rows[model.merge['correction_paths'][0]]['sha256']='0'*64
            else:model.contract['bounds']['command_rows']=3
            model.sync()
            with self.subTest(change=change),self.assertRaises(ValueError):G.qualify(model.namespace())
            self.assertEqual(model.saved,{})

    def test_extra_certificate_still_joins_actual_git_source_and_hosted_jobs(self):
        raw=b'name: MODELED x86\njobs:\n  model:\n    runs-on: ubuntu-24.04\n'
        path='.github/workflows/MODELED.yml'
        witness=b'tree '+b'a'*40+b'\n\nMODELED reviewed\n';actual=b'tree '+b'b'*40+b'\n\nMODELED actual\n'
        source=G.oid('commit',actual);reviewed=G.oid('commit',witness)
        c=obj('x86-body-certificate.template.json')
        c.update(schema=1,issuer='Root',status='ROOT_CLASSIFIED_EXACT_HOSTED_X86_WORKFLOW_BODY',independently_classified=True,
                 classification='AUTOMATIC_HOSTED_X86_CI_ONLY',approval_scope='EXACT_BYTES_EACH_ACTUAL_SOURCE_AND_JOBS_REJOINED',
                 native_permission=False,CI_success_claim=False,runner_literals=['ubuntu-24.04'],job_labels=['ubuntu-24.04'],closed_scope='MODELED only',workflow_id=7,
                 workflow=dict(path=path,**G.pin(raw),mode='100644',oid=G.oid('blob',raw)),
                 reviewed_git_source=dict(source=reviewed,raw_commit=G.pin(witness)))
        run=dict(event='push',path=path,workflow_id=7,id=1,run_attempt=1,head_sha=source,
                 repository=dict(id=1414857795,full_name='Gabriel-Kahen/cachy-asahi'),head_repository=dict(id=1414857795,full_name='Gabriel-Kahen/cachy-asahi'))
        job=dict(id=2,run_id=1,head_sha=source,run_attempt=1,status='completed',conclusion='success',labels=['ubuntu-24.04'],runner_id=3,
                 runner_group_id=0,runner_group_name='GitHub Actions',runner_name='GitHub Actions 3')
        authority=dict(x86_body_certificates=obj('Root-eight-x86-certificates.json')['certificates'],current_x86_body_certificates=[],namespace_x86_body_certificates=[],x86_body_catalog={})
        saved=[]
        with tempfile.TemporaryDirectory() as tmp:
            receipts=Path(tmp);a=receipts/'MODELED-authority.json';a.write_bytes(P.encoded(authority))
            (receipts/'admission-bound.json').write_bytes(P.encoded(dict(path=str(a),admission=G.pin(a.read_bytes()))))
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
            catalog=SimpleNamespace(certificates=lambda *args:[])
            held=SimpleNamespace(inputs=lambda:(Path('/MODELED/held'),None),obj=lambda p:dict(certificates={}),save=lambda *args:saved.append(args))
            ns=dict(Path=Path,json=json,hashlib=hashlib,re=re,HERE=HERE/'templates',need=G.need,pin=G.pin,oid=G.oid,held=held,
                    reference=lambda row:dict(workflow=dict(path=row['path'],sha256=row['sha256'])),current_certificates=lambda rows:[],namespace_certificates=lambda rows:[c],
                    importlib=SimpleNamespace(util=SimpleNamespace(spec_from_file_location=lambda *args:spec,module_from_spec=lambda s:catalog)))
            functions('ci-adapter.py',['certify_x86_run'],ns)
            bad_actual=False
            def git(*args):
                if args[:2]==('cat-file','commit'):return {reviewed:witness,source:actual}[args[2]]
                if args[0]=='show':return b'changed actual body' if bad_actual and args[1].startswith(source+':') else raw
                if args[0]=='ls-tree':return ('100644 blob '+G.oid('blob',raw)+'\t'+path).encode()+b'\0'
                raise AssertionError(args)
            def certify(r,j):return ns['certify_x86_run'](lambda *args:(_ for _ in ()).throw(AssertionError('GET forbidden')),git,r,path,raw,j,'unused',receipts)
            result=certify(run,[job]);self.assertFalse(result['native_permission']);self.assertFalse(result['CI_success_claim']);self.assertEqual(len(saved),1)
            for mutate in ('native_label','self_hosted','wrong_job_source','wrong_workflow','empty_jobs','wrong_actual_body'):
                r=deepcopy(run);j=deepcopy(job);jobs=[j];bad_actual=False
                if mutate=='native_label':j['labels']=['ubuntu-24.04-arm']
                elif mutate=='self_hosted':j['runner_group_name']='self-hosted'
                elif mutate=='wrong_job_source':j['head_sha']='0'*40
                elif mutate=='wrong_workflow':r['workflow_id']=8
                elif mutate=='empty_jobs':jobs=[]
                else:bad_actual=True
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):certify(r,jobs)
            self.assertEqual(len(saved),1)

    def test_json_and_operand_alias_refusals(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):P.obj(raw)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'file';p.write_bytes(b'data');link=root/'alias';link.symlink_to(p)
            with self.assertRaises(ValueError):P.read(link)
            hard=root/'hard';os.link(p,hard)
            with self.assertRaises(ValueError):P.read(p)


if __name__=='__main__':unittest.main()
