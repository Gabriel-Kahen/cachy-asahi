#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite exact-carrier caller projection; no issuance, entry or metadata command."""
import argparse
import ast
import base64
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
if not (HERE/'prepare.py').exists():HERE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-native349-pinned-input-carrier-20261117/scripts/ci/native349-pinned-input-carrier')
s=importlib.util.spec_from_file_location('exact_carrier_source',HERE/'prepare.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)
P=S.P
PARENT_SEAL=dict(bytes=4942,sha256='dfe7043e6936762d8d6281e00b689d290511ff7dec8b0ee528ec01de6d7a4c80')
OPERATOR='packet/operator-DRAFT/llhttp_once.py';PRIMITIVE='packet/operator-DRAFT/llhttp_dispatch_once.py'
PROOF='carrier-parent-inverse.DATA.json'
OLD_SOURCE='c23c2874c82a3e83b76be09fe98ee6e134c8ff81';OLD_REF='codex/llhttp-reference-native-source-20261117-r6'


def physical(root,mode):
    root=P.ordinary(root);out={}
    for path in root.rglob('*'):
        P.need(not path.is_symlink(),'ordinary complete carrier namespace')
        if path.is_file():
            P.need(path.stat().st_mode&0o777==mode,'whole carrier modes');out[str(path.relative_to(root))]=P.read(path)
        else:P.need(path.is_dir(),'no special carrier members')
    return out


def parent_bodies(root):
    value=physical(root,0o600);validate_parent(value);return value


def validate_parent(value):
    P.need(len(value)==27 and sum(map(len,value.values()))==1660733 and P.pin(value['packet-seal.DATA.json'])==PARENT_SEAL,'whole immutable27 Source95 caller')
    rows=json.loads(value['packet-seal.DATA.json'])['files']
    P.need(set(value)==set(rows)|{'packet-seal.DATA.json'} and all(dict(P.pin(value[n]),mode=0o600)==r for n,r in rows.items()),'whole27 prior caller body inverse')


def source_binding(root,publication=None,registration=None):
    bodies=physical(root,0o644);old=S.inverse(bodies);S.validate_parent(old)
    m=json.loads(bodies['source-map.json'])
    P.need(all(v is None for v in m['actual'].values()) and len(bodies)==95 and sum(map(len,bodies.values()))<2*1024**2,'same strict Source bounds/allNULL')
    result=dict(tree=P.tree(bodies),source_files=len(bodies),source_bytes=sum(map(len,bodies.values())),source_map=P.pin(bodies['source-map.json']),
        owner_program=P.pin(bodies[S.PREFIX+'owner-program.json']),policy=P.pin(bodies[S.PREFIX+'policy.json']),workflow_body=P.pin(bodies[S.NEW_WF]),
        public_retention=P.pin(bodies[S.PREFIX+'public_evidence.py']),carrier_helper=P.pin(bodies[S.HELPER]),source_root=str(root),
        source_CID=None,source_ref=None,workflow_id=None,delegated_metadata_result=None,registration_metadata_result=None,Root_authority=None,runtime54_profile=None,
        source_inverse_counts=[95,93,85,76,68,62],native_pair='NOT RUN',Root_entry='NOT RUN')
    if publication is not None:
        path,digest=publication;raw=P.read(path);v=json.loads(raw)
        P.need(P.pin(raw)['sha256']==digest and v['issuer']=='Root' and v['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY'
            and type(v['source'])is str and re.fullmatch('[0-9a-f]{40}',v['source']) and type(v['ref'])is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9_.-]+',v['ref'])
            and v['tree']==result['tree'] and v['source_map']==result['source_map'] and v['files']==95 and v['bytes']==result['source_bytes']
            and v['source']!=OLD_SOURCE and v['ref']!='refs/heads/'+OLD_REF and v['native']==v['M2']=='NOT RUN'
            and all(v[k]is True for k in('public_clone_complete','public_blob_tree_join','Root_independent_whole_file_mode_recheck','Root_independent_fresh_ref_commit_recheck')),'actual exact new Source publication only')
        result.update(source_CID=v['source'],source_ref=v['ref'],delegated_metadata_result=dict(path=str(path),**P.pin(raw)))
    if registration is not None:
        path,digest=registration;raw=P.read(path);v=json.loads(raw)
        P.need(P.pin(raw)['sha256']==digest and v['kind']=='CALLER_WORKFLOW_REGISTRATION_READBACK_DATA_V1' and v['repository']=='Gabriel-Kahen/cachy-asahi'
            and type(v['workflow_id'])is int and v['workflow_id']>0 and v['workflow_id']!=420972285 and v['workflow_path']==S.NEW_WF
            and v['workflow_sha256']==result['workflow_body']['sha256'] and v['registered_on_default_branch']is True and v['state']=='active','exact distinct actual new workflow registration')
        result.update(workflow_id=v['workflow_id'],registration_metadata_result=dict(path=str(path),**P.pin(raw)))
    return result


def render(original,binding,script,test,policy):
    new=dict(original);old=json.loads(original['binding.DATA.json']);seams={}
    def change(name,before,after):
        if before==after:return
        text=new[name].decode();P.need(before in text,'one finite caller seam: '+before[:100]);new[name]=text.replace(before,after).encode()
        seams.setdefault(name,[]).append(dict(before=before,after=after))
    cid=binding['source_CID'];ref=None if binding['source_ref']is None else binding['source_ref'].removeprefix('refs/heads/')
    for name in (OPERATOR,PRIMITIVE):
        for before,after in ((old['tree'],binding['tree']),(old['source_map']['sha256'],binding['source_map']['sha256']),
             (repr(old['policy']),repr(binding['policy'])),(repr(old['owner_program']),repr(binding['owner_program'])),
             (S.OLD_WF,S.NEW_WF),(old['workflow_body']['sha256'],binding['workflow_body']['sha256'])):change(name,before,after)
        change(name,"CANDIDATE_SOURCE="+repr(OLD_SOURCE)+";CANDIDATE_REF="+repr(OLD_REF),
                    'CANDIDATE_SOURCE='+repr(cid)+';CANDIDATE_REF='+repr(ref)+';CANDIDATE_WORKFLOW_ID='+repr(binding['workflow_id']))
        change(name,", '8f6370a35215496c0e6c10922929028f5146644b');CONSUMED_REFS=",", '8f6370a35215496c0e6c10922929028f5146644b', "+repr(OLD_SOURCE)+");CONSUMED_REFS=")
        change(name,"'codex/llhttp-reference-native-source-20261117-r5')","'codex/llhttp-reference-native-source-20261117-r5', "+repr(OLD_REF)+')')
        change(name,'==420972285','==CANDIDATE_WORKFLOW_ID')
    change(OPERATOR,'PROPOSED_REF='+repr(OLD_REF),'PROPOSED_REF='+repr(ref))
    change(OPERATOR,"OP='llhttp-reference-inner-public-retention-v6'","OP='llhttp-reference-native349-pinned-input-carrier-v1'")
    change(OPERATOR,'source_bytes=1318237','source_bytes='+str(binding['source_bytes']))
    change(OPERATOR,"public['bytes']==1318237","public['bytes']=="+str(binding['source_bytes']))
    change(OPERATOR,"==1318237 and all(r['mode']","=="+str(binding['source_bytes'])+" and all(r['mode']")
    change(OPERATOR,'dict(bytes=20200,sha256=MAP)','dict(bytes='+str(binding['source_map']['bytes'])+',sha256=MAP)')
    change(OPERATOR," program_raw=read(root/prefix/'owner-program.json')",
        " need(pin(read(root/prefix/'native349_carrier.py'))=="+repr(binding['carrier_helper'])+",'exact pinned-input carrier helper')\n program_raw=read(root/prefix/'owner-program.json')")
    change(OPERATOR,'PRIMITIVE_SHA='+repr(P.pin(original[PRIMITIVE])['sha256']),'PRIMITIVE_SHA='+repr(P.pin(new[PRIMITIVE])['sha256']))
    name='issue_root_packet.DRAFT.py';text=new[name].decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='SOURCE'for t in n.targets))
    change(name,ast.get_source_segment(text,node),'SOURCE=Path('+repr(binding['source_root'])+')')
    name='packet/operator-DRAFT/workflow-registration.TEMPLATE.json';v=json.loads(new[name]);v.update(workflow_path=S.NEW_WF,workflow_id=None,workflow_sha256=binding['workflow_body']['sha256']);new[name]=P.encode(v)
    new['packet/operator-DRAFT/policy.json']=policy
    new['binding.DATA.json']=P.encode(dict(binding,opbindings={n:P.pin(new[n])for n in(OPERATOR,PRIMITIVE,'issue_root_packet.DRAFT.py','packet/make_root_config.DRAFT.py')}))
    inputs={k:None for k in json.loads(original['ROOT-INPUTS.UNISSUED.json'])};inputs.update(status='PINNED_INPUT_CARRIER_NATIVE_OPERANDS_UNISSUED',Root_entry='NOT RUN',source_CID=cid,source_ref=binding['source_ref'],delegated_metadata_result=binding['delegated_metadata_result']);new['ROOT-INPUTS.UNISSUED.json']=P.encode(inputs)
    new['registration-plan.DATA.json']=P.encode(dict(issuer='workerDATA',Root_adoption=None,registration=None,Main=None,repository='Gabriel-Kahen/cachy-asahi',workflow_id=binding['workflow_id'],workflow_path=S.NEW_WF,workflow_body=binding['workflow_body'],initial_final_Main_CAS=None,required_secret_name_count=23,secret_name_catalog=None,secret_values_read=False,Root_authority=None))
    new['HANDOFF.md']=b'Exact182 carrier Source canonical ONCE DRAFT. Complete27 original Source95 caller inverse; all old constraints preserved. New workflow requires actual Main registration; carrier/public Source metadata and all Root native authority remain unissued until separately supplied. No private fetch, role or POST occurs in construction.\n'
    new['prepare-carrier.py']=script;new['test_canonical_cli.DATA.py']=test
    for name,parts in seams.items():
        text=new[name].decode()
        for part in reversed(parts):text=text.replace(part['after'],part['before'])
        P.need(text.encode()==original[name],'whole operational caller seam inverse')
    return new


def inverse(value):
    bodies=physical(value,0o600)if isinstance(value,(str,Path))else value
    seal=json.loads(bodies['packet-seal.DATA.json']);rows=seal['files']
    P.need(set(bodies)==set(rows)|{'packet-seal.DATA.json'} and all(dict(P.pin(bodies[n]),mode=0o600)==r for n,r in rows.items()),'whole sealed caller')
    P.need(seal['Root_authority']is None and seal['role_label']is None and seal['runtime54_profile']is None and seal['actual_POSTs']==0,'unissued complete caller seal')
    proof=json.loads(bodies[PROOF]);P.need(proof['parent_seal']==PARENT_SEAL and len(proof['files'])==27,'complete27 compact inverse rows')
    old={}
    for name,row in proof['files'].items():
        raw=bodies[name]if row['inherited']else base64.b64decode(row['body_base64'],validate=True)
        P.need(P.pin(raw)==row['pin']and row['mode']==0o600,'whole original caller body/mode');old[name]=raw
    validate_parent(old)
    binding=json.loads(bodies['binding.DATA.json'])
    expected=render(old,binding,bodies['prepare-carrier.py'],bodies['test_canonical_cli.DATA.py'],bodies['packet/operator-DRAFT/policy.json'])
    P.need(set(expected)|{PROOF}==set(bodies) and all(bodies[n]==r for n,r in expected.items()if n!='packet-seal.DATA.json'),'whole finite caller projection')
    return old


def construct(parent,source,output,publication=None,registration=None):
    parent,source,output=map(P.ordinary,(parent,source,output));P.need(not output.exists()and all(not output.is_relative_to(p)and not p.is_relative_to(output)for p in(parent,source)),'fresh disjoint caller')
    old=parent_bodies(parent);binding=source_binding(source,publication,registration)
    new=render(old,binding,P.read(HERE/'prepare_canonical.py'),P.read(HERE/'test_canonical.py'),P.read(source/S.PREFIX/'policy.json'))
    new[PROOF]=P.encode(dict(parent_seal=PARENT_SEAL,files={n:dict(pin=P.pin(raw),mode=0o600,inherited=new.get(n)==raw and n!='packet-seal.DATA.json',**({}if new.get(n)==raw and n!='packet-seal.DATA.json' else dict(body_base64=base64.b64encode(raw).decode())))for n,raw in old.items()},Root_authority=None))
    new['packet-seal.DATA.json']=P.encode(dict(status='PINNED_INPUT_CARRIER_CANONICAL_DRAFT_UNISSUED',files={n:dict(P.pin(raw),mode=0o600)for n,raw in sorted(new.items())if n!='packet-seal.DATA.json'},Root_authority=None,role_label=None,runtime54_profile=None,actual_source_metadata=binding['source_CID'],source_ref=binding['source_ref'],actual_POSTs=0))
    inverse(new);P.need(len(new)<40 and sum(map(len,new.values()))<2*1024**2,'unchanged finite40leaf/2MiB caller bounds')
    output.mkdir(mode=0o700)
    for name,raw in new.items():
        p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
        if p.suffix=='.py':ast.parse(raw)
    return dict(status='UNISSUED_EXACT_CARRIER_CANONICAL_ONCE_DRAFT',files=len(new),bytes=sum(map(len,new.values())),binding=binding,seal=P.pin(new['packet-seal.DATA.json']),operator=P.pin(new[OPERATOR]),primitive=P.pin(new[PRIMITIVE]),Root_authority=None)


if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__)
    for n in('parent','source','output'):a.add_argument('--'+n,type=Path,required=True)
    for n in('publication','registration'):a.add_argument('--'+n,type=Path);a.add_argument('--'+n+'-sha256')
    v=a.parse_args()
    for n in('publication','registration'):P.need((getattr(v,n)is None)==(getattr(v,n+'_sha256')is None),'whole optional actual metadata binding')
    print(json.dumps(construct(v.parent,v.source,v.output,*[None if getattr(v,n)is None else(getattr(v,n),getattr(v,n+'_sha256'))for n in('publication','registration')]),sort_keys=True,indent=2))
