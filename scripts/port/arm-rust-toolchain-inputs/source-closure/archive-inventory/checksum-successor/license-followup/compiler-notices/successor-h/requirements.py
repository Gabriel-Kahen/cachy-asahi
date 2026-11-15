#!/usr/bin/env python3
"""Route exact missing inputs for this finite 90-case ledger; never accept cases."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import resource
import signal
import tomllib
import urllib.parse

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_g', HERE.parent / 'successor-g/reevaluate.py')
previous = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(previous)
compiler = previous.compiler
require, pin, blob = compiler.require, compiler.prior.pin, compiler.prior.blob

# Data requirements, not an acquisition executor or legal acceptance engine.
CATALOG = {
 'dirty_source': {'supplier': 'retained source/delta custodian', 'required_inputs': ['Exact published dirty bytes and complete delta against the recorded base', 'Grant/notice provenance covering base and every changed contribution'], 'gates': ['Never clear the original dirty flag', 'A clean replacement is a different candidate and cannot close this original artifact by substitution']},
 'publisher_transform': {'supplier': 'publisher provenance record', 'required_inputs': ['Immutable publisher script/revision and release record for 0.166.0', 'Deterministic generated manifest/source mapping from declared Rust commit ce89c898570852a1bb441d77570596e50bf362c2 to the exact retained generated package'], 'gates': ['Every generated manifest must match its retained full SHA-256', 'Do not assume ra-ap manifests equal rustc manifests', 'Current publisher head/tag or common version does not replace missing transformation/VCS proof']},
 'source_lineage': {'supplier': 'publisher/release provenance record', 'required_inputs': ['Retained exact package VCS declaration or authoritative equivalent when that record is absent/failed', 'Same retained package artifact/checksum and manifest/source correspondence; retained VCS availability alone does not discharge manifest/workspace gates'], 'gates': ['No guessed repository, tag/head, or revision correction', 'README project links alone and equal license bodies do not establish lineage', 'A prior HTTP failure is historical evidence, not proof that no source exists', 'SATISFIED here means the narrow VCS input is available; canonical repository and package manifest correspondence still require their separate gates']},
 'original_manifest': {'supplier': 'exact-version published source or retained indexed metadata', 'required_inputs': ['Complete original manifest bytes matching the retained full hash and captured prefix when available'], 'gates': ['An absent original manifest is not a truncated one: request provenance, not a fabricated hash', 'Full hash and prefix must both match before parsing/replacing the in-memory view', 'Frozen private capture remains unchanged']},
 'sdk_scope': {'supplier': 'versioned SDK/source licensing record', 'required_inputs': ['Exact source/SDK derivation and applicable grant/notice scope for framework code', 'Complete actual package grant and attribution; SPDX overview links alone are insufficient'], 'gates': ['Preserve the retained Apple SDK distribution uncertainty', 'Do not infer permission or ownership from framework/author/company names', 'Do not automatically assign this SDK finding to the five core objc runtime crates']},
 'workspace': {'supplier': 'exact pinned ancestor workspace metadata', 'required_inputs': ['Governing Cargo.toml at the recorded revision, evidenced explicit/implicit path membership and exclusions, and inherited values', 'Proof no nearer workspace overrides the governing metadata'], 'gates': ['Match all manifest Git blobs and package identity', 'Retain already-satisfied version proofs for the three recorded wasm cases', 'An inherited declaration is not proof its value is unresolved if a current exact proof already exists']},
 'manifest_git': {'supplier': 'primary immutable Git metadata/source', 'required_inputs': ['Exact original manifest Git blob at the recorded source path/revision', 'Exact literal version or proved governing workspace version'], 'gates': ['No metadata declaration alone becomes a package-source proof', 'Keep absent VCS path distinct from a proved root path', 'Reject dirty/version/body mismatches rather than selecting a convenient revision']},
 'grant_text': {'supplier': 'exact package/project upstream source', 'required_inputs': ['Complete actual selected license grant/conditions/disclaimers and package ancestor or explicit project application proof'], 'gates': ['No SPDX-only or substituted canonical template', 'Retain every applicable condition and distinct required notice', 'Keep source-code license owners distinct from owners of license text itself']},
 'package_notice': {'supplier': 'authoritative version/revision-scoped notice record', 'required_inputs': ['Actual named copyright/NOTICE evidence and exact package/project scope', 'Exact notice-source URL/revision/body hash and grant-source relationship'], 'gates': ['No authors, equal license bodies, Apache placeholders, or source-file notice promoted to a whole package', 'Keep code and supplemental notice revisions distinct; any supplemental attestation must explicitly identify the old snapshot and receive scope review', 'Do not refetch already-retained root templates hoping for different names; a new scoped input is required']}
}
PRIORITY = ['dirty_source', 'publisher_transform', 'source_lineage', 'original_manifest', 'sdk_scope', 'workspace', 'manifest_git', 'grant_text', 'package_notice']
FAILURES = {
 'hifijson-0.5.0': ('../requests.json',17,422), 'rsqlite-vfs-0.1.1': ('../successor-b/requests.json',8,422),
 'syn-test-suite-0.0.0+test': ('../successor-e/requests.json',13,404), 'perf-event-open-sys-4.0.0': ('../successor-g/requests.json',3,404),
 'selectors-0.25.0': ('requests.json',2,404), 'servo_arc-0.3.0': ('requests.json',3,404)
}


def record_pin(record):
    return {k: record[k] for k in ('bytes','sha256')}


def package_metadata(record):
    if record is None:
        return {}, 'ABSENT'
    body = record['text'].encode()
    require(len(body) == record['captured_bytes'] and pin(body)['sha256'] == record['captured_prefix_sha256'], 'capture prefix pin mismatch')
    if record['complete_text']:
        compiler.prior.check(body, record_pin(record))
        return tomllib.loads(record['text'])['package'], 'COMPLETE'
    # Only use a fully closed first [package] table as observed prefix DATA.
    text = record['text']
    end = text.find('\n[', 1)
    if text.startswith('[package]') and end > 0:
        return tomllib.loads(text[:end])['package'], 'CAPTURED_PACKAGE_TABLE_ONLY'
    return {}, 'INCOMPLETE'


def candidate_repository(package, proof, component):
    if proof:
        return proof['repository'], 'EXACT_RETAINED_PACKAGE_BINDING'
    value = package.get('repository')
    if isinstance(value, str):
        match = re.match(r'https://github.com/([^/]+/[^/]+)', value)
        if match:
            return match.group(1).removesuffix('.git'), 'DECLARATION_ONLY_NOT_PACKAGE_BINDING'
    # Already-retained primary roots are candidates, not inherited repo proof.
    if component.startswith(('cranelift-', 'wasmtime-internal-')):
        return 'bytecodealliance/wasmtime', 'RETAINED_CANDIDATE_ROOT_ONLY'
    if component.startswith(('wasip2-', 'wasip3-')):
        return 'bytecodealliance/wasi', 'RETAINED_CANDIDATE_ROOT_ONLY'
    if component.startswith('wit-bindgen-rt-'):
        return 'bytecodealliance/wit-bindgen', 'RETAINED_CANDIDATE_ROOT_ONLY'
    if component.startswith(('objc2-', 'block2-', 'dispatch2-')):
        return 'madsmtm/objc2', 'RETAINED_CANDIDATE_ROOT_ONLY'
    return None, 'UNESTABLISHED'


def metadata_request(repo, revision, path, orig, blocked):
    if not repo or not revision or not path or not orig:
        return None
    url = 'https://api.github.com/repos/' + repo + '/contents/' + urllib.parse.quote(path) + '?ref=' + revision
    result = {'candidate_url':url, 'expected_path':path, 'expected_original_body_pin':record_pin(orig),
              'automatic_fetch_recommended':not blocked, 'acceptance':'Exact decoded body full hash/prefix plus path/revision; URL existence alone is not package proof'}
    if orig['complete_text']:
        result['expected_git_blob_sha1'] = blob(orig['text'].encode())
    if blocked:
        result['before_acquisition']='Resolve the listed dirty/missing-lineage/publisher inputs; do not repeat failed or speculative probes'
    return result


def network_summary(ledger):
    events=ledger['requests']; size=sum(r['bytes'] for r in events); elapsed=ledger['stopped_epoch']-ledger['started_epoch']
    require(len(events)<=50 and size==ledger['body_bytes'] and size<=2*1024**2 and all(isinstance(r.get('bytes'),int) and 0<=r['bytes']<=128*1024 for r in events),'network byte/request budget mismatch')
    require([r['ordinal'] for r in events]==list(range(1,len(events)+1)),'request ordinal mismatch')
    require(ledger.get('acquisition_closed') is True and 0<=elapsed<=900,'acquisition deadline mismatch')
    return {'new_actual_HTTP_requests':len(events),'new_response_body_bytes':size,'acquisition_seconds':round(elapsed,3),
            'error_requests':[r['ordinal'] for r in events if r.get('HTTP',0)>=400 or not r.get('complete_body')],
            'offline_replay_requests':0}


def build(packet_path):
    inputs = json.loads((HERE/'inputs.json').read_text())
    def read(name):
        body=(HERE/name).read_bytes(); compiler.prior.check(body,inputs['evidence_files'][name]); return body
    for name in inputs['evidence_files']:
        read(name)
    baseline=previous.evaluate(packet_path)
    require(baseline==json.loads(read('../successor-g/report.json')), 'baseline replay changed')
    packet_body=packet_path.read_bytes(); compiler.prior.check(packet_body,inputs['candidate_packet']); packet=json.loads(packet_body)
    require(packet['source_pin_verified'], 'authenticated source packet required')
    remaining=baseline['remaining_components']; selected=inputs['selected_components']
    require(len(selected)<=12 and len(selected)==len(set(selected)) and set(selected)<=set(remaining), 'invalid finite selection')
    require(not set(selected)&set(baseline['screened_components']), 'do not reselect previous G cohort')
    notes={r['component']:r for r in json.loads(read('../../priority-notes.json'))['all_case_membership_and_proof_availability']}
    inventory=json.loads(read('../../../../reports/rust.json'))
    current={r['component']:{**r,'proof_ref':'../report.json#cases/'+r['component']} for r in json.loads(read('../report.json'))['cases']}
    c=json.loads(read('../successor-c/report.json')); current[c['package_binding']['component']]={**c['package_binding'],'proof_ref':'../successor-c/report.json#package_binding','grant_pin':c['file_notice']['grant_pin']}
    rows=[]
    for component in remaining:
        require(packet['component_statuses'].get(component)=='PASS','routing case must retain authenticated checksum-PASS status')
        captures=[r for r in packet['candidates'] if r['crate']==component]
        orig=next((r for r in captures if r['path'].endswith('/Cargo.toml.orig')),None)
        vcs_record=next((r for r in captures if r['path'].endswith('/.cargo_vcs_info.json')),None)
        package, capture_state=package_metadata(orig)
        vcs=json.loads(vcs_record['text']) if vcs_record else None
        if vcs_record:
            require(vcs_record['complete_text'], 'complete VCS record required'); compiler.prior.check(vcs_record['text'].encode(),record_pin(vcs_record))
        proof=current.get(component); revision=vcs['git']['sha1'] if vcs else None
        if proof:
            require(orig and orig['complete_text'] and proof['manifest_pin']==record_pin(orig) and proof['commit']==revision, 'current proof must match exact captured manifest/revision')
        requirements={}
        def req(key, unresolved, detail=None, applicable=True):
            requirements[key]={'status':'UNRESOLVED' if unresolved else ('SATISFIED' if applicable else 'NOT_APPLICABLE')}
            if detail is not None: requirements[key]['detail']=detail
        dirty=bool(vcs and vcs['git'].get('dirty') is True)
        generated=component.startswith('ra-ap-rustc_')
        source_hint=re.search(r'repository from commit ([0-9a-f]{40})',package.get('description',''))
        if generated: require(source_hint and source_hint.group(1)=='ce89c898570852a1bb441d77570596e50bf362c2','generated source hint changed')
        req('dirty_source',dirty,applicable=dirty)
        req('publisher_transform',generated,{'declared_Rust_source_commit':source_hint.group(1),'publisher_revision':'UNPROVED'} if generated else None,applicable=generated)
        failure=None
        if component in FAILURES:
            file,ordinal,status=FAILURES[component]; event=json.loads(read(file))['requests'][ordinal-1]
            require(event.get('HTTP')==status,'retained failed identity receipt changed')
            failure={'ledger':file,'ordinal':ordinal,'HTTP':status,'observed_url':event['url']}
        req('source_lineage',vcs is None or failure is not None,{'VCS_present':vcs is not None,'observed_failed_primary':failure,
             'satisfaction_scope':'retained VCS input and no unresolved failed primary route only; canonical repository/manifest correspondence is separate'})
        req('original_manifest',capture_state!='COMPLETE',{'capture_state':capture_state,'expected_complete_pin':record_pin(orig) if orig else None})
        path=vcs.get('path_in_vcs') if vcs else None
        sdk=bool(path and path.startswith('framework-crates/'))
        req('sdk_scope',sdk,{'retained_overview':'../successor-d/evidence/objc-framework-LICENSE.md'} if sdk else None,applicable=sdk)
        inherited=[key for key in ('version','license','repository') if package.get(key)=={'workspace':True}]
        version_proved=bool(proof and proof.get('workspace_version_resolved'))
        pending_inherited=[key for key in inherited if not (version_proved and key in ('version','license'))]
        req('workspace',bool(pending_inherited),{'declared_inherited_values':inherited,'pending_values':pending_inherited,'version_proof_ref':proof['proof_ref'] if version_proved else None},applicable=bool(inherited))
        if not package:
            requirements['workspace']={'status':'DEFERRED','detail':'Original package table unavailable; assess inheritance after source/manifest recovery'}
        req('manifest_git',proof is None,{'proof_ref':proof['proof_ref'] if proof else None})
        req('grant_text',not (proof and proof.get('grant_pin')),{'retained_grant_pin':proof.get('grant_pin') if proof else None,'scope':'retained ancestor text only; all-file/legal acceptance held'})
        req('package_notice',True,{'notice_scope':'actual named project/package notice; source-file-only notices do not discharge this gate'})
        repo,repo_status=candidate_repository(package,proof,component)
        manifest=proof['manifest_path'] if proof else ((path.rstrip('/')+'/' if path else '')+'Cargo.toml' if path is not None else None)
        unresolved=[key for key in PRIORITY if requirements[key]['status']=='UNRESOLVED']
        next_route=unresolved[0]
        blocked=any(requirements[k]['status']=='UNRESOLVED' for k in ('dirty_source','publisher_transform','source_lineage'))
        observed_file=None
        if component=='wasmparser-0.219.2': observed_file={'status':'RETAINED_UPSTREAM_FILE_ONLY','proof_ref':'../report.json#cases/wasmparser-0.219.2/file_scoped_notice'}
        if component=='wasmparser-0.243.0': observed_file={'status':'EXACT_VENDOR_AND_UPSTREAM_FILE_ONLY','proof_ref':'../successor-c/report.json#file_notice'}
        vendor = inventory['vendor_components'][component]
        checksum=vendor['.cargo-checksum.json']['declarations']['package_checksum']
        candidate_refs=[]
        known={
          'anes-0.1.6':['../successor-b/evidence/anes-tree.json'],
          'ui_test-0.30.7':['../successor-b/evidence/ui-test-tree.json'],
          'line-index-0.1.2':['../successor-b/evidence/line-index-root-tree.json'],
          'block2-0.6.2':['../successor-f/evidence/objc-core-root-tree.json','../successor-f/evidence/objc-core-crates-tree.json','../successor-f/evidence/block2-package-tree.json'],
          'objc2-0.6.3':['../successor-f/evidence/objc-core-root-tree.json','../successor-f/evidence/objc-core-crates-tree.json','../successor-f/evidence/objc2-package-tree.json']}
        for ref in known.get(component,[]):
            candidate_refs.append({'path':ref,'pin':inputs['evidence_files'][ref],
                                   'disposition':'reuse offline; original receipt/manifest scope must be checked before promotion'})
        offline_manifest_candidates=[]
        if orig and orig['complete_text']:
            expected_blob=blob(orig['text'].encode())
            for candidate in candidate_refs:
                metadata=json.loads(read(candidate['path']))
                for entry in metadata.get('tree',[]):
                    if entry.get('type')=='blob' and entry.get('sha')==expected_blob and entry['path'].endswith('Cargo.toml'):
                        offline_manifest_candidates.append({'tree_ref':candidate['path'],'entry_path':entry['path'],'git_blob_sha1':expected_blob,
                                                            'status':'CANDIDATE_ONLY_VALIDATE_ORIGINAL_PRIMARY_RECEIPT_AND_SCOPE'})
        if sdk:
            for ref in ['../successor-d/evidence/objc-framework-Cargo.toml','../successor-d/evidence/objc-framework-root-tree.json','../successor-d/evidence/objc-framework-LICENSE.md']:
                candidate_refs.append({'path':ref,'pin':inputs['evidence_files'][ref],
                                       'disposition':'reuse pinned workspace/overview; SDK, package and notice gates remain unresolved'})
        rows.append({'component':component,'selected_for_H':component in selected,'closure_credit':0,
                     'original_metadata':{'manifest_state':capture_state,'manifest_pin':record_pin(orig) if orig else None,'captured_prefix_bytes':orig['captured_bytes'] if orig else None,
                                          'captured_prefix_sha256':orig['captured_prefix_sha256'] if orig else None,'VCS_pin':record_pin(vcs_record) if vcs_record else None,
                                          'declared_revision':revision,'declared_revision_is_40_hex':bool(revision and re.fullmatch('[0-9a-f]{40}',revision)),
                                          'dirty_flag':vcs['git'].get('dirty') if vcs else None,'path_in_vcs':path,'path_in_vcs_present':bool(vcs and 'path_in_vcs' in vcs),'package_table_scope':capture_state,
                                          'expected_original_git_blob_sha1':blob(orig['text'].encode()) if orig and orig['complete_text'] else None},
                     'package_declarations':{k:package.get(k) for k in ('name','version','license','repository')},
                     'retained_normalized_manifest_pin':{k:vendor['Cargo.toml'][k] for k in ('bytes','sha256')},
                     'retained_primary_metadata_candidates':candidate_refs,'offline_manifest_candidates':offline_manifest_candidates,
                     'declared_registry_crate_checksum':checksum,'original_registry_archive_authenticity':'NOT_PROVED',
                     'publisher_metadata_lookup':{'url':'https://crates.io/api/v1/crates/'+urllib.parse.quote(vendor['Cargo.toml']['declarations']['package']['name'],safe='')+'/'+urllib.parse.quote(vendor['Cargo.toml']['declarations']['package']['version'],safe=''),
                                                  'expected_declared_checksum':checksum,'purpose':'exact-version publisher/checksum metadata only; not a grant or source-commit proof','automatic_fetch_recommended':False} if requirements['source_lineage']['status']=='UNRESOLVED' else None,
                     'repository_candidate':{'value':repo,'basis':repo_status},'lock_membership':notes[component]['lock_membership'],
                     'requirements':requirements,'next_route':next_route,'all_unresolved_routes':unresolved,
                     'all_blocking_routes':[k for k in PRIORITY if requirements[k]['status'] in ('UNRESOLVED','DEFERRED')],
                     'ready_manifest_request':metadata_request(repo,revision,manifest,orig,blocked) if requirements['manifest_git']['status']=='UNRESOLVED' and not offline_manifest_candidates else None,'current_file_notice':observed_file,
                     'source_cleanliness_actual_target_activation_all_file_legal_native_M2_release_acceptance':'HELD'})
    groups={key:[r['component'] for r in rows if r['requirements'][key]['status']=='UNRESOLVED'] for key in PRIORITY}
    require(len(rows)==90 and len({r['component'] for r in rows})==90,'routing must cover all 90 cases exactly once')
    # New exact root files are source DATA only; the Servo errors remain errors.
    ledger=json.loads(read('requests.json')); events=ledger['requests']
    require(events[1]['HTTP']==events[2]['HTTP']==404,'preserve exact Servo failed endpoints')
    root_body=read('evidence/fortanix-root-tree.json'); root=json.loads(root_body); require(root.get('truncated') is False,'complete root metadata required')
    url='https://api.github.com/repos/fortanix/rust-sgx/git/trees/adcc6cdb981bcf2101437edbd3ef6144246621d3'
    previous.receipt(events,url,root_body)
    entries={r['path']:r for r in root['tree']}
    for file,path in [('evidence/fortanix-LICENSE','LICENSE'),('evidence/fortanix-README.md','README.md')]:
        body=read(file); require(entries[path]['sha']==blob(body),'new root source Git blob mismatch')
        previous.receipt(events,'https://raw.githubusercontent.com/fortanix/rust-sgx/adcc6cdb981bcf2101437edbd3ef6144246621d3/'+path,body)
    network=network_summary(ledger)
    return {'schema':1,'new_scoped_package_notice_cases_closed':0,'remaining_unresolved':90,'remaining_components':remaining,'selected_components':selected,
            'status_legend':{'SATISFIED':'Only this narrow evidence input is satisfied; no package/legal acceptance','NOT_APPLICABLE':'Specific gate not triggered by retained metadata; no cleanliness/rights inference','UNRESOLVED':'Required input/proof is missing','DEFERRED':'Cannot assess before prerequisite source/manifest recovery'},
            'catalog':CATALOG,'routing_priority':PRIORITY,'routing_groups':groups,'unresolved_requirement_counts':{k:len(v) for k,v in groups.items()},
            'next_route_counts':dict(Counter(r['next_route'] for r in rows)),
            'deferred_requirement_groups':{key:[r['component'] for r in rows if r['requirements'][key]['status']=='DEFERRED'] for key in PRIORITY},'components':rows,
            'retained_cross_cutting_holds':{'object_manifest_correspondence':{'status':'HELD', 'proof_ref':'../successor-c/report.json#object_source_declarations',
               'authenticated_vendor_pin':c['object_source_declarations']['authenticated_vendor_normalized_manifest_pin'],
               'published_source_pin':c['object_source_declarations']['docs_normalized_manifest_pin']},
               'recipe_BUILDINFO_submodule_full_projection_installed_notices_and_target_acceptance':'NOT_CHANGED_OR_CREDITED_BY_THIS_LEDGER'},
            'corrections':[{'component':'hifijson-0.5.0','frozen_prior_label':'39-character revision','correct_value':'40 lowercase hex characters',
                            'impact':'HTTP422/source-identity hold and closure counts unchanged; no revision spelling changed'}],
            'limits':{'no_acquisition_executor':True,'no_external_contact_performed':True,'no_actor_or_shared_manifest_changes':True,
                      'all_existing_source_projection_activation_all_file_legal_native_M2_release_holds':'PRESERVED'},
            'network':network}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--candidate-packet',type=Path,required=True); parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    require(args.output.resolve().is_relative_to(Path('/tmp')),'new output must be below /tmp')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2)); signal.alarm(30)
    result=build(args.candidate_packet)
    with args.output.open('x') as out: json.dump(result,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({k:result[k] for k in ('new_scoped_package_notice_cases_closed','remaining_unresolved','unresolved_requirement_counts','network')}))
