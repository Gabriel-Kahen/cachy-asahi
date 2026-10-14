# SPDX-License-Identifier: MIT
"""Pure fixed-scope correspondence records; trusted entry supplies actual checks.

Digests are data, never permission objects. Root separately chooses the literal
trusted runtime/entry, performs checks under its original frame, and issues its
own opaque objects. No native operations or compiler search query occurs here.
"""
import hashlib
import json
from pathlib import Path
import re

POLICY={'accepted_outer_sha256': '22ab60121191de19244a832eed139a5ba7a1bfef9d4f959f6159d1450603f4e4', 'baseline_code_rows': {'bootstrap.py': {'bytes': 21103, 'mode': 420, 'sha256': '9009e5bfa2fc94b3bc8e7b3d8af590e0e76bd4924371a469ff47bab9ae462537'}, 'native_workspace.py': {'bytes': 11033, 'mode': 420, 'sha256': '1f9667ba10006eb1d010c5e69e50b3e950d12f05baaa22600e0f4804a801ea96'}}, 'baseline_commit': '1e8fd873345c02dd2f678d8e143c8e22fe7a6e84', 'code_names': ['bootstrap.py', 'native_workspace.py', 'trusted_entry.py', 'correspondence.py'], 'environment': {'LANG': 'C', 'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'workspace_base': '/var/tmp/cachy-asahi-test-signer-compile'}, 'gate_receipt_sha256': '9f46925bf72bcdf86c33d706c7d3110f1de41b59f702754eff6e09b2e1afab90', 'group_premises': ['trusted_fixed_compiler_and_helper_call_paths', 'no_group_or_session_escape', 'no_late_spawn_after_terminal_empty', 'complete_same_namespace_proc_visibility', 'single_owner_no_competing_reaper', 'selected_runtime_public_SIGCHLD_waitability', 'blocking_call_latency_and_partial_birth_uncertainty_accepted', 'Root_loaded_Source_and_helper_no_exec_privilege_verified'], 'object_flags': ['-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pie', '-fno-tree-loop-distribute-patterns', '-c'], 'order': ['compile-shim', 'compile-abi', 'readelf-shim', 'objdump-shim', 'readelf-abi', 'objdump-abi'], 'purpose': 'ROOT_SELECTED_FIRST_STATIC_COMPILE_POLICY_V1', 'runtime': {'child_gid': 1001, 'child_uid': 1001, 'implementation': 'cpython', 'machine': 'aarch64', 'parent_gid': 0, 'parent_uid': 0, 'platform': 'trusted GitHub ubuntu-24.04-arm', 'python': [3, 12], 'sysname': 'Linux'}, 'schema_version': 1, 'scope': {'GPG': False, 'artifact_execution': False, 'cleanup_seconds': 130, 'commands': 6, 'hardware': False, 'installation': False, 'private_cgroup_required': False, 'probe': False, 'reobservations': 7, 'signing': False, 'work_seconds': 120}, 'shim_flags': ['-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pie', '-no-pie', '-fno-tree-loop-distribute-patterns', '-nostdlib', '-static', '-Wl,-e,_start,--build-id=none,-z,max-page-size=65536'], 'source13_commit': '1e8fd873345c02dd2f678d8e143c8e22fe7a6e84', 'source_manifest_sha256': 'c9e7bb8f8d2d876ec0cafe93fe855f9d864fcb264417e2396d13ce54e7637058', 'source_prefix': 'scripts/ci/test-signer-compile-v2', 'source_rows': {'abi_layout.c': {'bytes': 22615, 'mode': 420, 'sha256': '278432c15fd759707986f90b1e5e08c19a934c849ef3368ddcdf1141031294a6'}, 'compile_lane_v2.py': {'bytes': 14816, 'mode': 420, 'sha256': '13c06d5a1b2316f517cca74c2ffaf568c3051268256a1cf659f7e990bcdfeae4'}, 'exec_filter.inc': {'bytes': 735, 'mode': 420, 'sha256': '0e26f261f2f9d1c9eb2de15fa70eb3a6c4158c3eaab5bb9f330ceb8dd32bdc19'}, 'group_process_v2.py': {'bytes': 19256, 'mode': 420, 'sha256': 'a8c9044e13f16ead4ed0271b4448f0ec0e3be8a891de66f23a836245ac0bfffb'}, 'guardian.py': {'bytes': 23775, 'mode': 420, 'sha256': 'f2a832f3e01c59a2fd61907301818cb85dc511828f0ea40b416ecb3c66ef4446'}, 'inspection.py': {'bytes': 11897, 'mode': 420, 'sha256': '9658a91a003e17b3f3606b5b1ea03af279a5390e6b02c377fed2ea8dd458159a'}, 'observation_entry.py': {'bytes': 12522, 'mode': 420, 'sha256': '540db1ab5a877fd2486673e86d2a1216c036dd9d8bec3953f44f467ee4966071'}, 'passive.py': {'bytes': 40917, 'mode': 420, 'sha256': 'b844e94ae9cf69882550526a93aed3606398e9252175472be0bf6f2888eba1c9'}, 'reobserve.py': {'bytes': 42040, 'mode': 420, 'sha256': '045620837bb30cdfa719a4e45e216b3aeec389b7fc7da3c08ed86db81e44bdc7'}, 'root_entry.py': {'bytes': 5930, 'mode': 420, 'sha256': '24467b0cc3fc0bbbdee45e5e4905cc4a1e51484712b219c92d2ed555b0774299'}, 'thread_filter.inc': {'bytes': 828, 'mode': 420, 'sha256': '0811954954a107744eaef4592d2be070e30312ed5dbbae716acf6c65e83039ed'}, 'witness_shim.c': {'bytes': 6826, 'mode': 420, 'sha256': 'f5ad7cc5d6247bfa673226c842ee9795a4619f6adfd6062b9edfd0b5872af537'}, 'workspace.py': {'bytes': 8724, 'mode': 420, 'sha256': '8fe059b38492ef56c25d34157774db56087b86e265fb7c64a9ae8dc15ae305f8'}}, 'trust': {'compiler_search_queried': False, 'fixed_selected_GCC_helper_chain': True, 'metadata_driver_include_loader_correspondence_sufficient_for_first_compile': True, 'ordinary_selected_host_runtime': True, 'universal_executed_bytes_or_kernel_proof': False}, 'workflow': '.github/workflows/native-arm-runner-observation.yml'}
ROLES=('Source_review','runtime','native_providers','containment','no_exec_privilege','driver_search','header_include','loader')
class Refused(ValueError):pass
def need(value,code):
    if not value:raise Refused(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def sha(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def row(value):
    return (type(value) is dict and set(value)=={'bytes','mode','sha256'} and type(value['bytes']) is int and
        0<value['bytes']<=64*1024**2 and type(value['mode']) is int and value['mode'] in (0o644,0o755) and sha(value['sha256']))

def generate(*,outer,gate_receipt_sha256,source_rows,code_rows,checks,environment,context):
    need(type(outer) is dict and digest(outer)==POLICY['accepted_outer_sha256'] and
         all(outer[k] is False for k in ('selected','execution_grant_issued','compile_allowed')),'exact-accepted-outer')
    need(gate_receipt_sha256==POLICY['gate_receipt_sha256'],'exact-Root-gate-receipt')
    need(source_rows==POLICY['source_rows'] and len(source_rows)==13,'exact-Source13-rows')
    need(type(code_rows) is dict and set(code_rows)==set(POLICY['code_names']) and
         all(row(v) and v['mode']==0o644 for v in code_rows.values()),'Root-checked-stage-code-rows')
    need(all(code_rows[k]==v for k,v in POLICY['baseline_code_rows'].items()),'exact-baseline-helper-rows')
    need(type(context) is dict and set(context)=={'source13_commit','baseline_commit','workflow_source_commit','manual_expected_commit'}
         and context['source13_commit']==POLICY['source13_commit'] and context['baseline_commit']==POLICY['baseline_commit']
         and type(context['workflow_source_commit']) is str and re.fullmatch('[0-9a-f]{40}',context['workflow_source_commit'])
         and context['workflow_source_commit']==context['manual_expected_commit'],'three-level-Source-context')
    need(type(environment) is dict and set(environment)=={'LANG','LC_ALL','PATH','TMPDIR'} and
         all(environment[k]==POLICY['environment'][k] for k in ('LANG','LC_ALL','PATH')),'fixed-compile-environment')
    tmp=environment['TMPDIR'];base=POLICY['environment']['workspace_base']
    need(type(tmp) is str and str(Path(tmp))==tmp and re.fullmatch(re.escape(base)+r'/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}/outputs',tmp),
         'fixed-owned-output-TMPDIR')
    need(type(checks) is dict and set(checks)=={'runtime','no_exec_privilege','custody'},'closed-fresh-check-records')
    runtime=checks['runtime'];expected=outer['provenance']['python']
    runtime_keys={'sysname','machine','python_version_info','python_executable','row','parent_uid','parent_gid','child_uid','child_gid','python_flags','implementation_name'}
    need(type(runtime) is dict and set(runtime)==runtime_keys and runtime['sysname']=='Linux' and runtime['machine']=='aarch64'
         and runtime['implementation_name']=='cpython' and runtime['python_version_info']==expected['version_info'][:3]
         and type(runtime['python_version_info']) is list and all(type(v) is int for v in runtime['python_version_info']),
         'fresh-selected-Python-platform-version')
    need(runtime['python_executable']==expected['executable_file']['canonical'] and
         runtime['row']==expected['executable_file']['row'],'fresh-Python-ELF-content-mismatch')
    for key,value in (('parent_uid',0),('parent_gid',0),('child_uid',1001),('child_gid',1001)):
        need(type(runtime[key]) is int and runtime[key]==value,'fixed-Root-child-credentials')
    need(runtime['python_flags']=={'isolated':1,'no_site':1,'dont_write_bytecode':1,'optimize':0} and
         type(runtime['python_flags']) is dict and all(type(v) is int for v in runtime['python_flags'].values()),
         'selected-isolated-Python-flags')
    c=outer['observation']['candidate'];e=outer['observation']['evidence']
    privilege=checks['no_exec_privilege']
    need(type(privilege) is dict and set(privilege)=={'checked_files','complete'} and privilege['complete'] is True,
         'complete-actual-privilege-check-record')
    elf={name:{k:v for k,v in r.items() if k!='kind'} for name,r in c['files'].items() if r['kind']=='ELF'}
    need(type(privilege['checked_files']) is dict and set(privilege['checked_files'])==set(elf),'all-ELF-privilege-check-coverage')
    for name,value in privilege['checked_files'].items():
        need(type(value) is dict and set(value)=={'row','uid','gid','nlink','mode','filecap_present','setid_present'}
             and value['row']==elf[name] and all(type(value[k]) is int for k in ('uid','gid','nlink','mode'))
             and value['uid']==value['gid']==0 and value['nlink']==1 and value['mode']==elf[name]['mode']
             and value['filecap_present'] is False and value['setid_present'] is False,'actual-filecap-setid-owner-check')
    custody=checks['custody']
    need(type(custody) is dict and set(custody)=={'workspace_held_named','base_root_protected','child_traversal','selected_premises'}
         and all(custody[k] is True for k in ('workspace_held_named','base_root_protected','child_traversal')),
         'actual-workspace-check-record')
    need(type(custody['selected_premises']) is dict and set(custody['selected_premises'])==set(POLICY['group_premises'])
         and all(v is True for v in custody['selected_premises'].values()),'Root-selected-narrow-custody-premises')
    common=dict(schema_version=1,purpose='ROOT_FIRST_STATIC_COMPILE_CORRESPONDENCE_V1',policy_sha256=digest(POLICY),
        source_manifest_sha256=POLICY['source_manifest_sha256'],accepted_outer_sha256=POLICY['accepted_outer_sha256'],
        observer_gate_receipt_sha256=gate_receipt_sha256,context=context,source_rows_sha256=digest(source_rows),
        code_rows_sha256=digest(code_rows),command_scope=dict(order=POLICY['order'],shim_flags=POLICY['shim_flags'],
            object_flags=POLICY['object_flags'],environment=environment,limits=POLICY['scope']),
        record_origin='ROOT_SELECTED_TRUSTED_ENTRY_CHECKS_AND_EXPLICIT_POLICY',permission_objects_issued=False,
        universal_executed_bytes_or_kernel_proof=False)
    facts={
        'Source_review':dict(checked_Source13=source_rows,checked_stage_code=code_rows),
        'runtime':dict(fresh_runtime=runtime,observed_reference_sha256=digest(expected)),
        'native_providers':dict(actual_parent_uid=runtime['parent_uid'],actual_parent_gid=runtime['parent_gid'],
            checked_workspace_flags={k:custody[k] for k in ('workspace_held_named','base_root_protected','child_traversal')}),
        'containment':dict(checked_workspace_flags={k:custody[k] for k in ('workspace_held_named','base_root_protected','child_traversal')},
            group_absence_observed=False),
        'no_exec_privilege':privilege,
        'driver_search':dict(gcc_directory=c['gcc_directory'],gcc_discovery_sha256=digest(c['gcc_discovery']),
            helper_discovery_sha256=digest(c['helper_discovery']),roles=c['roles'],requests_sha256=digest(e['requests']),
            compiler_search_queried=False),
        'header_include':dict(headers_sha256=digest(c['headers']),header_rows_sha256=digest({n:c['files'][n] for n in c['headers']}),
            inventories_sha256=digest(c['inventories']),actual_include_trace_observed=False),
        'loader':dict(declarations_sha256=digest({n:v for n,v in e['observations'].items() if c['files'][n]['kind']=='ELF'}),
            loaded_library_execution_observed=False)}
    trust={
        'Source_review':{'Root_selected_loaded_Source_and_callback_binding':True},
        'runtime':{'ordinary_selected_GitHub_Ubuntu_ARM_Python312_Linux_runtime':True},
        'native_providers':{'selected_stdlib_OS_subprocess_signal_resource_and_pinned_guardian':True},
        'containment':custody['selected_premises'],
        'no_exec_privilege':{'fresh_read_checks_plus_Root_selected_helper_no_privilege_behavior':True},
        'driver_search':{'metadata_correspondence_and_trusted_fixed_GCC_helper_chain':True},
        'header_include':{'metadata_correspondence_for_fixed_two_inputs_and_flags':True},
        'loader':{'ELF_declarations_plus_ordinary_selected_host_loader_trust':True}}
    records={role:{**common,'proof_role':role,'facts':facts[role],'selected_trust_premises':trust[role]} for role in ROLES}
    need(len(canonical(records))<=256*1024,'bounded-eight-correspondence-records')
    return dict(records=records,proofs={role:digest(record) for role,record in records.items()},records_sha256=digest(records),
                selected=False,execution_grant_issued=False,compile_allowed=False)
