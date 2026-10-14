# SPDX-License-Identifier: MIT
"""Successor: six commands under explicit waitable-leader custody."""
import hashlib
import json
import math

FLAGS=('-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie',
       '-fno-tree-loop-distribute-patterns','-nostdlib','-static','-Wl,-e,_start,--build-id=none,-z,max-page-size=65536')
OBJECT_FLAGS=('-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie',
              '-fno-tree-loop-distribute-patterns','-c')
PROOFS={'driver_search','header_include','loader','no_exec_privilege','containment','native_providers','runtime','Source_review'}
ORDER=('compile-shim','compile-abi','readelf-shim','objdump-shim','readelf-abi','objdump-abi')

class Refused(ValueError):
    pass

def need(value,code):
    if not value:raise Refused(code)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def sha(value):
    return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)

def frame(entry,outer_work_end,outer_cleanup_end):
    need(all(type(v) in (int,float) and math.isfinite(v) for v in (entry,outer_work_end,outer_cleanup_end))
         and entry>=0 and entry<outer_work_end<outer_cleanup_end,'original-outer-frame')
    work,cleanup=min(entry+120,outer_work_end),min(entry+130,outer_cleanup_end)
    need(work<cleanup,'reserved-cleanup-frame');return work,cleanup

def selected(observation,selection,expected_sha,manifest_sha,admission,expected_admission):
    """Root selects the complete accepted envelope, proofs and opaque grant.

    The unchanged Root reobserve factory must validate the full retained schema
    before constructing workspace/runner; hashes alone issue no authority.
    """
    need(type(admission) is object and admission is expected_admission,'Root-compile-grant')
    need(sha(expected_sha) and digest(canonical(selection))==expected_sha,'external-Root-selection')
    keys={'schema_version','purpose','observation_sha256','source_manifest_sha256',
          'gcc_directory','gcc_discovery','helper_discovery','roles','files','headers','inventories',
          'provenance','observer_gate_receipt_sha256','proofs','environment'}
    need(type(selection) is dict and set(selection)==keys,'selection-shape')
    need(type(selection['schema_version']) is int and selection['schema_version']==1
         and selection['purpose']=='ROOT_SELECTED_SIGNER_COMPILE_TOOLCHAIN_V1'
         and sha(manifest_sha) and selection['source_manifest_sha256']==manifest_sha,'selection-source-scope')
    okeys={'schema_version','purpose','source_pins','configuration','context','observation','provenance',
           'entry','deadline_at','selected','execution_grant_issued','compile_allowed'}
    raw=canonical(observation)
    need(type(observation) is dict and set(observation)==okeys and len(raw)<=4*1024**2
         and type(observation['schema_version']) is int and observation['schema_version']==1
         and observation['purpose']=='SIGNER_NATIVE_PASSIVE_ADOPTION_V1'
         and all(observation[k] is False for k in ('selected','execution_grant_issued','compile_allowed'))
         and selection['observation_sha256']==digest(raw)
         and sha(selection['observer_gate_receipt_sha256']),'complete-accepted-envelope-binding')
    inner=observation['observation']
    need(type(inner) is dict and set(inner)=={'candidate','evidence'},'complete-observation-binding')
    candidate=inner['candidate'];evidence=inner['evidence']
    need(type(candidate) is dict and set(candidate)=={'schema_version','purpose','gcc_directory',
         'gcc_discovery','helper_discovery','roles','files','headers','inventories','selected','execution_grant_issued'}
         and type(candidate['schema_version']) is int and candidate['schema_version']==1
         and candidate['purpose']=='NATIVE_SIGNER_COMPILE_TOOLCHAIN_CANDIDATE_V1'
         and candidate['selected'] is False and candidate['execution_grant_issued'] is False,'passive-not-selected')
    need(evidence['context']['machine']=='aarch64'
         and evidence['context']['source_commit']==evidence['context']['workflow_commit']
         and canonical(evidence['context'])==canonical(observation['context']),'native-observation-context')
    need(all(canonical(selection[k])==canonical(candidate[k]) for k in
         ('gcc_directory','gcc_discovery','helper_discovery','roles','files','headers','inventories'))
         and canonical(selection['provenance'])==canonical(observation['provenance']),'selected-complete-envelope-rows')
    need(type(selection['proofs']) is dict and set(selection['proofs'])==PROOFS
         and all(sha(v) for v in selection['proofs'].values()),'Root-independent-correspondence-required')
    required=('gcc','cc1','cc1plus','as','ld','readelf','objdump','python_candidate')
    need(type(selection['roles']) is dict and all(type(selection['roles'].get(k)) is str for k in required),
         'required-selected-tool-roles')
    need(type(selection['files']) is dict and 1<=len(selection['files'])<=4096
         and type(selection['headers']) is list and 0<len(selection['headers'])<=4096
         and len(selection['headers'])==len(set(selection['headers']))
         and type(selection['inventories']) is dict and selection['inventories'],'complete-selected-file-header-set')
    for path,row in selection['files'].items():
        need(type(path) is str and path.startswith('/') and '\0' not in path
             and '..' not in path.split('/') and type(row) is dict and set(row)=={'bytes','mode','sha256','kind'}
             and type(row['bytes']) is int and 0<row['bytes']<=64*1024**2 and sha(row['sha256'])
             and type(row['mode']) is int and row['mode'] in (0o644,0o755)
             and row['kind'] in ('ELF','HEADER','DATA'),'selected-file-row')
    for role in required:
        path=selection['roles'][role]
        need(path in selection['files'] and selection['files'][path]['kind']=='ELF'
             and selection['files'][path]['mode']==0o755,'selected-role-file-binding')
    need(all(name in selection['files'] and selection['files'][name]['kind']=='HEADER'
             for name in selection['headers']),'selected-header-file-binding')
    need(type(selection['environment']) is dict and set(selection['environment'])=={'LANG','LC_ALL','PATH','TMPDIR'}
         and selection['environment']['LANG']==selection['environment']['LC_ALL']=='C'
         and all(type(v) is str and v and '\0' not in v for v in selection['environment'].values()),'selected-exact-environment')
    return selection


def command_argv(workspace,selection):
    ip=lambda n:workspace.path('inputs',n)
    op=lambda n:workspace.path('outputs',n)
    gcc,readelf,objdump=(selection['roles'][n] for n in ('gcc','readelf','objdump'))
    return {
        'compile-shim':(gcc,*FLAGS,ip('witness_shim.c'),'-o',op('witness-shim')),
        'compile-abi':(gcc,*OBJECT_FLAGS,ip('abi_layout.c'),'-o',op('abi-layout.o')),
        'readelf-shim':(readelf,'-W','-h','-l','-S','-s',op('witness-shim')),
        'objdump-shim':(objdump,'-d','-r',op('witness-shim')),
        'readelf-abi':(readelf,'-W','-h','-S','-x','.witness_abi',op('abi-layout.o')),
        'objdump-abi':(objdump,'-s','-j','.witness_abi',op('abi-layout.o'))}

def command_binding(table):
    """Private immutable expected rows, retained locally; never serialized."""
    need(tuple(table)==ORDER,'fixed-command-order')
    return tuple((name,tuple(sorted(table[name].items()))) for name in ORDER)

def commands(workspace,selection,sample):
    """Create held fixed-command rows; never dispatch or accept an arbitrary argv."""
    need(selection['environment']['TMPDIR']==workspace.paths['outputs'],
         'selected-TMPDIR-owned-output-directory')
    programs={}
    for role in ('gcc','readelf','objdump'):
        path=selection['roles'][role];row=selection['files'][path]
        need(row['kind']=='ELF','selected-native-ELF-tool')
        programs[role]=(*workspace.tool(path,row,sample),row['sha256'])
    workspace.absent_output('witness-shim');workspace.absent_output('abi-layout.o')
    argv=command_argv(workspace,selection)
    table={}
    for name in ORDER:
        role='gcc' if name.startswith('compile') else name.split('-',1)[0]
        fd,ident,sha256=programs[role]
        stdout,stdout_id=workspace.capture(name+'.out');stderr,stderr_id=workspace.capture(name+'.err')
        cwd=workspace.directories['outputs']
        table[name]=dict(argv=argv[name],executable_fd=fd,executable_identity=ident,executable_sha256=sha256,
            cwd_fd=cwd,cwd_identity=workspace.owned[cwd],stdout_fd=stdout,stdout_identity=stdout_id,
            stderr_fd=stderr,stderr_identity=stderr_id,output_limit=4*1024**2)
    need(workspace.command_binding is None,'command-binding-once')
    workspace.command_binding=command_binding(table)
    return dict(environment=dict(selection['environment']),commands=table)

def execute(*,workspace,runner,selection,sources,source_rows,inspect_outputs,reobserve,
            cancel,cancel_types,work_end,cleanup_end):
    """Root constructs these exact Source-admitted objects after selected() succeeds.

    runner is OwnedCommands with commands()'s exact held table and Root's actual
    containment/provider grant. reobserve covers ALL selected tools/header trees,
    aliases, negatives and libraries, not only the three direct command binaries.
    """
    result=dict(status='FAIL',first_cause=None,cancelled=False,uncertain=False,commands=[],
                outputs={},inspection=None,owned_FDs_retired=False,scope_retired=False,
                shim_executed=False,ABI_helper_executed=False,GPG_executed=False,
                kernel_handler_proved=False,loader_runtime_proved=False,full_signer_API_acceptance=False)
    def failure(error):
        if result['first_cause'] is None:
            result['first_cause']='CANCELLED' if isinstance(error,cancel_types) else 'LANE_REFUSED'
        result['cancelled']|=isinstance(error,cancel_types)
    try:
        need(workspace.work_end==runner.work_end==work_end and workspace.cleanup_end==runner.cleanup_end==cleanup_end,
             'shared-original-frame')
        need(tuple(runner.tools['commands'])==ORDER,'six-selected-commands')
        need(type(workspace.command_binding) is tuple
             and command_binding(runner.tools['commands'])==workspace.command_binding,'held-command-table-binding')
        need(runner.tools['environment']==selection['environment'],'selected-runner-environment')
        for name,argv in command_argv(workspace,selection).items():
            row=runner.tools['commands'][name]
            role='gcc' if name.startswith('compile') else name.split('-',1)[0]
            need(row['argv']==argv and row['executable_sha256']==selection['files'][selection['roles'][role]]['sha256'],
                 'fixed-command-body-and-tool-pin')
        need(set(sources)==set(source_rows)=={'witness_shim.c','exec_filter.inc','thread_filter.inc','abi_layout.c'},
             'closed-compile-inputs')
        for name,raw in sources.items():
            row=source_rows[name]
            need(type(raw) is bytes and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'source-byte-pin')
            workspace.put_source(name,raw)
        for name in ORDER:
            workspace.guard(work_end);cancel()
            need(reobserve(selection,work_end) is True,'fresh-full-toolchain-reobservation')
            outcome=runner.run(name)
            if outcome['first_cause'] is not None:
                result['first_cause']=result['first_cause'] or outcome['first_cause']
            result['cancelled']|=outcome['cancelled'];result['uncertain']|=outcome['uncertain']
            result['commands'].append(dict(name=name,natural_returncode=outcome['natural_returncode'],
                stdout_sha256=digest(outcome['stdout']),stderr_sha256=digest(outcome['stderr']),
                descendants_absent=outcome['descendants_absent']))
            if outcome['first_cause']=='work:REFUSED':
                result['commands'][-1]['work_refusal']=outcome['work_refusal']
            need(outcome['status']=='PASS_NATURAL_ZERO_OWNED_ABSENCE_BYTES_ONLY' and outcome['natural_returncode']==0
                 and outcome['reaped_returncode']==0 and outcome['child_reaped'] is True
                 and outcome['descendants_absent'] is True
                 and outcome['ownership_kind']=='WAITABLE_LEADER'
                 and outcome['leader_reaped'] is True and outcome['leader_custody_retired'] is True
                 and not outcome['uncertain'] and not outcome['cancelled'] and outcome['first_cause'] is None,
                 'natural-zero-owned-command-required')
            workspace.guard(work_end)
        need(reobserve(selection,work_end) is True,'final-full-toolchain-reobservation')
        shim,shim_row=workspace.output('witness-shim',16*1024**2)
        abi,abi_row=workspace.output('abi-layout.o',16*1024**2)
        captures={name:workspace.read_fd(row['stdout_fd'],4*1024**2,work_end)
                  for name,row in runner.tools['commands'].items()}
        result['inspection']=inspect_outputs(shim,abi,shim_disassembly=captures['objdump-shim'],
            shim_readelf=captures['readelf-shim'],abi_disassembly=captures['objdump-abi'],abi_readelf=captures['readelf-abi'])
        workspace.guard(work_end);cancel()
        result['outputs']=dict(shim=shim_row,ABI_object=abi_row)
        result['status']='PASS_STATIC_COMPILE_AND_METADATA_ONLY'
    except BaseException as error:failure(error)
    finally:
        try:
            closed=runner.close()
            if closed['first_cause'] is not None:result['first_cause']=result['first_cause'] or closed['first_cause']
            result['cancelled']|=closed['cancelled'];result['uncertain']|=closed['uncertain']
            result['scope_retired']=(closed['status']=='PASS_OWNED_SCOPE_CLOSED_ONLY'
                and closed['ownership_kind']=='WAITABLE_LEADER'
                and all(closed[k] is True for k in ('descendants_absent','leader_reaped','leader_custody_retired'))
                and not closed['cancelled'] and not closed['uncertain'] and closed['first_cause'] is None)
            need(result['scope_retired'],'scope-retirement-uncertain')
        except BaseException as error:result['uncertain']=True;failure(error)
        try:
            result['owned_FDs_retired']=workspace.retire() is True
            need(result['owned_FDs_retired'],'owned-FD-retirement-uncertain')
        except BaseException as error:result['uncertain']=True;failure(error)
        try:cancel()
        except BaseException as error:failure(error)
        result['cancelled']|=workspace.cancelled
        if result['first_cause'] is not None or result['cancelled'] or result['uncertain']:
            result['status']='FAIL'
    return result
