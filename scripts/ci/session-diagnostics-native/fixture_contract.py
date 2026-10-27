# SPDX-License-Identifier: MIT
"""Finite installed diagnostic fixture and five-transition contract."""
from pathlib import Path
import re


def need(ok,message):
    if not ok:raise ValueError(message)


def validate_fixture(value,architecture,page_size):
    need(value.get('status')=='PASS_SESSION_DIAGNOSTICS_HEADLESS_CONTROLS' and
         value.get('architecture')==architecture and value.get('page_size')==page_size and
         type(value.get('uid')) is int and value['uid']>0 and value.get('actual_cli_headless') is True and
         value.get('installed_payload_preserved') is True and value.get('unrelated_cwd') is True and
         value.get('hostile_python_environment_ignored') is True and value.get('physical')=='NOT_RUN' and
         value.get('service_queries')=='NONE' and value.get('performance')=='NOT_MEASURED',
         'complete ordinary-user installed headless fixture required')
    head=value.get('headless_checks',{})
    need(head.get('status')=='PASS_HEADLESS_ENDPOINT_ABSENCE' and head.get('unavailable_endpoint_checks')==12 and
         head.get('compositor_renderer')=='UNKNOWN' and head.get('speaker_protection')=='NOT TESTED' and
         head.get('physical')=='NOT_RUN','unavailable endpoints and explicit unknowns required')
    missing=value.get('missing_tool_control',{})
    need(missing.get('status')=='PASS_REAL_EXEC_ABSENCE' and missing.get('service_queries')=='NONE' and
         missing.get('scope')=='INJECTED_ENDPOINT_CONTEXT_AND_PRIVATE_EXECUTABLE_MAPPING' and
         len(missing.get('calls',[]))==12 and all(row.get('reason')=='command-absent' for row in missing['calls']) and
         set(missing.get('report',{}).get('physical_checks',{}).values())=={'NOT RUN'},
         'explicit private absent-tool control required')
    tamper=value.get('tamper_refusal',{})
    events=tamper.get('events',[])
    need(tamper.get('status')=='PASS_PRIVATE_TAMPER_REFUSAL' and tamper.get('installed_runtime_modified') is False and
         tamper.get('restored_help_exit')==0 and len(events)==4 and
         [row.get('case') for row in events]==['changed','missing','oversized','symlink'] and
         all(row.get('returncode')==2 and row.get('stdout_bytes')==0 and row.get('refusal_before_probe') is True for row in events),
         'all four private integrity refusals required')
    owned=value.get('owned_process_cleanup',{})
    process=owned.get('events',[])
    need(owned.get('status')=='PASS_OWNED_INSTALLED_RUNTIME_CHILDREN' and
         owned.get('all_owned_children_reaped') is True and owned.get('subreaper_scope')=='THIS_FIXTURE_PROCESS_ONLY' and
         len(process)==3 and process[0]==dict(case='natural',reason='observed',returncode=0) and
         process[1]==dict(case='leader-exit-inherited-pipe',reason='timeout',returncode=0,
                         leader_absent=True,descendant_reaped=True,descendant_exit=-9) and
         process[2]==dict(case='SIGCHLD-ignored',reason='reaping-policy-incompatible',returncode=None,launch='SKIPPED'),
         'natural, inherited-pipe and incompatible-policy cleanup required')
    public=value.get('public_evidence',{})
    required={'help.stdout','help.stderr','headless.stdout','headless.stderr','missing-tool-control.json',
              'owned-process-control.json','commands.json'}|{label+suffix for label in
              ('tamper-changed','tamper-missing','tamper-oversized','tamper-symlink','tamper-restored')
              for suffix in ('.stdout','.stderr')}
    need(type(public) is dict and set(public)==required and sum(row['bytes'] for row in public.values())<=16*1024**2,
         'exact raw fixture output closure required')
    for name,row in public.items():
        need(Path(name).name==name and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and
             0<=row['bytes']<=2*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'bounded raw fixture output pin required')
    need(value.get('actual_cli_report')==dict(path='headless.stdout',**public['headless.stdout']) and
         public['headless.stdout']['bytes']>0 and public['headless.stderr']['bytes']==0,
         'raw actual headless CLI report join required')


def validate_lifecycle(value):
    need(value.get('status')=='PASS_SESSION_DIAGNOSTICS_INSTALLED_LIFECYCLE' and
         value.get('base_count')==574 and value.get('installed_count')==575 and
         value.get('user_config_preserved') is True and value.get('system_config_preserved') is True and
         value.get('user_outputs_preserved') is True and value.get('user_reports_preserved') is True and
         value.get('owned_process_cleanup')=='PASS_ALL_FIXTURES' and value.get('service_queries')=='NONE' and
         value.get('hardware')=='NOT_RUN' and value.get('native_architecture')=='aarch64' and
         type(value.get('actual_page_size')) is int and value['actual_page_size']>0 and
         value.get('trust')=='PRIVATE_ACTUAL_TIME_TEST_KEYRING_ONLY' and value.get('network')=='NONE',
         'complete installed session diagnostics lifecycle required')
    def users(rows):
        need(type(rows) is list and len(rows)==2 and {r.get('home') for r in rows}=={
             'session-diagnostics-home-fresh','session-diagnostics-home-existing'} and
             len({r.get('uid') for r in rows})==2,'both distinct ordinary user contexts required')
        for row in rows:
            proof=row.get('session_diagnostics',{})
            need(row.get('uid')==proof.get('uid') and type(row.get('account')) is str,'ordinary user proof join required')
            validate_fixture(proof,'aarch64',value['actual_page_size'])
    users(value.get('staged_observations'))
    events=value.get('events')
    need(type(events) is list and len(events)==5,'five lifecycle transitions required')
    for event,(phase,count) in zip(events,(('install',575),('same-version-reinstall',575),('remove',574),
                                        ('reinstall-after-removal',575),('final-remove',574))):
        need(event.get('phase')==phase and event.get('status')=='PASS' and event.get('inventory_count')==count and
             event.get('config_preserved') is True,'lifecycle transition differs')
        if count==575:users(event.get('observations'))
        else:need(event.get('removed_payload_absent') is True,'removed payload absence required')
    signing=value.get('package_test_signing',{})
    need(signing.get('private_key_removed') is True and signing.get('signature_verified_at_actual_time') is True and
         signing.get('actual_time_signature_verified') is True and signing.get('fake_signature_time_used') is False and
         signing.get('alpm_local_signature_policy')=='Required' and signing.get('production_trust')=='UNTOUCHED' and
         re.fullmatch('[0-9A-F]{40}',signing.get('fingerprint','')) and
         type(signing.get('created_epoch')) is int and type(signing.get('verified_epoch')) is int and
         signing['created_epoch']<=signing['verified_epoch'],'fresh actual-time TEST signature and private-key cleanup required')
    for key in ('archive_sha256','signature_sha256'):
        need(re.fullmatch('[0-9a-f]{64}',signing.get(key,'')),'signed archive/signature pin required')
    need(re.fullmatch('[0-9a-f]{64}',value.get('fixture_evidence_manifest_sha256','')),
         'raw public fixture evidence manifest required')
