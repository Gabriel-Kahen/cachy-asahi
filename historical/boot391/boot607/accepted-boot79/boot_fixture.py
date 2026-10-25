# SPDX-License-Identifier: MIT
"""Installed CLI controls over explicit synthetic journal/pstore DATA only."""
import hashlib,json,os,shutil,stat
from pathlib import Path
B1,B2='1'*32,'2'*32

def need(value,message):
 if not value:raise ValueError(message)
def pin(path):
 raw=path.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def snapshot(root):
 return {str(p.relative_to(root)):dict(pin=pin(p),mode=stat.S_IMODE(p.stat().st_mode),uid=p.stat().st_uid,mtime_ns=p.stat().st_mtime_ns)for p in root.rglob('*')if p.is_file()and not p.is_symlink()}
def exercise(root,fixture,invoke,label):
 """root is private/caller-owned. invoke(argv, expected=0) executes installed CLI."""
 need(root.is_dir()and stat.S_IMODE(root.stat().st_mode)==0o700,'private fixture root required')
 journal=root/'journal';journal.mkdir(mode=0o700);shutil.copyfile(fixture/'system.journal',journal/'system.journal');(journal/'system.journal').chmod(0o600)
 saved=root/'pstore';saved.mkdir(mode=0o700);(saved/'synthetic-record').write_bytes(b'SYNTHETIC TEST pstore\x00\xff\n');(saved/'synthetic-record').chmod(0o600)
 original=dict(journal=snapshot(journal),pstore=snapshot(saved));checks=[]
 def check(ok,name):need(ok,name);checks.append(name)
 listed=json.loads(invoke(['list','--journal-directory',str(journal)]))
 check(listed['state']=='listed'and {b['boot_id']for b in listed['boots']}=={B1,B2},'exact_two_synthetic_boots')
 output=root/'report';args=['export','--journal-directory',str(journal),'--boot-id',B1,'--output',str(output),'--include-pstore','--pstore-directory',str(saved)]
 invoke(args);report=json.loads((output/'report.json').read_bytes());records=[json.loads(r)for r in(output/'kernel.jsonl').read_bytes().splitlines()]
 expected=json.loads((fixture/'decoded-records.json').read_bytes())[0]
 check(records==[expected],'complete_selected_record_equality_no_other_boot_or_transport')
 check(report['state']=='captured'and report['kernel_journal']['validated_records']==1 and report['kernel_journal']['raw']==pin(output/'kernel.jsonl'),'captured_raw_provenance')
 check(report['history_completeness']=='UNKNOWN'and report['kernel_crash_diagnosis']=='NOT_ESTABLISHED'and report['pstore']['boot_attribution']=='UNKNOWN','no_real_history_crash_or_pstore_attribution')
 check((output/'pstore-0000.bin').read_bytes()==(saved/'synthetic-record').read_bytes(),'exact_synthetic_pstore')
 check(stat.S_IMODE(output.stat().st_mode)==0o700 and all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in output.iterdir()),'private_report_modes')
 before=snapshot(output);invoke(args,expected=1);check(snapshot(output)==before,'no_overwrite_unchanged')
 absent=root/'absent';invoke(['export','--journal-directory',str(journal),'--boot-id','3'*32,'--output',str(absent)],expected=1)
 check(not(absent/'kernel.jsonl').exists()and json.loads((absent/'report.json').read_bytes())['history_completeness']=='UNKNOWN','missing_boot_unknown')
 empty=root/'empty';empty.mkdir(mode=0o700);empty_report=json.loads(invoke(['list','--journal-directory',str(empty)],expected=1));check(empty_report['history_completeness']=='UNKNOWN'and empty_report.get('boots',[])==[],'empty_rotated_history_unknown')
 rotated=root/'rotated';rotated.mkdir(mode=0o700);shutil.copyfile(journal/'system.journal',rotated/'system@synthetic.journal');rotated_report=json.loads(invoke(['list','--journal-directory',str(rotated)]));check({b['boot_id']for b in rotated_report['boots']}=={B1,B2},'explicit_rotated_journal_read')
 denied=root/'denied';denied.mkdir(mode=0o700);shutil.copyfile(journal/'system.journal',denied/'system.journal');(denied/'system.journal').chmod(0)
 failure=json.loads(invoke(['list','--journal-directory',str(denied)],expected=1));check(failure['history_completeness']=='UNKNOWN'and failure.get('boots',[])==[],'unreadable_history_never_inferred');(denied/'system.journal').chmod(0o600)
 alias=root/'alias';alias.symlink_to(journal,target_is_directory=True);invoke(['list','--journal-directory',str(alias)],expected=1)
 invoke(['export','--journal-directory',str(journal),'--boot-id','-1','--output',str(root/'bad-id')],expected=2)
 check(not(root/'bad-id').exists(),'invalid_boot_refused_before_output')
 unsafe=root/'unsafe';unsafe.mkdir(mode=0o777);unsafe.chmod(0o777);invoke(['export','--journal-directory',str(journal),'--boot-id',B1,'--output',str(unsafe/'new')],expected=1);check(not(unsafe/'new').exists(),'unsafe_parent_refused')
 check(original==dict(journal=snapshot(journal),pstore=snapshot(saved)),'all_private_input_bytes_and_metadata_held')
 check(not(root/'must-not-execute').exists(),'hostile_pager_not_executed')
 return dict(status='PASS_INSTALLED_SYNTHETIC_FIXTURE_ONLY',label=label,checks=checks,report_sha256=pin(output/'report.json')['sha256'],report_mode='0600',no_overwrite='PASS',report=report,record=records[0],journal_sha256=pin(fixture/'system.journal')['sha256'],history_completeness='UNKNOWN',kernel_crash_diagnosis='NOT_ESTABLISHED')

def validate(row,journal_sha):
 need(row['status']=='PASS_INSTALLED_SYNTHETIC_FIXTURE_ONLY'and row['journal_sha256']==journal_sha and row['history_completeness']=='UNKNOWN'and row['kernel_crash_diagnosis']=='NOT_ESTABLISHED','fixture scope/journal differs')
 need(row['checks']==['exact_two_synthetic_boots','complete_selected_record_equality_no_other_boot_or_transport','captured_raw_provenance','no_real_history_crash_or_pstore_attribution','exact_synthetic_pstore','private_report_modes','no_overwrite_unchanged','missing_boot_unknown','empty_rotated_history_unknown','explicit_rotated_journal_read','unreadable_history_never_inferred','invalid_boot_refused_before_output','unsafe_parent_refused','all_private_input_bytes_and_metadata_held','hostile_pager_not_executed'],'complete installed fixture controls required')
 need(row['report_mode']=='0600'and row['no_overwrite']=='PASS','report publication guards absent')
 report=row['report'];need(report['state']=='captured'and report['history_completeness']=='UNKNOWN'and report['kernel_crash_diagnosis']=='NOT_ESTABLISHED'and report['pstore']['boot_attribution']=='UNKNOWN'and report['selected_boot_id']==B1,'capture scope changed')

 need(row['report_sha256']==hashlib.sha256((json.dumps(report,sort_keys=True,indent=2)+'\n').encode()).hexdigest(),'full private report hash join differs')
 need(report['kernel_journal']['state']=='complete'and report['kernel_journal']['exit_code']==0 and report['kernel_journal']['child_reaped']is True and report['kernel_journal']['validated_records']==1,'full bounded real child receipt absent')
 need(report['pstore']['state']=='enumerated'and report['pstore']['files'][0]['sha256']==hashlib.sha256(b'SYNTHETIC TEST pstore\x00\xff\n').hexdigest()and len(report['pstore']['files'])==1 and report['pstore']['files'][0]['stable_metadata']is True,'complete synthetic pstore hash/stability absent')
