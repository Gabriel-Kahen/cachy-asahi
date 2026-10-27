# SPDX-License-Identifier: MIT
"""Finite TEST signature, actual-job clock and public-only signer receipt gates."""
import datetime,hashlib,re
BAD={'BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','KEYREVOKED','SIGEXPIRED','NODATA','BADARMOR','FAILURE','ERROR'}

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def whole(value,cap=8*1024**2,empty=False):
 return type(value)is dict and set(value)=={'bytes','sha256'} and type(value['bytes'])is int and (0 if empty else 1)<=value['bytes']<=cap and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None and (value['bytes']>0 or value['sha256']==hashlib.sha256(b'').hexdigest())

def job_scope(job):
 need(type(job)is dict and set(job)=={'source_sha','run_id','run_attempt','proof_issued_epoch','consumer_token'},'closed actual signing job context required')
 need(type(job['source_sha'])is str and re.fullmatch('[0-9a-f]{40}',job['source_sha']) and type(job['run_id'])is str and re.fullmatch('[1-9][0-9]{0,19}',job['run_id']) and job['run_attempt']=='1' and type(job['proof_issued_epoch'])is int and job['proof_issued_epoch']>0,'typed actual job/source/attempt/time required')
 expected=hashlib.sha256(('mirrors-consumer:'+job['run_id']+':'+job['run_attempt']+':'+job['source_sha']).encode()).hexdigest()[:32]
 need(job['consumer_token']==expected,'source/run/attempt consumer token differs')
 return job['proof_issued_epoch'],job['proof_issued_epoch']+6000

def verify_status(stdout,returncode,expected_fpr,window_start,window_end):
 need(type(stdout)is bytes and len(stdout)<=65536 and type(returncode)is int and returncode==0,'successful bounded real GPG status required')
 need(type(expected_fpr)is str and re.fullmatch('[0-9A-F]{40}',expected_fpr) and type(window_start)is int and type(window_end)is int and 0<window_start<=window_end,'exact signer and actual time window required')
 rows=[line[len('[GNUPG:] '):].split() for line in stdout.decode('utf-8','strict').splitlines() if line.startswith('[GNUPG:] ')]
 need(rows and all(row and row[0] not in BAD for row in rows),'bad/expired/revoked/failed GPG status refuses even exit0')
 valid=[row for row in rows if row[0]=='VALIDSIG'];good=[row for row in rows if row[0]=='GOODSIG']
 need(len(valid)==len(good)==1 and len(valid[0])==11 and len(good[0])>=3,'one complete detached good primary signature required')
 row=valid[0];need(row[1]==row[10]==expected_fpr and good[0][1]==expected_fpr[-16:],'signature or primary signer differs')
 need(row[3].isdigit() and row[4].isdigit() and row[5]=='4' and row[6]=='0' and row[7]=='22' and row[8] in ('8','9','10','11') and row[9]=='00','finite Ed25519 SHA2 detached binary signature required')
 created,expires=int(row[3]),int(row[4]);need(window_start<=created<=window_end and (expires==0 or expires>window_end),'signature creation/expiry outside current actual job window')
 need(row[2]==datetime.datetime.fromtimestamp(created,datetime.timezone.utc).date().isoformat(),'signature date/epoch differs')
 return dict(status='PASS_CURRENT_TEST_SIGNATURE',fingerprint=expected_fpr,primary_fingerprint=expected_fpr,created_epoch=created,expires_epoch=expires,status_pin=pin(stdout))

def validate_signing(value,job,archive_rows,*,architecture='aarch64'):
 start,end=job_scope(job)
 need(type(value)is dict and set(value)=={'schema_version','status','job','actor','signer','wrong_signer','key_lifetimes','public_key','wrong_public_key','wrong_signature','archives','negatives','cleanup','operations'} and type(value.get('schema_version'))is int and value['schema_version']==1 and value.get('status')=='PASS_FRESH_TEST_SIGNATURES_PUBLIC_ONLY' and value.get('job')==job,'complete current-job signing receipt required')
 actor=value.get('actor',{});need(actor.get('architecture')==architecture and type(actor.get('uid'))is int and actor['uid']>0 and type(actor.get('started_epoch'))is int and type(actor.get('finished_epoch'))is int and start<=actor['started_epoch']<=actor['finished_epoch']<=end and actor.get('limit')==120 and type(actor.get('seconds'))in(int,float) and 0<=actor['seconds']<=120 and 0<=actor['finished_epoch']-actor['started_epoch']<=121 and abs(actor['finished_epoch']-actor['started_epoch']-actor['seconds'])<=2,'actual native signer identity/clock/120s envelope required')
 signer,wrong=value.get('signer'),value.get('wrong_signer');need(type(signer)is str and type(wrong)is str and re.fullmatch('[0-9A-F]{40}',signer) and re.fullmatch('[0-9A-F]{40}',wrong) and signer!=wrong,'two distinct fresh TEST primary signers required')
 for key,fpr in (('main',signer),('wrong',wrong)):
  row=value.get('key_lifetimes',{}).get(key,{})
  need(row.get('fingerprint')==fpr and type(row.get('created_epoch'))is int and type(row.get('expires_epoch'))is int and actor['started_epoch']-1<=row['created_epoch']<=actor['finished_epoch'] and row['expires_epoch']>end and 86390<=row['expires_epoch']-row['created_epoch']<=86410,'fresh actual-time one-day TEST key required')
 need(whole(value.get('public_key'),65536) and whole(value.get('wrong_public_key'),65536) and whole(value.get('wrong_signature'),65536),'bounded public keys and negative signature required')
 need(type(archive_rows)is dict and set(archive_rows)==set(value.get('archives',{}))=={'a','b'},'both exact build signatures required')
 for side,input_row in archive_rows.items():
  row=value['archives'][side];need(type(row)is dict and set(row)=={'archive','bytes','sha256','signature','verification'} and {k:row[k] for k in ('archive','bytes','sha256')}==input_row and whole({k:row[k] for k in ('bytes','sha256')}) and whole(row['signature'],65536),'signature archive/source byte join differs')
  proof=row['verification'];need(type(proof)is dict and proof.get('status')=='PASS_CURRENT_TEST_SIGNATURE' and proof.get('fingerprint')==proof.get('primary_fingerprint')==signer and type(proof.get('created_epoch'))is int and value['key_lifetimes']['main']['created_epoch']<=proof['created_epoch']<=actor['finished_epoch'] and type(proof.get('expires_epoch'))is int and (proof['expires_epoch']==0 or proof['expires_epoch']>end) and whole(proof.get('status_pin'),65536),'full verification/current clock join differs')
 need(archive_rows['a']['bytes']==archive_rows['b']['bytes'] and archive_rows['a']['sha256']==archive_rows['b']['sha256'],'only the byte-identical native pair may be signed')
 for name in ('wrong_key','tampered'):
  row=value.get('negatives',{}).get(name,{})
  need(type(row.get('exit'))is int and row['exit']!=0 and row.get('expected_rejection')is True and whole(row.get('status'),65536),'real wrong-key/tamper verification refusal required')
 cleanup=value.get('cleanup',{});need(set(cleanup)=={'private_keys_removed','agent_endpoints_absent','private_root_removed','verifier_home_removed'} and all(v is True for v in cleanup.values()),'all private signer/verifier state and agent endpoints must retire')
 operations=value.get('operations');expected=['MAIN_KEY_GENERATE','MAIN_PUBLIC_LIST','MAIN_PUBLIC_EXPORT','MAIN_ARCHIVE_SIGN','MAIN_ARCHIVE_SIGN','WRONG_KEY_GENERATE','WRONG_PUBLIC_LIST','WRONG_PUBLIC_EXPORT','WRONG_ARCHIVE_SIGN','MAIN_RETIRE','WRONG_RETIRE','PUBLIC_IMPORT','PUBLIC_NO_SECRET_KEYS','VERIFY_BUILD_A','VERIFY_BUILD_B','REFUSE_WRONG_KEY','REFUSE_TAMPERED_BYTES','PUBLIC_RETIRE']
 need(type(operations)is list and [r.get('operation') for r in operations]==expected and all(set(r)=={'operation','exit','stdout','stderr'} and type(r.get('exit'))is int and whole(r.get('stdout'),65536,True) and whole(r.get('stderr'),65536,True) for r in operations),'exact held signer/verification/retirement operation closure required')
 for i,row in enumerate(operations):need(row['exit']!=0 if i in (15,16) else row['exit']==0,'actual signing/refusal/cleanup operation exit differs')
 need(operations[2]['stdout']==value['public_key'] and operations[7]['stdout']==value['wrong_public_key'] and operations[13]['stdout']==value['archives']['a']['verification']['status_pin'] and operations[14]['stdout']==value['archives']['b']['verification']['status_pin'] and operations[15]['stdout']==value['negatives']['wrong_key']['status'] and operations[16]['stdout']==value['negatives']['tampered']['status'] and operations[15]['exit']==value['negatives']['wrong_key']['exit'] and operations[16]['exit']==value['negatives']['tampered']['exit'],'exported public keys and actual verification status operands must join')
 return dict(status='PASS_CURRENT_JOB_NATIVE_TEST_SIGNATURES',signer=signer,signatures=2,wrong_key_and_tamper='REFUSED',private_keys='REMOVED',job=job)
