#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real installed mirror CLI against an owned loopback HTTPS snapshot only."""
import hashlib
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import threading


def need(ok,message):
    if not ok:raise ValueError(message)


def command(args,expected=0,env=None):
    row=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
    need(row.returncode==expected and len(row.stdout)+len(row.stderr)<=65536,'installed mirror command failed')
    return row.stdout.decode()


def main(work):
    need(os.getuid()>0 and work.is_dir() and not list(work.iterdir()),'fresh ordinary fixture workspace required')
    data=b'owned offline TLS database fixture\n';pin=hashlib.sha256(data).hexdigest()
    command(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
             '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
             '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
             '-addext','subjectKeyIdentifier=hash','-addext','authorityKeyIdentifier=keyid:always','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem')])
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            body=data if self.path=='/good/aarch64/core/core.db' else b'X'*len(data)
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server=HTTPServer(('127.0.0.1',0),Handler);server.timeout=2
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(work/'cert.pem',work/'key.pem')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    env=dict(os.environ,SSL_CERT_FILE=str(work/'cert.pem'));exe='/usr/bin/cachy-asahi-mirrors'
    catalog=dict(schema_version=1,architecture='aarch64',base='asahi-alarm',repository='core',database=dict(bytes=len(data),sha256=pin),
        mirrors=[dict(id=kind,server='https://localhost:'+str(server.server_port)+'/'+kind+'/$arch/$repo') for kind in ('good','bad')])
    path=work/'catalog.json';path.write_text(json.dumps(catalog));candidate=work/'candidate';outside=work/'outside';outside.write_text('preserve\n')
    try:
        need(command([exe,'--version'])=='cachy-asahi-mirrors 0.2.0\n','version differs')
        command([exe,'--help'])
        checked=json.loads(command([exe,'check',str(path)]));need(checked['status']=='PASS_CATALOG_SYNTAX' and checked['network']=='NOT_USED','catalog CLI failed')
        ranked=json.loads(command([exe,'rank',str(path),'--output',str(candidate)],env=env))
        need(ranked['status']=='PASS_CANDIDATE_WRITTEN' and ranked['activation']=='NOT_PERFORMED' and
             [r['status'] for r in ranked['results']]==['PASS_EXACT_SNAPSHOT','FAIL'],'exact/mismatched TLS snapshot behavior failed')
        raw=candidate.read_bytes();need(stat.S_IMODE(candidate.stat().st_mode)==0o600 and
             hashlib.sha256(raw).hexdigest()==ranked['candidate']['sha256'] and b'/good/' in raw and b'/bad/' not in raw,'candidate publication differs')
        failed=json.loads(command([exe,'rank',str(path),'--output',str(candidate)],1,env));need(failed['status']=='FAIL' and candidate.read_bytes()==raw,'overwrite refused incorrectly')
        alias=work/'alias';alias.symlink_to('outside');command([exe,'rank',str(path),'--output',str(alias)],1,env)
        need(outside.read_text()=='preserve\n' and alias.is_symlink(),'symlink target changed')
        # Root binds only the final product CLI vectors. The checks themselves are fixed.
        spec=json.loads(Path('/runner/product-spec.json').read_text())
        activation=spec['products']['cachy-asahi-mirrors']['activation_cli']
        need(type(activation) is dict,'final mirror activation CLI binding missing')
        report=work/'rank-report.json';report.write_text(json.dumps(ranked))
        target=work/'explicit-target';prior=b'# preexisting explicit fixture mirror list\n'
        target.write_bytes(prior);target.chmod(0o640);prior_stat=target.stat()
        def invoke(verb,journal,target_path=target,expected=0):
            replacements={'{candidate}':str(candidate),'{target}':str(target_path),'{journal}':str(journal),
                          '{catalog}':str(path),'{report}':str(report)}
            return command([exe,*(replacements.get(arg,arg) for arg in activation[verb])],expected,env)
        journal=work/'activation-journal'
        invoke('activate',journal);need(target.read_bytes()==raw,'activation did not select exact candidate')
        active=target.stat();journal_before=journal.read_bytes()
        invoke('activate',journal);repeated=target.stat()
        need(target.read_bytes()==raw and (active.st_ino,active.st_mtime_ns,active.st_mode,active.st_uid,active.st_gid)==
             (repeated.st_ino,repeated.st_mtime_ns,repeated.st_mode,repeated.st_uid,repeated.st_gid) and
             journal.read_bytes()==journal_before,'repeat activation rewrote active target or original journal')
        invoke('restore',journal);info=target.stat()
        need(target.read_bytes()==prior and stat.S_IMODE(info.st_mode)==0o640 and
             (info.st_uid,info.st_gid)==(prior_stat.st_uid,prior_stat.st_gid),'restore lost preexisting bytes/mode/ownership')
        restored=target.stat();invoke('restore',journal);repeat_restore=target.stat()
        need(target.read_bytes()==prior and (restored.st_ino,restored.st_mtime_ns,restored.st_mode,restored.st_uid,restored.st_gid)==
             (repeat_restore.st_ino,repeat_restore.st_mtime_ns,repeat_restore.st_mode,repeat_restore.st_uid,repeat_restore.st_gid),
             'repeat restore changed restored target')
        journal=work/'conflict-journal';invoke('activate',journal)
        target.write_bytes(b'third-party change\n');invoke('restore',journal,expected=activation['refusal_exit'])
        need(target.read_bytes()==b'third-party change\n','conflicting target overwritten')
        invoke('activate',work/'symlink-journal',alias,activation['refusal_exit'])
        need(outside.read_text()=='preserve\n' and alias.is_symlink() and candidate.read_bytes()==raw,
             'activation changed symlink target or candidate')
        catalog['mirrors']=catalog['mirrors'][1:];path.write_text(json.dumps(catalog))
        failed=json.loads(command([exe,'rank',str(path),'--output',str(work/'none')],1,env))
        need(failed['status']=='FAIL' and not (work/'none').exists(),'all-failed rank published output')
        catalog['architecture']='x86_64';path.write_text(json.dumps(catalog));command([exe,'check',str(path)],1)
        result=dict(status='PASS_OFFLINE_TLS_CLI',real_cli=True,real_TLS=True,external_network='NONE',snapshot_trust='FIXTURE_ONLY',
                    candidate_sha256=hashlib.sha256(raw).hexdigest(),activate_restore=True,repeat_activation_preserved=True,repeat_restore_preserved=True,restore_conflict_preserved=True,
                    explicit_target='OWNED_FIXTURE_ONLY',prior_mode_restored=True,no_overwrite=True,symlink_preserved=True,
                    exact_and_mismatched_snapshots=True,all_failed_no_output=True)
    finally:
        server.shutdown();server.server_close();worker.join(timeout=3);need(not worker.is_alive(),'owned HTTPS thread remained')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main(Path(sys.argv[1]))
