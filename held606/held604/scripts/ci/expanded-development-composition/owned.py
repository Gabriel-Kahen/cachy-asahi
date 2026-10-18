# SPDX-License-Identifier: MIT
"""Persist identity before launch; retire only exact owned container IDs."""
import json
import fcntl
import os
from pathlib import Path
import re
import subprocess
import contract as C


def capture(argv):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    C.need(len(result.stdout)+len(result.stderr)<=1024**2,'Docker observation cap')
    result.check_returncode();return result.stdout.strip()


class Containers:
    def __init__(self,path,image):
        self.path=path;self.image=image;self.token=os.urandom(16).hex();self.rows=[]
        self.lease=os.open(path.with_suffix('.lease'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
        fcntl.flock(self.lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        os.write(self.lease,C.encoded(dict(token=self.token,image=image,pid=os.getpid())))
        os.fsync(self.lease);self.save()

    def close(self):
        if self.lease is not None:
            os.close(self.lease);self.lease=None

    def __del__(self):
        if getattr(self,'lease',None) is not None:self.close()

    def save(self):
        temporary=self.path.with_suffix('.new');temporary.write_bytes(C.encoded(dict(token=self.token,image=self.image,containers=self.rows)))
        temporary.replace(self.path)

    def launch(self,argv):
        C.need(argv[:2]==['docker','run'] and '--name' in argv and '--rm' not in argv,'retained named container run required')
        name=argv[argv.index('--name')+1]
        C.need(re.fullmatch('cachy-asahi-[a-z0-9-]{1,100}',name) and name not in {r['name'] for r in self.rows},'unique owned name required')
        C.need(not capture(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.ID}}']),
               'new container name already exists')
        self.rows.append(dict(name=name,status='RESERVED',id=None));self.save()
        return argv[:2]+['--label',C.LABEL+'='+self.token]+argv[2:]

    def cleanup(self):
        errors=[]
        for row in reversed(self.rows):
            try:
                observed=subprocess.run(['docker','container','inspect',row['name']],capture_output=True,text=True,timeout=20)
                C.need(len(observed.stdout)+len(observed.stderr)<=1024**2,'owned inspection cap')
                if observed.returncode:
                    C.need('No such container' in observed.stderr or 'No such object' in observed.stderr,'container absence unknown')
                else:
                    records=json.loads(observed.stdout);C.need(len(records)==1,'one container identity required');record=records[0]
                    identifier=record['Id']
                    C.need(re.fullmatch('[0-9a-f]{64}',identifier) and record['Name']=='/'+row['name'] and
                           record['Image']==self.image and record['Config']['Labels'].get(C.LABEL)==self.token and
                           row['id'] in (None,identifier),'owned container identity/label/image differs')
                    row.update(id=identifier,status='RETIRING');self.save()
                    capture(['docker','container','rm','--force',identifier])
                    C.need(not capture(['docker','container','ls','-a','--no-trunc','--filter','id='+identifier,'--format','{{.ID}}']),
                           'owned container remains')
                row.update(status='PASS_ABSENCE_VERIFIED');self.save()
            except BaseException as error:
                row.update(status='FAIL',error=str(error)[:512]);self.save();errors.append(row['name'])
        C.need(not errors,'owned cleanup failed: '+','.join(errors))
