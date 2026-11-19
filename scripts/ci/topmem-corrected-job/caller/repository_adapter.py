# SPDX-License-Identifier: MIT
"""Explicit Source19 publisher adaptation: internal bytes, native GPG signatures."""
import hashlib
import io
import re
import sys
import os
from pathlib import Path
import stat
from contextlib import contextmanager
from types import SimpleNamespace

KIND = 'TOPMEM_SINGLE_PACKAGE_PACMAN_DATABASE_V1'
SCOPE = 'TOPMEM_INTERNAL_DATABASE_PRODUCTION_V1'


def bind(profile='topmem-v1'):
    """Fixed caller profile; clocks, pins and custody remain borrowed unchanged."""
    if type(profile) is not str or profile not in ('topmem-v1', 'fish-history-v1'):
        raise ValueError('repository-profile-unselected')
    PROFILE = profile
    if profile == 'topmem-v1':
        NAME, ADDON_SCOPE, REPO = 'cachy-asahi-topmem', 'topmem-addon', 'topmem'
        KIND, SCOPE = 'TOPMEM_SINGLE_PACKAGE_PACMAN_DATABASE_V1', 'TOPMEM_INTERNAL_DATABASE_PRODUCTION_V1'
    else:
        NAME, ADDON_SCOPE, REPO = 'cachy-asahi-fish-bang-bang', 'fish-history-addon', 'fish-history'
        KIND, SCOPE = 'FISH_HISTORY_SINGLE_PACKAGE_PACMAN_DATABASE_V1', 'FISH_HISTORY_INTERNAL_DATABASE_PRODUCTION_V1'

    def write(addon, path, raw, end):
        addon.live(end); before = addon.directory(path.parent, public=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw); stream.flush(); os.fsync(fd)
        finally: os.close(fd)
        after = addon.directory(path.parent, public=True)
        addon.need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino), 'repository-parent-drift')
        addon.need(addon.read(path,end,max(len(raw),1))==raw, 'repository-write-drift')


    def checked(decoder, operation):
        """Close every selected decoder without masking a primary cancellation."""
        error = None; result = None
        try: result = operation()
        except BaseException as fault: error = fault
        try:
            if decoder is not None: decoder.close()
        except BaseException as fault:
            cancel = lambda e: isinstance(e,KeyboardInterrupt) or type(e).__name__=='Cancelled'
            if PROFILE == 'fish-history-v1' and error is not None:
                if cancel(fault) and not cancel(error):
                    error.secondary_cancelled = True
            elif error is None or (cancel(fault) and not cancel(error)): error = fault
        if error is not None: raise error
        return result


    def archive_reader(checks, addon, producer, c, config, end, guard):
        """Keep captured package() predicates; provide only the selected Zstd stream."""
        original = checks.subprocess
        root = Path(config['jobroot'])/ADDON_SCOPE
        allowed = {root/(v+'-'+str(n))/'artifacts' for v in ('current','upgrade-fixture') for n in (1,2)}
        def stream(argv, stdout, stderr):
            addon.live(end)
            addon.need(type(argv) is list and len(argv)==4 and argv[:3]==['zstd','-dc','--']
                and type(argv[3]) is str and stdout==stderr==original.PIPE,'repository-archive-command')
            path=Path(argv[3]);addon.need(path.is_absolute() and path.parent in allowed and path==path.resolve()
                and re.fullmatch(re.escape(NAME)+r'-0\.1\.0-[12]-any\.pkg\.tar\.zst',path.name), 'repository-archive-path')
            addon.need(('-0.1.0-1-' in path.name)==path.parent.parent.name.startswith('current-'), 'repository-archive-version')
            raw=addon.read(path,end,16*1024**2);policy=guard(c,end)
            decoder=producer.zstd_decoder(c,policy,end)
            decoded=checked(decoder,lambda:decoder(raw,end))
            addon.need(type(decoded) is bytes and len(decoded)<=32*1024**2,'repository-archive-stream')
            return SimpleNamespace(stdout=io.BytesIO(decoded),stderr=io.BytesIO(b''),wait=lambda:0)
        checks.subprocess=SimpleNamespace(Popen=stream,PIPE=original.PIPE)
        return original


    @contextmanager
    def selected(addon, producer, source_path, producer_sha, producer_bytes, caller_manifest_sha, guard, worker, config):
        """Temporarily select this reviewed publisher, never intercept runner argv."""
        if PROFILE == 'fish-history-v1':
            required = ('repository_factory', 'repository_runtime', 'live', 'need', 'read', 'save', 'directory', 'pin', 'tool')
            if not all(callable(getattr(addon, name, None)) for name in required):
                raise ValueError('fish-repository-runtime-api-required')
            original = addon.repository_factory()
        else:
            original = addon.Repository
        original_graph = worker.graph
        @contextmanager
        def graph(configuration, deadline=None):
            with original_graph(configuration,deadline) as (c,provider,load):
                end=configuration['work_deadline'] if deadline is None else deadline
                c.pinned(source_path,producer_sha,deadline=end)
                held=[]; original_module=provider.module
                def bind(value):
                    before=archive_reader(value,addon,producer,c,configuration,end,guard)
                    held.append((value,before));return value
                def selected_load(name,path):
                    value=load(name,path)
                    return bind(value) if name=='package_checks' else value
                try:
                    bind(sys.modules['package_checks']);provider.module=selected_load
                    yield c,provider,selected_load
                finally:
                    provider.module=original_module
                    for value,before in reversed(held):value.subprocess=before
        class Repository(original):
            def run(self, argv):
                addon.need(type(argv) is list and argv and argv[0]=='/usr/bin/gpg', 'repository-gpg-only')
                guard(self.c,self.end)
                return super().run(argv)
            def publish(self, artifacts):
                addon.need(self.contract['repo_add_sha256']==producer_sha, 'repository-producer-owner')
                raw = self.c.pinned(source_path,producer_sha,deadline=self.end)
                addon.need(len(raw)==producer_bytes, 'repository-producer-source')
                repo = self.out/'repo';addon.need(not repo.exists() and not repo.is_symlink(),'addon-repository-fresh')
                repo.mkdir(mode=0o755);repo.chmod(0o755)
                key=self.contract; fingerprint=key['fingerprint']
                gpg=['/usr/bin/gpg','--no-autostart','--batch','--no-options','--homedir',key['keyhome'],'--no-auto-key-retrieve']
                lines=self.run(gpg+['--with-colons','--show-keys',key['certificate']]).decode('ascii').splitlines()
                primary=[];pending=False
                for line in lines:
                    fields=line.split(':')
                    if fields[0]=='pub':addon.need(len(fields)>1 and fields[1] not in ('r','e'),'addon-key-revoked');pending=True
                    elif fields[0]=='fpr' and pending:
                        addon.need(len(fields)>9,'addon-key-fingerprint');primary.append(fields[9]);pending=False
                addon.need(primary==[fingerprint],'addon-key-fingerprint')
                exported=self.run(gpg+['--armor','--export',fingerprint])
                addon.need(hashlib.sha256(exported).hexdigest()==key['certificate_sha256'],'addon-export-certificate')
                write(addon,repo/'public-key.asc',exported,self.end)
                journal={'schema_version':1,'scope':SCOPE,'producer_kind':KIND,'producer_sha256':producer_sha,
                    'caller_manifest_sha256':caller_manifest_sha,'rows':[]}
                addon.save(self.out/'database-production.json',journal)
                for variant,label in (('current','v1'),('upgrade-fixture','v2')):
                    directory=repo/label;directory.mkdir(mode=0o755);directory.chmod(0o755)
                    row=artifacts[variant];addon.need(type(row) is dict and set(row)=={'path','sha256'},'addon-repo-artifact')
                    source=Path(row['path']);target=directory/source.name
                    addon.need(source.parent==self.out/(variant+'-1')/'artifacts','addon-repo-artifact-path')
                    package=addon.read(source,self.end,16*1024**2)
                    addon.need(hashlib.sha256(package).hexdigest()==addon.pin(row['sha256']),'addon-repo-artifact-drift')
                    write(addon,target,package,self.end)
                    def sign(path):
                        self.run(gpg+['--local-user',fingerprint,'--digest-algo','SHA256','--output',str(path)+'.sig','--detach-sign',str(path)])
                    sign(target);signature=addon.read(Path(str(target)+'.sig'),self.end,65536)
                    reservation={'variant':variant,'filename':target.name,'package_sha256':row['sha256'],
                        'signature_sha256':hashlib.sha256(signature).hexdigest(),'status':'STARTED','db_sha256':None,'files_sha256':None,'decoder_sha256':None}
                    journal['rows'].append(reservation);addon.save(self.out/'database-production.json',journal)
                    self.c.pinned(source_path,producer_sha,deadline=self.end)
                    policy=guard(self.c,self.end)
                    decoder=producer.zstd_decoder(self.c,policy,self.end) if target.name.endswith('.zst') else None
                    def produce():
                        reservation['decoder_sha256']=decoder.sha256 if decoder is not None else None
                        addon.save(self.out/'database-production.json',journal)
                        return producer.build(package,signature,target.name,variant,self.end,zstd_decoder=decoder)
                    built=checked(decoder,produce)
                    addon.need(type(built) is dict and set(built)=={'db','files','metadata'},'repository-producer-result')
                    for kind in ('db','files'):
                        raw=built[kind];addon.need(type(raw) is bytes and 0<len(raw)<=512*1024,'repository-database-bound')
                        path=directory/(REPO+'.'+kind+'.tar.gz');write(addon,path,raw,self.end);sign(path)
                        reservation[kind+'_sha256']=hashlib.sha256(raw).hexdigest()
                    for path in (target,directory/(REPO+'.db.tar.gz'),directory/(REPO+'.files.tar.gz')):
                        status=self.run(gpg+['--status-fd','1','--verify',str(path)+'.sig',str(path)]).decode('ascii')
                        self.native.valid_signature(status,fingerprint)
                        path.chmod(0o644);Path(str(path)+'.sig').chmod(0o644)
                    for kind in ('db','files'):
                        for suffix in ('','.sig'):
                            source=directory/(REPO+'.'+kind+'.tar.gz'+suffix)
                            write(addon,directory/(REPO+'.'+kind+suffix),addon.read(source,self.end),self.end)
                    self.c.pinned(source_path,producer_sha,deadline=self.end)
                    reservation['status']='COMPLETED';addon.save(self.out/'database-production.json',journal)
                return repo
        if PROFILE == 'fish-history-v1':
            with addon.repository_runtime(Repository):
                worker.graph=graph
                try:yield
                finally:worker.graph=original_graph
        else:
            addon.Repository=Repository;worker.graph=graph
            try:yield
            finally:addon.Repository=original;worker.graph=original_graph


    def admit(c, addon, producer, config, manifest_sha, end, policy):
        """Regenerate both databases from actual bound package/signature bytes."""
        root=Path(config['jobroot']);out=root/ADDON_SCOPE
        journal=c.decode(c.read(out/'database-production.json',65536,deadline=end))
        expected={'schema_version','scope','producer_kind','producer_sha256','caller_manifest_sha256','rows'}
        addon.need(set(journal)==expected and type(journal['schema_version']) is int and journal['schema_version']==1
            and journal['scope']==SCOPE and journal['producer_kind']==KIND
            and journal['producer_sha256']==config['repository_producer_sha256']
            and journal['caller_manifest_sha256']==manifest_sha and type(journal['rows']) is list
            and len(journal['rows'])==2, 'repository-production-binding')
        manifest=c.decode(c.pinned(Path(config['caller_source'])/'manifest.json',manifest_sha,deadline=end))
        selected=manifest['files']['producer.py']
        c.pinned(Path(config['caller_source'])/'producer.py',selected['sha256'],deadline=end)
        addon.need(selected['sha256']==journal['producer_sha256'],'repository-production-source')
        for row,(variant,label) in zip(journal['rows'],(('current','v1'),('upgrade-fixture','v2'))):
            addon.need(type(row) is dict and set(row)=={'variant','filename','package_sha256','signature_sha256','status','db_sha256','files_sha256','decoder_sha256'}
                and row['variant']==variant and row['status']=='COMPLETED','repository-production-row')
            name=c.relative(row['filename']);addon.need(len(name.parts)==1,'repository-production-filename')
            directory=out/'repo'/label;package=addon.read(directory/name,end,16*1024**2)
            signature=addon.read(directory/(str(name)+'.sig'),end,65536)
            addon.need(c.sha(package)==addon.pin(row['package_sha256']) and c.sha(signature)==addon.pin(row['signature_sha256']),
                'repository-production-input-drift')
            original=addon.read(out/(variant+'-1')/'artifacts'/name,end,16*1024**2)
            addon.need(package==original,'repository-production-build-drift')
            provenance=c.decode(c.read(out/(variant+'-1')/'provenance.json',1024**2,deadline=end))
            addon.need(provenance['artifacts'][str(name)]==row['package_sha256'],'repository-production-provenance')
            decoder=producer.zstd_decoder(c,policy,end) if str(name).endswith('.zst') else None
            def regenerate():
                addon.need(row['decoder_sha256']==(decoder.sha256 if decoder is not None else None),'repository-production-decoder')
                return producer.build(package,signature,str(name),variant,end,zstd_decoder=decoder)
            built=checked(decoder,regenerate)
            for kind in ('db','files'):
                raw=addon.read(directory/(REPO+'.'+kind+'.tar.gz'),end,512*1024)
                addon.need(raw==built[kind] and c.sha(raw)==addon.pin(row[kind+'_sha256']), 'repository-production-output-drift')
                if PROFILE == 'fish-history-v1':
                    for suffix in ('', '.sig'):
                        limit = 65536 if suffix else 512*1024
                        canonical = addon.read(directory/(REPO+'.'+kind+'.tar.gz'+suffix), end, limit)
                        alias = addon.read(directory/(REPO+'.'+kind+suffix), end, limit)
                        addon.need(alias == canonical, 'fish-repository-alias-drift')
        return 2

    return SimpleNamespace(profile=PROFILE, NAME=NAME, ADDON_SCOPE=ADDON_SCOPE, REPO=REPO, KIND=KIND, SCOPE=SCOPE, write=write, checked=checked, archive_reader=archive_reader, selected=selected, admit=admit)

_DEFAULT = bind()
for _name in ('write','checked','archive_reader','selected','admit'):
    globals()[_name] = getattr(_DEFAULT, _name)
