#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-reviewed proposed offline constructor. NEVER boots; explicit opt-in."""
import argparse, hashlib, json, os, secrets, shutil, signal, subprocess, tarfile, tempfile
from pathlib import Path, PurePosixPath
from intake import descriptor, exact, sha
from audit import metadata
import ownership
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2];SEAT=HERE.parent/'systemd_tcg_seat_guest'
BASE='cachy-nm-real-seat:ca3b06ea4aff9410';PIN='sha256:1f4922c557070c90e9af8dbc2099ba9df61cce352b1f86f214d84d6eb19bbee3'
AUDIT='f569165fa3d08a9d00ccc6912753572f7935a31cf050e8ade38f378f253028a1'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-ui-seat-reference',action='store_true');p.add_argument('--official-intake',type=Path,required=True);p.add_argument('--official-audit',type=Path,required=True);p.add_argument('--official-keyring',type=Path,required=True);p.add_argument('--retained-ui',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not(a.allow_prepare_ui_seat_reference and __debug__ and os.geteuid()!=0):p.error('explicit reviewed constructor/ordinary host user required')
    assert sha(a.official_audit)==AUDIT,'exact reviewed official evidence required'
    official=json.loads(a.official_audit.read_text());assert official['verified']==125 and official['descriptor_sha256']==sha(HERE/'closure.json')
    contract=descriptor(HERE/'closure.json');project=json.loads((HERE/'project.json').read_text());assert sha(a.official_keyring)==contract['keyring_sha256']
    references=json.loads((HERE/'references.json').read_text())
    for name,ref in references.items():exact(REPO/name,ref['bytes'],ref['sha256'])
    assert 'name=rootless' in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
    base=json.loads(subprocess.check_output(['docker','image','inspect',BASE]))[0];assert base['Id']==PIN
    available=int(dict(l.split(':',1)for l in Path('/proc/meminfo').read_text().splitlines())['MemAvailable'].split()[0])*1024
    assert available>=6*1024**3 and shutil.disk_usage(a.output.parent).free>=4*1024**3,'fresh aggregate memory/storage guard'
    out=a.output.resolve();out.mkdir(mode=0o700,exist_ok=False);tag='cachy-ui-real-seat:'+secrets.token_hex(8);name='cachy-ui-seat-assembly-'+secrets.token_hex(16)
    report={'status':'HOLD','VM_boot':'NOT RUN','scope':'offline x86 DATA constructor only','base':{'name':BASE,'id':PIN},'official_audit_sha256':AUDIT,'MemAvailable_bytes':available};submitted=False;image=None
    labels={'org.cachy-asahi.ui-assembly-owner':str(os.getuid()),'org.cachy-asahi.ui-assembly-nonce':secrets.token_hex(16)}
    def cancelled(number,frame):raise InterruptedError('assembly signal '+str(number))
    previous={number:signal.signal(number,cancelled)for number in [signal.SIGTERM,signal.SIGINT]}
    def call(label,args,timeout=90):
        with(out/(label+'.log')).open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        assert r.returncode==0,(label,r.returncode)
    try:
        with tempfile.TemporaryDirectory(prefix='.context-',dir=out)as temp:
            context=Path(temp);inputs=context/'ui-session';inputs.mkdir();packages=inputs/'packages';packages.mkdir();rows=[];primaries=[]
            for row,verified in zip(contract['official'],official['records'],strict=True):
                assert row['filename']==verified['filename'] and verified['status']=='BYTE_SIGNATURE_METADATA_VERIFIED'
                source=a.official_intake/'packages'/row['filename'];sig=source.with_name(source.name+'.sig')
                exact(source,row['bytes'],row['sha256']);exact(sig,row['catalog_signature_bytes'],row['catalog_signature_sha256'])
                for path in [source,sig]:shutil.copyfile(path,packages/path.name)
                rows.append({**row,'signature_bytes':row['catalog_signature_bytes'],'signature_sha256':row['catalog_signature_sha256']})
                statuses=[s.split()for s in verified['signature']['status'].splitlines()if s.startswith('[GNUPG:] VALIDSIG ')];assert len(statuses)==1;primaries.append(statuses[0][-1])
            public=a.retained_ui/'public-lifecycle';cert=public/'TEST-public.asc';exact(cert,project['TEST_certificate']['bytes'],project['TEST_certificate']['sha256']);shutil.copyfile(cert,inputs/cert.name)
            shutil.copyfile(a.official_keyring,inputs/'official-keyring.gpg');home=context/'verify';home.mkdir(mode=0o700);binary=home/'public.gpg'
            subprocess.run(['gpg','--homedir',str(home),'--batch','--dearmor','--output',str(binary),str(cert)],capture_output=True,check=True,timeout=15)
            payloads={}
            for ref in project['packages']:
                item=ref['archive'];filename=item['filename'];source=(a.retained_ui/'build'/filename if filename.startswith('cachy-asahi-first-login-ui-') else a.retained_ui/'inputs/materials'/filename);sig=public/(filename+'.sig')
                exact(source,item['bytes'],item['sha256']);exact(sig,ref['signature']['bytes'],ref['signature']['sha256'])
                r=subprocess.run(['gpgv','--homedir',str(home),'--keyring',str(binary),'--status-fd','1',str(sig),str(source)],capture_output=True,timeout=15);assert r.returncode==0 and ('[GNUPG:] VALIDSIG '+project['TEST_fingerprint']+' ') in r.stdout.decode(),'current retained TEST signature refusal'
                info=metadata(source)['.PKGINFO']['fields'];rows.append({'filename':filename,'name':info['pkgname'][0],'version':info['pkgver'][0],'bytes':item['bytes'],'sha256':item['sha256'],'signature_bytes':ref['signature']['bytes'],'signature_sha256':ref['signature']['sha256']})
                for path in [source,sig]:shutil.copyfile(path,packages/path.name)
                with tarfile.open(source,'r:*')as archive:
                    for member in archive:
                        if member.name.startswith('usr/')and member.isfile():
                            assert member.size<=256*1024;payloads[member.name]=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            templates=inputs/'templates';templates.mkdir()
            for component,ref in project['templates'].items():
                source=a.retained_ui/'inputs/materials'/ref['filename'];exact(source,ref['bytes'],ref['sha256'])
                with tarfile.open(source,'r:*')as archive:
                    for member in archive:
                        if not member.name.startswith('usr/share/cachy-asahi/'+component+'/'):continue
                        relative=PurePosixPath(member.name).relative_to('usr/share/cachy-asahi');assert '..'not in relative.parts and not relative.is_absolute()
                        destination=templates/relative
                        if member.isdir():destination.mkdir(parents=True,exist_ok=True)
                        else:
                            assert member.isfile()and member.size<=1024**2;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(archive.extractfile(member).read())
            assert (templates/'fish/config.fish').is_file()and (templates/'zsh/config.zsh').is_file()
            export=json.loads(subprocess.check_output(['docker','run','--rm','--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--entrypoint=/usr/bin/cat',BASE,'/opt/nm-session-export.json'],timeout=20))
            baseline=export['selected'];assert len(baseline)==164
            ownership_metadata=ownership.build_index(packages,rows,inputs/'ownership')
            profile={'ownership_metadata':ownership_metadata,'archives':rows,'baseline_versions':baseline,'project_payloads':payloads,'official_primary_signers':sorted(set(primaries)),'official_keyring_sha256':contract['keyring_sha256'],'TEST_fingerprint':project['TEST_fingerprint'],'TEST_certificate_sha256':project['TEST_certificate']['sha256']}
            (inputs/'inputs.json').write_text(json.dumps(profile,sort_keys=True,indent=2)+'\n')
            mapping={'seat-user-proof.py':SEAT/'user_proof.py','seat-observer.service':SEAT/'observer.service','seat-keyboard.py':SEAT/'keyboard.py','seat-input.py':SEAT/'input_seat.py','seat-observer.py':HERE/'observer.py','vm_actor.py':HERE/'vm_actor.py','ui-client.py':HERE/'client.py','ui-gui-probe.py':HERE/'gui_probe.py','ui-root-fixture.py':HERE/'root_fixture.py','ui-fixture.service':HERE/'fixture.service','ui-result.py':HERE/'result.py','ui-owned-process.py':REPO/'scripts/virtual/owned_process.py','ui-receipts.py':HERE/'receipts.py','ui-ownership.py':HERE/'ownership.py'}
            # Exact original assembly becomes a separately pinned source variant.
            original=(SEAT/'assemble.py').read_text();s=original.replace("'/tmp/tcg-seat-root'","'/tmp/ui-seat-root'").replace('1536*1024**2','3072*1024**2').replace('generic x86 real-seat/PAM/Polkit reference; ARM/M2/release NOT RUN','x86 real-seat first-login GTK fixture; ARM/M2/release NOT RUN')
            needle="k=Path('/usr/lib/modules/7.2.14-arch1-1')";assert s.count(needle)==1
            addition="""shutil.copytree(I/'ui-session',R/'opt/ui-session')
for source,dest in [('ui-client.py','ui-client.py'),('ui-gui-probe.py','ui-gui-probe.py'),('ui-root-fixture.py','ui-root-fixture.py'),('ui-result.py','ui-result.py'),('ui-owned-process.py','ui-owned-process.py'),('ui-receipts.py','ui-receipts.py'),('ui-ownership.py','ui-ownership.py')]:
 shutil.copyfile(I/source,R/'usr/local/libexec'/dest);(R/'usr/local/libexec'/dest).chmod(0o755)
shutil.copyfile(I/'ui-fixture.service',R/'etc/systemd/system/ui-fixture.service')
(R/'etc/systemd/system/multi-user.target.wants/ui-fixture.service').symlink_to('/etc/systemd/system/ui-fixture.service')
(R/'home/builder/user-config.txt').write_text('preserved real-seat UI user settings\\n');os.chown(R/'home/builder/user-config.txt',1000,1000)
p=R/'home/builder/.bash_profile';old=p.read_text();needle='/usr/bin/python3 -I -B /usr/local/libexec/seat-user-proof.py';assert old.count(needle)==1
p.write_text(old.replace(needle,'/usr/bin/python3 -I -B /usr/local/libexec/ui-client.py 2>/home/builder/UI_ERROR\\n'+needle));os.chown(p,1000,1000)
"""
            s=s.replace(needle,addition+needle);(context/'seat-assemble.py').write_text(s)
            for dest,path in mapping.items():shutil.copyfile(path,context/dest)
            sources={dest:sha(context/dest)for dest in [*mapping,'seat-assemble.py']};(context/'seat-inputs.json').write_text(json.dumps({'sources':sources})+'\n')
            dockerfile='FROM '+BASE+'\nUSER 0:0\n'+''.join('COPY '+dest+' /opt/'+dest+'\n' for dest in [*sources,'seat-inputs.json'])+'COPY ui-session /opt/ui-session\n'
            (context/'Dockerfile').write_text(dockerfile);report.update(Dockerfile=dockerfile,source_pins=sources,inputs_sha256=sha(inputs/'inputs.json'))
            call('COPY-only-image',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],120)
        image=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];assert image['RootFS']['Layers'][:len(base['RootFS']['Layers'])]==base['RootFS']['Layers'];report.update(tool_image=tag,tool_image_id=image['Id'])
        prepared=out/'prepared';prepared.mkdir(mode=0o700)
        fresh_available=int(dict(l.split(':',1)for l in Path('/proc/meminfo').read_text().splitlines())['MemAvailable'].split()[0])*1024
        assert fresh_available>=6*1024**3 and shutil.disk_usage(out).free>=3*1024**3,'fresh pre-assembly aggregate resource guard'
        report['pre_assembly_MemAvailable_bytes']=fresh_available
        submitted=True
        call('create',['docker','create','--name',name,*[v for k,x in labels.items()for v in ['--label',k+'='+x]],'--init=false','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1536m','--mount','type=bind,source='+str(prepared)+',target=/work','--entrypoint=/usr/bin/fakeroot',tag,'--','/usr/bin/python3','-I','-B','/opt/seat-assemble.py'])
        call('assemble',['docker','start','--attach',name],300)
        state=json.loads(subprocess.check_output(['docker','inspect',name]))[0]['State'];assert state['ExitCode']==0 and not state['OOMKilled'];report.update(status='PREPARED_NOT_BOOTED',prepared_sha256=sha(prepared/'prepared.json'),prepared=json.loads((prepared/'prepared.json').read_text()))
    except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
    finally:
        # Unique-name recovery covers ambiguous create failures. Cleanup has an
        # independent finite budget; an earlier failure remains the primary error.
        for number in previous:signal.signal(number,signal.SIG_IGN)
        try:
            if submitted:
                inspected=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=8)
                if inspected.returncode==0:
                    owned=json.loads(inspected.stdout)[0]
                    assert image and owned['Image']==image['Id'] and all(owned['Config']['Labels'].get(k)==v for k,v in labels.items())
                    assert len(owned['Mounts'])==1 and owned['Mounts'][0]['Source']==str(out/'prepared') and owned['Mounts'][0]['Destination']=='/work' and owned['Mounts'][0]['RW']is True
                    removed=subprocess.run(['docker','rm','--force',owned['Id']],capture_output=True,timeout=20);assert removed.returncode==0
                elif b'No such'not in inspected.stderr:raise RuntimeError('ambiguous assembly identity inspection')
                absent=subprocess.run(['docker','container','ls','--all','--no-trunc','--format','{{.Names}}','--filter','name=^/'+name+'$'],capture_output=True,timeout=8)
                assert absent.returncode==0 and not absent.stdout.strip();report['assembly_removed']=True
        except BaseException as e:report['cleanup_failure']={'category':type(e).__name__,'message':str(e)[:1024]};report['status']='HOLD_CLEANUP'
        finally:
            (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
            for number,handler in previous.items():signal.signal(number,handler)
    print(json.dumps({'status':report['status'],'report':str(out/'preparation.json'),'failure':report.get('failure')}));return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1
if __name__=='__main__':raise SystemExit(main())
