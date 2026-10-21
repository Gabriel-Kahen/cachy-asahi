#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy exact already-signed ready604/tools606/latest inputs into one closed606 cache."""
import argparse,json,shutil
from pathlib import Path
import context606 as C
HERE=Path(__file__).resolve().parent

def assemble(ready604,tools606,latest,out):
    ready604,tools606,latest,out=(Path(p).absolute()for p in(ready604,tools606,latest,out));profile=C.obj(HERE/'profile.json');expected=dict(line.split()for line in(HERE/'expected606.lock').read_text().splitlines());base=C.obj(ready604/'manifest.json');rows={r['name']:r for r in base['packages']};C.need(len(rows)==len(base['packages'])==604 and not out.exists()and out.parent.is_dir(),'whole original604 and fresh output');orig606=dict(line.split()for line in(HERE/'original606.lock').read_text().splitlines());held604={n:v for n,v in orig606.items()if n not in('cachy-asahi-dns','cachy-asahi-sysctl')};C.need({n:r['version']for n,r in rows.items()}==held604,'exact original604 source versions');roles=base['preparation']['signer_roles'];where={n:ready604 for n in rows}
    additions=C.obj(tools606/'products.json');C.need(set(additions)=={'cachy-asahi-dns','cachy-asahi-sysctl'},'exact original DNS2/Sysctl2 pair inputs')
    for name,r in additions.items():
        C.need(name not in rows and r['name']==name and r['version']=='0.1.0-2'and r['signer']==roles['ephemeral_TEST'],'exact freshly signed original606 addition');sig=r['signature_pin'];rows[name]=dict(name=name,version=r['version'],archive=r['archive'],size=r['bytes'],sha256=r['sha256'],signature=r['signature'],signature_size=sig['bytes'],signature_sha256=sig['sha256'],signer=r['signer']);where[name]=tools606
    plan=C.obj(latest/'input-plan.json');C.need(plan['status']=='READY_FIVE_EXACT_TOOL_ARCHIVES_FRESH_ORIGINAL_TEST_SIGNATURES'and plan['signer_roles']==roles and plan['actual_source']is plan['actual_ref']is plan['actual_run']is None,'whole same-producer latest input plan remains nonauthority')
    for role,name in [('apps','cachy-asahi-apps'),('doctor','cachy-asahi-doctor'),('ksm','cachy-asahi-ksmctl'),('welcome','cachy-asahi-welcome')]:
        r=plan['products'][role]['latest'];C.need(r['name']==name and r['version']==profile['versions'][name]and r['signer']==roles['ephemeral_TEST']and r['verification']['returncode']==0,'exact same original producer product signature');sig=r['signature'];rows[name]=dict(name=name,version=r['version'],archive='packages/'+r['archive'],size=r['bytes'],sha256=r['sha256'],signature='packages/'+sig['path'],signature_size=sig['bytes'],signature_sha256=sig['sha256'],signer=r['signer']);where[name]=latest/'archives'
    C.need({n:r['version']for n,r in rows.items()}==expected,'only four replacements and two original additions')
    # Validate every original member before making the output, including the
    # existing signed source's original574 builder/key metadata.
    for name,r in rows.items():
        root=where[name]
        for field,size,sha in [('archive','size','sha256'),('signature','signature_size','signature_sha256')]:
            member=Path(r[field]).name if root==latest/'archives'else r[field];C.checked(root,member,r[size],r[sha])
    out.mkdir(mode=0o700)
    for name,r in rows.items():
        root=where[name]
        for field in('archive','signature'):
            member=Path(r[field]).name if root==latest/'archives'else r[field];target=out/r[field];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/member,target)
    for r in base['keyrings']:
        p=C.checked(ready604,r['path'],r['size'],r['sha256']);q=out/r['path'];q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
    shutil.copyfile(ready604/'builder-packages.lock',out/'builder-packages.lock');shutil.copyfile(HERE/'expected606.lock',out/'expected-installed.lock')
    # Retain complete originals separately; no old selected version/project table
    # is mislabeled as the new606 manifest.
    origins={}
    for name,path in [('original604-manifest.json',ready604/'manifest.json'),('original-tools606-products.json',tools606/'products.json'),('original-latest-input-plan.json',latest/'input-plan.json')]:
        raw=C.read(path);(out/name).write_bytes(raw);origins[name]=C.pin(raw)
    preparation=dict(base['preparation'],archive_count=606,compressed_archive_bytes=sum(r['size']for r in rows.values()))
    manifest=dict(schema_version=1,status='READY_SIGNED_CURRENT606_WELCOME7',packages=[rows[n]for n in sorted(rows)],expected_lock=dict(path='expected-installed.lock',sha256=profile['expected606']['sha256']),builder_lock=base['builder_lock'],keyrings=base['keyrings'],preparation=preparation,original_input_pins=origins)
    (out/'manifest.json').write_bytes(C.enc(manifest));return dict(status='ASSEMBLED_EXACT_SIGNED606_INPUTS_ONLY',packages=606,native='NOT_RUN',GUI='NOT_RUN')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in('ready604','tools606','latest','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(assemble(a.ready604,a.tools606,a.latest,a.output),sort_keys=True))
