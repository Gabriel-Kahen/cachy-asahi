# SPDX-License-Identifier: MIT
"""Exact failed GUI ownership retirement; never a GUI acceptance predicate."""
import base64,hashlib,re

def need(ok,why):
    if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def image(v):return type(v)is str and re.fullmatch('sha256:[a-f0-9]{64}',v)is not None

def plan(containers,images,base,reference,fixture):
    # A late failed GUI has an unambiguous complete resource set. Earlier partial
    # acquisition remains unqualified and conservatively preserves the producer.
    patterns=('desktop574-config-[a-f0-9]{32}','desktop574-fixture-[a-f0-9]{16}','desktop574-vm-[a-f0-9]{16}')
    need(type(containers)is list and len(containers)==3 and all(type(n)is str and re.fullmatch(p,n)for n,p in zip(containers,patterns))and len(set(containers))==3,'complete fixed three-container acquisition')
    need(type(images)is list and len(images)==2 and len(set(images))==2 and all(image(v)for v in images)and image(base)and base not in images,'two exact owned images and distinct borrowed base')
    need(type(reference)is str and re.fullmatch('cachy-asahi-desktop574-base:[a-f0-9]{32}',reference)and fixture is True,'exact owned alias and fixture acquisition')
    return dict(schema_version=1,containers=list(containers),images=list(images),base_image=base,base_reference=reference,fixture=True)

def output(raw):
    need(type(raw)is bytes and len(raw)<=65536,'bounded complete cleanup stdout')
    return dict(stdout=pin(raw),stdout_base64=base64.b64encode(raw).decode())

def raw(row):
    need(type(row)is dict and type(row.get('exit'))is int and row['exit']==0 and 'error'not in row,'successful actual cleanup command')
    b=base64.b64decode(row['stdout_base64'],validate=True);need(len(b)<=65536 and pin(b)==row['stdout'],'complete cleanup stdout identity');return b

def retired(value):
    need(type(value)is dict and value.get('status')=='FAIL','failed GUI only; cleanup errors and positive status cannot enter failure gate')
    p=value['resource_acquisition'];need(type(p)is dict and set(p)=={'schema_version','containers','images','base_image','base_reference','fixture'}and p==plan(p['containers'],p['images'],p['base_image'],p['base_reference'],p['fixture'])and p['schema_version']==1,'source-owned exact acquisition state')
    need(value['base_image']==p['base_image']and value['base_reference']==p['base_reference']and [value['runtime_image'],value['controller_image']]==p['images'],'runtime and acquisition identity join')
    rows=value['cleanup'];need(type(rows)is list and len(rows)==15,'all fifteen acquired-resource cleanup rows')
    actions=[]
    for n in reversed(p['containers']):actions += ['remove-container:'+n,'check-container:'+n]
    actions += ['remove-image:'+n for n in p['images']]+['remove-fixture','remove-cleaner',None,'check-base-alias','remove-base-alias','check-base-alias-absent','check-base-image-after-alias']
    need([r.get('action')for r in rows]==actions and rows[10]=={'guest_disk_removed':True},'ordered exact retirement of every acquired resource')
    for i,r in enumerate(rows):
        if i!=10:raw(r)
    need(all(raw(rows[i])==b''for i in(1,3,5,13)),'fresh exact container and alias absence outputs')
    need(raw(rows[11]).decode().splitlines()==[p['base_image']],'owned alias still bound to selected borrowed image before release')
    listed=raw(rows[14]).decode().splitlines();need(all(image(v)for v in listed)and p['base_image']in listed and not set(p['images'])&set(listed),'fresh borrowed base present and both owned images absent')
    need(value['base_reference_cleanup']==dict(ok=True,base_image_present=True),'original alias release verifies borrowed base preserved')
    return dict(status='PASS_FAILED_GUI_OWNED_RESOURCE_RETIREMENT_ONLY',GUI='FAILED_NOT_ACCEPTED',images=p['images'],containers=p['containers'],base_image=p['base_image'],base_reference=p['base_reference'],producer='BORROWED_NOT_REMOVED')
