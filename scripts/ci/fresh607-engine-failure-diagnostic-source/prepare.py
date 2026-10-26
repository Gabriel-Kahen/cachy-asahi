# SPDX-License-Identifier: MIT
"""Pure exact generic16K engine-failure DATA source constructor; never actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 1682757, 'sha256': '4af896dc044a15aefdb400be81202f81852b7a38d546a438587b36674ea8a23f'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw),
         'absolute normalized path required')
    path = Path(raw)
    need(str(path)==raw and path == path.resolve(), 'canonical resolved path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path

def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read_state(value):
    path = ordinary(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= (16 if path.name == "page-parent.json" else 8) * 1024**2, 'bounded ordinary single-link source file')
        parts, size = [], 0
        while part := os.read(fd, 1024**2):
            parts.append(part)
            size += len(part)
            need(size <= before.st_size, 'source file grew during read')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole stable descriptor and path identity')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)

def read(path):
    return read_state(path)[0]

def scan(value):
    root = ordinary(value)
    need(root.is_dir(), 'ordinary source root required')
    files, state, directories = {}, {}, {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(not path.is_symlink(), 'source alias refused')
        name = path.relative_to(root).as_posix() if path != root else ''
        if stat.S_ISDIR(info.st_mode):
            directories[name] = (identity(info), tuple(sorted(p.name for p in path.iterdir())))
        else:
            raw, record = read_state(path)
            files[name], state[name] = raw, record
    required = {''}
    for name in files:
        required.update('' if str(p) == '.' else p.as_posix() for p in Path(name).parents)
    need(set(directories) == required, 'closed source directory membership, no foreign empty dirs')
    for name, (record, names) in directories.items():
        path = root / name
        need(identity(path.lstat()) == record and
             tuple(sorted(p.name for p in path.iterdir())) == names, 'stable whole source namespace')
    return files, dict(files=state, directories=directories)

def tree(root):
    return scan(root)[0]

def paths(source, output):
    source, output = ordinary(source), ordinary(output)
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied source/factory/output paths')
    return source, output

def apply(raw,rows,reverse=False):
    for a,b in(reversed(rows)if reverse else rows):
        old,new=(b.encode(),a.encode())if reverse else(a.encode(),b.encode())
        need(old and raw.count(old)==1,'one exact readable source seam')
        raw=raw.replace(old,new,1)
    return raw

def numeric_before(values,p):
 """Finite whole417c before inverse, using only closed scalar source DATA."""
 if 'realtime_initialization'in json.loads(values['implementation/page-parent.json'])['engine_failure_parent']:values=clock_before(values,p)
 parentname='implementation/page-parent.json';guard='implementation/page_source.py';mode='implementation/page_mode.py';test='implementation/test_page_mode.py'
 parent=json.loads(values[parentname]);e=parent['engine_failure_parent'];a=e.pop('authentication_diagnostic')
 for k,v in a['engine_fields_before'].items():e[k]=v
 parent['guard_template']=a['guard_template']
 for n,w in a['products_before'].items():parent['products'][n]=w
 before=dict(values);before[parentname]=encoded(parent)
 for n,b in a['before_bodies'].items():need(n in(mode,test),'closed two numeric before modules');before[n]=b.encode()
 raw=values[guard];old=pin(values[parentname])['sha256'].encode();new=pin(before[parentname])['sha256'].encode()
 need(raw.count(old)==1 and raw.count(a['guard_proof'].encode())==1,'one numeric guard/selfseal inverse');before[guard]=raw.replace(old,new,1).replace(a['guard_proof'].encode(),b'',1)
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in before.items()if n not in('source-manifest.json',*aliases)};before['source-manifest.json']=encoded(manifest)
 for n in aliases:before[n]=values['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',pin(before['source-manifest.json'])['sha256'].encode(),1)
 need(len(before)==1203 and {n:pin(b)for n,b in before.items()}==p['numeric_parent']['files']==a['files'],'entire exact PUBLIC417c before inverse')
 return before



def abi_before(values,p):
 if 'implementation/storage-parent.json'in values:values=storage_before(values,p)
 """Pure DATA reconstruction of all exact public95a75 before bytes."""
 out=dict(values);pn='implementation/page-parent.json';gn='implementation/page_source.py';parent=json.loads(values[pn]);r=parent['engine_failure_parent'].pop('alpm_type_origin');need(r['source']=='95a75cd9798b8b827f80233f3ea402ff7fc9b224'and r['files']==p['abi_parent']['files']and all(r[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'closed whole95a75 ABI parent')
 parent['guard_template']=r['guard_template']
 for n,w in r['products_before'].items():parent['products'][n]=w
 out[pn]=encoded(parent)
 for role,name in(('mode','implementation/page_mode.py'),('test','implementation/test_page_mode.py')):
  raw=values[name];tail=r[role+'_append'].encode()
  if role=='mode':
   if tail:need(raw.endswith(tail),'whole ABI mode append inverse');raw=raw[:-len(tail)]
  else:
   entry=b"if __name__=='__main__':\n";insert=tail+b'\n'+entry;need(tail and raw.count(insert)==1,'one exact ABI test insertion');raw=raw.replace(insert,entry,1)
  out[name]=apply(raw,r[role+'_edits'],reverse=True)
 raw=values[gn];newsha=pin(values[pn])['sha256'];tail=r['guard_append'].encode();need(raw.count(newsha.encode())==1 and raw.endswith(tail),'whole ABI guard/seal inverse');raw=raw.replace(newsha.encode(),pin(out[pn])['sha256'].encode(),1);out[gn]=apply(raw[:-len(tail)],r['guard_edits'],reverse=True)
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n not in('source-manifest.json',*aliases)};out['source-manifest.json']=encoded(manifest)
 for n in aliases:out[n]=values['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',pin(out['source-manifest.json'])['sha256'].encode(),1)
 need(len(out)==1203 and {n:pin(b)for n,b in out.items()}==r['files'],'ENTIRE exact95a75 source before inverse');return out

def abi_stage(values,p,operands):
 """Exactly two selected16K Ptr origin operands; raw/default4K bodies held."""
 mode,test,gn,pn='implementation/page_mode.py','implementation/test_page_mode.py','implementation/page_source.py','implementation/page-parent.json';r=json.loads(operands['abi-context.json']);need(r['source']==p['abi_parent']['source']and {n:pin(b)for n,b in values.items()}==p['abi_parent']['files']and r['scope']=='SELECTED16K_TWO_ALPM_ORIGIN_PTR_ALLOCATIONS_RAW_4K_HELD'and all(r[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'whole exact95a75 source-only ABI stage')
 r['files']=p['abi_parent']['files'];r['git']['files']=r['files'];r['test_append']=operands['abi-tests.py.txt'].decode();r['guard_append']=operands['abi-guard.py.txt'].decode();parent=json.loads(values[pn]);need(parent['guard_template']==r['guard_template']and {n:parent['products'][n]for n in(mode,test)}==r['products_before'],'exact old95a75 products/guard')
 newmode=apply(values[mode],r['mode_edits']);need(not r['mode_append'],'no ABI runtime helper append');newtest=apply(values[test],r['test_edits']);entry=b"if __name__=='__main__':\n";need(newtest.count(entry)==1,'one actual ABI CI entry');newtest=newtest.replace(entry,r['test_append'].encode()+b'\n'+entry,1);oldsha=pin(values[pn])['sha256'];need(values[gn].count(oldsha.encode())==1,'one old95a75 seal');template=apply(values[gn].replace(oldsha.encode(),b'@PARENT_SHA@',1),r['guard_edits'])+r['guard_append'].encode();parent['engine_failure_parent']['alpm_type_origin']=r;parent['products'][mode]=pin(newmode);parent['products'][test]=pin(newtest);parent['guard_template']=pin(template);raw=encoded(parent);need(len(raw)<16*1024**2 and template.count(b'@PARENT_SHA@')==1,'held16MiB parent bound and exact ABI seal')
 out=dict(values);out.update({mode:newmode,test:newtest,pn:raw,gn:template.replace(b'@PARENT_SHA@',pin(raw)['sha256'].encode(),1)});aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n not in('source-manifest.json',*aliases)};out['source-manifest.json']=encoded(manifest)
 for n in aliases:out[n]=values['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',pin(out['source-manifest.json'])['sha256'].encode(),1)
 need(abi_before(out,p)==values,'complete immediate95a75 ABI stage inverse');return out

def clock_stage(values,p,operands):
 """Finite selected clock stage after complete engine/numeric/authentication."""
 mode,test,guard,pn='implementation/page_mode.py','implementation/test_page_mode.py','implementation/page_source.py','implementation/page-parent.json'
 r=json.loads(operands['clock-context.json']);need(r['source']==p['authentication_parent']['source']and r['scope']=='SOURCE_OWNED_SELECTED16K_REALTIME_CURRENT_HOST_LAUNCH_NONCE_SOURCE_RUN_WORKSPACE_NO_GPG_WAIVER'and all(r[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'closed selected clock source-only scope')
 need({n:pin(b)for n,b in values.items()}==p['authentication_parent']['files'],'complete exact PUBLIC087c before clock stage')
 r['files']=p['authentication_parent']['files'];r['git']['files']=r['files'];r['mode_append']=operands['clock-mode.py.txt'].decode()+"\nCLOCK_HOST="+repr(operands['clock-host.py.txt'].decode())+"\nCLOCK_GUEST="+repr(operands['clock-guest.py.txt'].decode())+'\n';r['guard_append']=operands['clock-guard.py.txt'].decode();r['test_append']=operands['clock-tests.py.txt'].decode()
 parent=json.loads(values[pn]);need(r['guard_template']==parent['guard_template']and r['products_before']=={n:parent['products'][n]for n in(mode,test)},'exact087c products/selfseal before clock stage')
 newmode=apply(values[mode],r['mode_edits'])+r['mode_append'].encode();newtest=apply(values[test],r['test_edits']);entry=b"if __name__=='__main__':\n";need(newtest.count(entry)==1,'one clock CI entry');newtest=newtest.replace(entry,r['test_append'].encode()+b'\n'+entry,1)
 oldsha=pin(values[pn])['sha256'];need(values[guard].count(oldsha.encode())==1,'one087c guard seal');template=apply(values[guard].replace(oldsha.encode(),b'@PARENT_SHA@',1),r['guard_edits'])+r['guard_append'].encode()
 parent['engine_failure_parent']['realtime_initialization']=r;parent['products'][mode]=pin(newmode);parent['products'][test]=pin(newtest);parent['guard_template']=pin(template);raw=encoded(parent);need(len(raw)<16*1024**2 and template.count(b'@PARENT_SHA@')==1,'held parent cap and exact current seal')
 result=dict(values);result.update({mode:newmode,test:newtest,pn:raw,guard:template.replace(b'@PARENT_SHA@',pin(raw)['sha256'].encode(),1)})
 workflow=apply(values['implementation/workflow-template.yml'],r['workflow_edits']);result['implementation/workflow-template.yml']=workflow
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in result.items()if n not in('source-manifest.json',*aliases)};result['source-manifest.json']=encoded(manifest)
 for n in aliases:result[n]=workflow.replace(b'@FRESH607_MANIFEST@',pin(result['source-manifest.json'])['sha256'].encode(),1)
 need(clock_before(result,p)==values,'whole087c stage inverse');return result

def clock_before(values,p):
 """Complete087c source reconstruction, no historical tree or code execution."""
 if 'alpm_type_origin'in json.loads(values['implementation/page-parent.json'])['engine_failure_parent']:values=abi_before(values,p)
 before=dict(values);pn='implementation/page-parent.json';guard='implementation/page_source.py';parent=json.loads(values[pn]);r=parent['engine_failure_parent'].pop('realtime_initialization');need(r['files']==p['authentication_parent']['files'],'closed087c before map')
 parent['guard_template']=r['guard_template']
 for n,w in r['products_before'].items():parent['products'][n]=w
 before[pn]=encoded(parent)
 for role,n in(('mode','implementation/page_mode.py'),('test','implementation/test_page_mode.py')):
  raw=values[n];tail=r[role+'_append'].encode();need(tail,'nonempty clock helper/control append')
  if role=='mode':need(raw.endswith(tail),'whole clock footer inverse');raw=raw[:-len(tail)]
  else:
   entry=b"if __name__=='__main__':\n";added=tail+b'\n'+entry;need(raw.count(added)==1,'one clock CI insertion inverse');raw=raw.replace(added,entry,1)
  before[n]=apply(raw,r[role+'_edits'],reverse=True)
 raw=values[guard];newsha=pin(values[pn])['sha256'];need(raw.count(newsha.encode())==1 and raw.endswith(r['guard_append'].encode()),'complete clock guard/footer inverse');raw=raw.replace(newsha.encode(),pin(before[pn])['sha256'].encode(),1);before[guard]=apply(raw[:-len(r['guard_append'].encode())],r['guard_edits'],reverse=True)
 workflow=apply(values['implementation/workflow-template.yml'],r['workflow_edits'],reverse=True);before['implementation/workflow-template.yml']=workflow
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in before.items()if n not in('source-manifest.json',*aliases)};before['source-manifest.json']=encoded(manifest)
 for n in aliases:before[n]=workflow.replace(b'@FRESH607_MANIFEST@',pin(before['source-manifest.json'])['sha256'].encode(),1)
 need(len(before)==1203 and {n:pin(b)for n,b in before.items()}==r['files'],'whole exact PUBLIC087c before clock source');return before


def storage_before(values,p):
 """Reconstruct all exact public0db934 bytes from the sealed1206 successor."""
 need(set(values)==set(p['storage_parent']['files'])|{'implementation/storage_source.py','implementation/storage-parent.json','implementation/test_storage.py'},'closed storage1206 namespace')
 need({n:pin(b)for n,b in values.items()}==p['result']['files'],'every exact current1206 byte before inversion')
 raw=values['implementation/storage-parent.json'];need(pin(raw)==p['operands']['storage-context.json'],'exact source-owned storage context')
 c=json.loads(raw)
 need(c['source']==p['storage_parent']['source']=='0db9341521b5cb5d9022715b5ba638b3e4018462'and c['files']==p['storage_parent']['files']and
      all(c[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and c['scope']=='FRESH607_TARGET_ALLOCATION_ADMISSION_ORIGINAL512M_AND10000_MARGINS','whole exact0db source-only storage parent')
 seal=pin(raw)['sha256'];guard=values['implementation/storage_source.py'];need(guard.count(seal.encode())==1 and pin(guard.replace(seal.encode(),b'@STORAGE_CONTEXT_SHA@',1))==c['guard_template'],'entire storage guard selfseal')
 out={n:values[n]for n in c['files']}
 helper=c['helper'].encode();after=c['capacity_after'].encode();before=c['capacity_before'].encode();body=out['parent604/installer.py']
 need(body.count(helper)==body.count(after)==1,'one exact storage helper and capacity call site');out['parent604/installer.py']=body.replace(helper,b'',1).replace(after,before,1)
 mapping=json.loads(out['parent604-map.json']);mapping['installer.py']=c['files']['parent604/installer.py'];out['parent604-map.json']=encoded(mapping)
 for n,edits in c['edits'].items():out[n]=apply(out[n],edits,reverse=True)
 profile=json.loads(out['implementation/profile.json']);need(profile.pop('storage_admission')==c['profile'],'entire original profile inverse and11 storage fields');out['implementation/profile.json']=encoded(profile)
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
 manifest=json.loads(out['source-manifest.json']);manifest['files']={n:w for n,w in c['files'].items()if n not in('source-manifest.json',*aliases)};out['source-manifest.json']=encoded(manifest)
 for n in aliases:out[n]=out['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',pin(out['source-manifest.json'])['sha256'].encode(),1)
 need(len(out)==1203 and {n:pin(b)for n,b in out.items()}==c['files'],'ENTIRE public0db9341203 before inverse')
 return out

def storage_stage(values,p,operands):
 """Pure DATA extension of the unchanged maintained ABI factory result."""
 need({n:pin(b)for n,b in values.items()}==p['storage_parent']['files'],'entire exact ABI934 intermediate')
 raw=operands['storage-context.json'];c=json.loads(raw)
 need(c['files']==p['storage_parent']['files']and c['source']==p['storage_parent']['source']=='0db9341521b5cb5d9022715b5ba638b3e4018462'and
      c['scope']=='FRESH607_TARGET_ALLOCATION_ADMISSION_ORIGINAL512M_AND10000_MARGINS'and all(c[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'closed exact storage parent and NULL actual scope')
 fields=['allocation_unit_bytes','capacity_reserved','directory_estimate_bytes','free_bytes','free_inodes','payload_bytes','required_bytes','required_inodes','reserve_bytes','rounded_file_bytes','symlink_estimate_bytes']
 need(c['profile']==dict(schema_version=1,purpose='fresh607-target-allocation-admission',fields=fields,reserve_bytes=512*1024**2,inode_margin=10000,allocation='max-filesystem-block-fragment',capacity_reserved=False,pages=['generic4k','generic16k'],native='NOT_RUN',hardware='NOT_RUN'),'exact11-field storage profile and held margins')
 body=values['parent604/installer.py'];a=c['capacity_before'].encode();b=c['capacity_after'].encode();entry=b'def engine(spec_fd,spec_pin,evidence_fd):'
 need(body.count(a)==body.count(entry)==1,'one exact original capacity and engine seam')
 out=dict(values);out['parent604/installer.py']=body.replace(a,b,1).replace(entry,c['helper'].encode()+entry,1)
 mapping=json.loads(values['parent604-map.json']);mapping['installer.py']=pin(out['parent604/installer.py']);out['parent604-map.json']=encoded(mapping)
 profile=json.loads(values['implementation/profile.json']);need('storage_admission'not in profile and profile['clocks']==c['clocks'],'unchanged original profile/clocks before storage');profile['storage_admission']=c['profile'];out['implementation/profile.json']=encoded(profile)
 for n,edits in c['edits'].items():out[n]=apply(out[n],edits)
 guard=operands['storage-guard.py.txt'];need(pin(guard)==c['guard_template']and guard.count(b'@STORAGE_CONTEXT_SHA@')==1,'entry-pinned readable storage guard template')
 out.update({'implementation/storage_source.py':guard.replace(b'@STORAGE_CONTEXT_SHA@',pin(raw)['sha256'].encode(),1),'implementation/storage-parent.json':raw,'implementation/test_storage.py':operands['storage-tests.py.txt']})
 need({n:pin(out[n])for n in c['products']}==c['products'],'all exact finite storage products and emitted controls')
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(values['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n not in('source-manifest.json',*aliases)};out['source-manifest.json']=encoded(manifest)
 for n in aliases:out[n]=out['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',pin(out['source-manifest.json'])['sha256'].encode(),1)
 need(storage_before(out,p)==values,'whole immediate0db934 storage stage inverse')
 return out


def compose(source):
 source=ordinary(source);own=read_state(HERE/'prepare.py');raw,state=read_state(HERE/'profile.json');need(pin(raw)==PROFILE,'entry-pinned closed profile');p=json.loads(raw)
 need(p['counts']==dict(before=1203,after=1206,held=1189,changed=14,added=3)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and p['acceptance_authority']is False,'closed source-only scope')
 before,bstate=scan(source);need({n:pin(b)for n,b in before.items()}==p['parent']['files'],'exact whole PUBLIC7bbdf1203 source required')
 operands={};states={'prepare.py':own,'profile.json':(raw,state)}
 for name,w in p['operands'].items():
  body,record=read_state(HERE/name);need(pin(body)==w,'fixed readable operand '+name);operands[name]=body;states[name]=(body,record)
 c=json.loads(operands['engine-context.json']);need(c['source']==p['parent']['source']and c['ref']==p['parent']['ref']and c['scope']=='GENERIC16K_EXACT_NUMERIC_PLATFORM_AND_RETURNED_ENGINE_DATA_NO_ACCEPTANCE'and all(c[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'historical SOURCE_DATA only, never current authority')
 mode,test,guardname,parentname=('implementation/page_mode.py','implementation/test_page_mode.py','implementation/page_source.py','implementation/page-parent.json');parent=json.loads(before[parentname]);oldsha=pin(before[parentname])['sha256']
 need(c['guard_template']==parent['guard_template']and c['products_before']=={n:parent['products'][n]for n in(mode,test)},'exact old products and guard operands')
 a=c.pop('engine_guard_operand');wrapped='        try:\n'+''.join('    '+line+'\n'for line in a.splitlines())+"        except BaseException:\n            result['engine_failure_data']=engine_failure_projection(receipt)\n            raise\n"
 footer=operands['mode-footer.py.txt'].decode();numeric_footer=footer
 for seam in (" out=edit(out,AUTH_COMMAND,AUTH_COMMAND_DATA)\n"," raw=edit(raw,AUTH_COMMAND_DATA,AUTH_COMMAND)\n"):
  need(numeric_footer.count(seam)==1,'one authentication transform/inverse seam');numeric_footer=numeric_footer.replace(seam,'',1)
 need(numeric_footer.count('+AUTH_HELPER')==2,'two exact helper append/inverse seams');numeric_footer=numeric_footer.replace('+AUTH_HELPER','')
 numeric_tail='\nNUMERIC_HELPER='+repr(operands['numeric-helper.py.txt'].decode())+'\nNUMERIC_RETURN='+repr('    return roots,roots.installer,driver,aux')+'\nNUMERIC_SELECTED_RETURN='+repr('    return roots,numeric16k_installer(code,profile),driver,aux')+'\n'
 engine_tail='\nENGINE_GUARD='+repr(a)+'\nENGINE_GUARD_DIAGNOSTIC='+repr(wrapped)+'\nENGINE_HELPER='+repr(operands['engine-helper.py.txt'].decode())+'\n'
 command=c.pop('auth_command_operand');failure="        if row.returncode!=0:\n            try:\n                result['authentication_failure_data']=authentication_failure_projection(argv,row)\n                evidence.save('result.json',result)\n            except BaseException:\n                pass  # Failure-only diagnostics never replace the original refusal.\n"+command
 auth_tail='\nAUTH_COMMAND='+repr(command)+'\nAUTH_COMMAND_DATA='+repr(failure)+'\nAUTH_HELPER='+repr(operands['authentication-helper.py.txt'].decode())+'\n'
 c['mode_append']=footer+numeric_tail+engine_tail+auth_tail
 c['guard_append']=operands['guard-footer.py.txt'].decode();c['test_append']=operands['caller-controls.py.txt'].decode();c['files']=p['parent']['files'];c['git']['files']=p['parent']['files'];c['before_bodies']={n:before[n].decode()for n in(mode,test)}
 auth=c['authentication_diagnostic'];need(auth['source']==p['numeric_parent']['source'],'closed exact current numeric source DATA')
 numeric_edits=[[old,new.replace(auth['guard_proof'],'')]for old,new in c['guard_edits']]
 numeric_test_edits=[[old,new.replace('suite.countTestCases()==18','suite.countTestCases()==14')]for old,new in c['test_edits']]
 marker='\ndef authentication_command_fixture(';need(c['test_append'].count(marker)==1,'one actual authentication caller control group');numeric_tests=c['test_append'].split(marker,1)[0]
 numeric_mode=apply(before[mode],c['mode_edits'])+(numeric_footer+numeric_tail+engine_tail).encode()
 numeric_test=apply(before[test],numeric_test_edits);entry=b"if __name__=='__main__':\n";need(numeric_test.count(entry)==1,'one numeric CI entry');numeric_test=numeric_test.replace(entry,numeric_tests.encode()+b'\n'+entry,1)
 auth['files']=p['numeric_parent']['files'];auth['git']['files']=p['numeric_parent']['files'];auth['before_bodies']={mode:numeric_mode.decode(),test:numeric_test.decode()};auth['engine_fields_before']=dict(guard_edits=numeric_edits,mode_append=numeric_footer+numeric_tail+engine_tail,test_append=numeric_tests,test_edits=numeric_test_edits)
 need(pin(numeric_mode)==auth['files'][mode]and pin(numeric_test)==auth['files'][test],'exact417c helpers/CI controls before authentication source')
 newmode=apply(before[mode],c['mode_edits'])+c['mode_append'].encode();newtest=apply(before[test],c['test_edits']);entry=b"if __name__=='__main__':\n";need(newtest.count(entry)==1,'one actual page CI entry');newtest=newtest.replace(entry,c['test_append'].encode()+b'\n'+entry,1)
 guard=before[guardname];need(guard.count(oldsha.encode())==1,'one original guard seal');template=apply(guard.replace(oldsha.encode(),b'@PARENT_SHA@',1),c['guard_edits'])+c['guard_append'].encode()
 parent['engine_failure_parent']=c;parent['products'][mode]=pin(newmode);parent['products'][test]=pin(newtest);parent['guard_template']=pin(template);praw=encoded(parent);need(len(praw)<16*1024**2 and template.count(b'@PARENT_SHA@')==1,'original parent16MiB cap and exact guard seal')
 values=dict(before);values.update({mode:newmode,test:newtest,parentname:praw,guardname:template.replace(b'@PARENT_SHA@',pin(praw)['sha256'].encode(),1)})
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in values.items()if n not in('source-manifest.json',*aliases)};values['source-manifest.json']=encoded(manifest);workflow=before['implementation/workflow-template.yml'];need(workflow.count(b'@FRESH607_MANIFEST@')==1,'one unchanged workflow seal')
 for name in aliases:values[name]=workflow.replace(b'@FRESH607_MANIFEST@',pin(values['source-manifest.json'])['sha256'].encode(),1)
 need({n:pin(b)for n,b in values.items()}==p['authentication_parent']['files'],'every exact PUBLIC087c1203 byte')

 need(apply(newmode[:-len(c['mode_append'].encode())],c['mode_edits'],reverse=True)==before[mode]and apply(template[:-len(c['guard_append'].encode())],c['guard_edits'],reverse=True).replace(b'@PARENT_SHA@',oldsha.encode(),1)==before[guardname],'whole helper/guard byte inverses')
 restored_test=newtest.replace(c['test_append'].encode()+b'\n'+entry,entry,1);need(apply(restored_test,c['test_edits'],reverse=True)==before[test],'whole original page CI control inverse')
 numeric_before(values,p)
 values=clock_stage(values,p,operands)
 need({n:pin(b)for n,b in values.items()}==p['abi_parent']['files'],'entire exact95a75 clock intermediate');values=abi_stage(values,p,operands)
 need({n:pin(b)for n,b in values.items()}==p['storage_parent']['files'],'entire public0db934 ABI intermediate')
 values=storage_stage(values,p,operands)
 need({n:pin(b)for n,b in values.items()}==p['result']['files']and{n for n in before if before[n]!=values[n]}==set(p['changed'])and set(values)-set(before)==set(p['added'])and all(values[n]==before[n]for n in p['held']),'entire public1e7771206 and all1189 held')
 need(scan(source)==(before,bstate)and all(read_state(HERE/n)==v for n,v in states.items()),'late whole source/operand FD identity/namespace drift')
 return values,p,(before,bstate),states

def emit(source,output,context):
 need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
 need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late all inputs before writes');output.mkdir(mode=0o700)
 for n,b in sorted(values.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact PUBLIC1206 bytes/modes')
 return dict(status='SOURCE_ONLY_FRESH607_STORAGE_ALLOCATION_FACTORY_NO_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',native='NOT_RUN',performance='NOT_MEASURED')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for name in('source','output','context'):parser.add_argument('--'+name,required=True)
 args=parser.parse_args();print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
