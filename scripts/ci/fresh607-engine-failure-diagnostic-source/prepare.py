# SPDX-License-Identifier: MIT
"""Pure exact generic16K engine-failure DATA source constructor; never actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 956718, 'sha256': '1c84b993ea16018c724f2a037256a678a4e38690c900b3afded988332621a4c1'}

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


def compose(source):
 source=ordinary(source);own=read_state(HERE/'prepare.py');raw,state=read_state(HERE/'profile.json');need(pin(raw)==PROFILE,'entry-pinned closed profile');p=json.loads(raw)
 need(p['counts']==dict(before=1203,after=1203,held=1196,changed=7,added=0)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and p['acceptance_authority']is False,'closed source-only scope')
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
 need({n:pin(b)for n,b in values.items()}==p['result']['files'],'every exact PUBLIC087c1203 byte')
 need({n for n in before if before[n]!=values[n]}==set(p['changed'])and all(values[n]==before[n]for n in p['held']),'seven changes/all1196 held')
 need(apply(newmode[:-len(c['mode_append'].encode())],c['mode_edits'],reverse=True)==before[mode]and apply(template[:-len(c['guard_append'].encode())],c['guard_edits'],reverse=True).replace(b'@PARENT_SHA@',oldsha.encode(),1)==before[guardname],'whole helper/guard byte inverses')
 restored_test=newtest.replace(c['test_append'].encode()+b'\n'+entry,entry,1);need(apply(restored_test,c['test_edits'],reverse=True)==before[test],'whole original page CI control inverse')
 numeric_before(values,p)
 need(scan(source)==(before,bstate)and all(read_state(HERE/n)==v for n,v in states.items()),'late whole source/operand FD identity/namespace drift')
 return values,p,(before,bstate),states

def emit(source,output,context):
 need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
 need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late all inputs before writes');output.mkdir(mode=0o700)
 for n,b in sorted(values.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact PUBLIC1203 bytes/modes')
 return dict(status='SOURCE_ONLY_NUMERIC_AND_AUTHENTICATION_FAILURE_DATA_NO_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',performance='NOT_MEASURED')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for name in('source','output','context'):parser.add_argument('--'+name,required=True)
 args=parser.parse_args();print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
