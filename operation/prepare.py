# SPDX-License-Identifier: MIT
"""Emit a complete source245 plus separate operation capsule; never execute actors."""
import argparse,os,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as X


def emit(source,output,profile_sha,context):
    X.need(context in('known','null'),'explicit source-only context')
    source,output=map(X.canonical,(source,output))
    X.need(output.parent.is_dir()and not os.path.lexists(output),'fresh capsule output')
    X.need(not any('native-actual'in p.name for p in(output,*output.parents)),'actual namespace protected')
    for root in(source,X.HERE):X.need(not output.is_relative_to(root)and not root.is_relative_to(output),'source/operation/output disjoint')
    p=X.verify(source,profile_sha);source_rows=X.tree(source);operation_rows=X.tree(X.HERE)
    values={}
    for prefix,root,rows in(('source',source,source_rows),('operation',X.HERE,operation_rows)):
        for name,w in rows.items():
            raw=X.read(root/name);X.need(X.pin(raw)==w,'complete capsule source leaf');values[prefix+'/'+name]=raw
    X.need(X.verify(source,profile_sha)==p and X.tree(source)==source_rows and X.tree(X.HERE)==operation_rows,'late capsule source drift')
    with tempfile.TemporaryDirectory(prefix='apps16-interruption-stage-',dir=output.parent)as temporary:
        stage=Path(temporary)/'capsule';stage.mkdir(mode=0o700)
        for name,raw in values.items():
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb')as stream:stream.write(raw);os.fchmod(stream.fileno(),0o644)
        X.need(X.tree(stage)=={n:X.pin(b)for n,b in values.items()},'complete staged capsule')
        X.need(not os.path.lexists(output),'late capsule output collision');os.rename(stage,output)
    return dict(status='SOURCE_ONLY_COMPLETE245_PLUS_SEPARATE_OPERATION_NOT_EXECUTED',operation=X.OPERATION,source=X.SOURCE if context=='known'else None,ref='codex/apps16-repair-inspect1800-v1'if context=='known'else None,files={n:X.pin(b)for n,b in values.items()},operation_profile_sha256=profile_sha,actual=None,Root_acceptance=None,native='NOT_RUN',hardware='NOT_RUN')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in('source','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--operation-profile-sha256',required=True);p.add_argument('--context',choices=('known','null'),required=True)
    args=p.parse_args();value=emit(args.source,args.output,args.operation_profile_sha256,args.context)
    print(X.encoded(value).decode(),end='')

if __name__=='__main__':main()
