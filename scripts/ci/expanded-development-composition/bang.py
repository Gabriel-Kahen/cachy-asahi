# SPDX-License-Identifier: MIT
"""Two clean offline574 builds using the accepted build function's shell path adapter."""
import ast
import inspect
import json
from pathlib import Path
import types
import contract as C
import inputs

SOURCES={
 'usr/share/cachy-asahi/fish-bang-bang/'+n:n for n in
 ('__history_previous_command.fish','__history_previous_command_arguments.fish','opt-in.fish')}
SOURCES['usr/share/cachy-asahi/fish-bang-bang/README.md']='usage.md'
SOURCES.update({'usr/share/licenses/'+C.UPGRADE+'/'+n:n for n in ('NOTICE','LICENSE.upstream','LICENSE.project')})


def recipe(source,policy,checks):
    root=source/'packages/shells'/C.UPGRADE
    bound=policy['bang_inputs']
    C.need(type(bound) is dict and bound and set(bound)=={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()},
           'exact bang recipe closure required')
    for name,digest in bound.items():
        C.relative(name);C.need(C.sha(C.safe(root/name))==digest,'bang source input differs')
    reviewed=checks.recipe(root/'PKGBUILD')
    C.need(not reviewed['errors'] and reviewed['input_sha256']==bound and
           reviewed['metadata'].get('pkgname')==[C.UPGRADE] and reviewed['metadata'].get('pkgver')==['0.1.0'] and
           reviewed['metadata'].get('pkgrel')==['2'] and reviewed['metadata'].get('arch')==['any'] and
           reviewed['metadata'].get('license')==['MIT'] and reviewed['metadata'].get('depends')==['fish>=4.0'] and
           not any(reviewed['metadata'].get(k) for k in ('install','conflicts','replaces','backup')),
           'bang2 recipe/metadata differs')
    return reviewed


def payload(report,source,name):
    C.need(name==C.UPGRADE and not report['errors'] and not report['elf'],'ordinary bang2 shell package required')
    actual={p:n for p,n in report['members'].items() if n['type']!='5' and p not in inputs.META}
    C.need(set(actual)==set(SOURCES),'exact seven bang2 installed members required')
    for path,node in actual.items():
        sourcefile=source/'packages/shells'/name/SOURCES[path]
        C.need(node['type']=='0' and node['mode']==0o644 and node['uid']==node['gid']==0 and
               node['sha256']==C.sha(sourcefile) and node['size']==sourcefile.stat().st_size and not node['link'],
               'bang2 source/license payload differs')
    return actual


def build(source,code,out,base,image,lock,epoch,policy,execute):
    checks,bind=inputs.tools(code);reviewed=recipe(source,policy,checks)
    original=C.load('expanded_accepted_builder',code/'scripts/ci/welcome-native/run.py')
    text=inspect.getsource(original.build)
    old="source/'packages/tools'/name";new="source/'packages/shells'/name"
    C.need(text.count(old)==1,'accepted fixed recipe path anchor changed')
    tree=ast.parse(text.replace(old,new))
    C.need(len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef) and tree.body[0].name=='build',
           'accepted build function AST shape differs')
    bridge=types.SimpleNamespace(need=C.need,verify_source=lambda s:recipe(s,policy,checks),
        recipe=lambda s,n:reviewed,digest=C.sha,payload=payload,NAME='NO_ELF_BRANCH',
        check_log=lambda log,n:dict(status='PASS_MAKEPKG_CHECK_EXIT',log_sha256=C.sha(log)))
    namespace=dict(C=bridge,save=original.save,shutil=original.shutil,os=original.os,docker=original.docker,
                   subprocess=original.subprocess,tarfile=original.tarfile,inventory=original.inventory)
    exec(compile(tree,'<accepted-build-shell-path-adapter>','exec'),namespace)
    containers=[]
    pair=[namespace['build'](source,out,base,image,lock,C.UPGRADE,side,epoch,execute,containers,checks,bind)
          for side in ('a','b')]
    comparison=C.load('expanded_build_compare',code/'scripts/build/compare.py').compare(*(r['directory'] for r in pair))
    C.need(comparison['status']=='contents-reproduced' and not comparison['errors'] and
           len(comparison['packages'])==1 and all(r['bytes_equal'] and r['buildinfo_equal'] and
           r['installed_contents_equal'] and r['pkginfo_equal'] for r in comparison['packages'].values()),
           'bang2 whole bytes/BUILDINFO/payload differ')
    original.save(out/'bang-comparison.json',comparison)
    first=pair[0]['archive'];report=checks.package(first)
    return dict(name=C.UPGRADE,version=C.NEW,pair_status='PASS_BYTES_AND_BUILDINFO_IDENTICAL',root=str(out),
        archive_ref=dict(path=str(first.relative_to(out)),bytes=first.stat().st_size,sha256=C.sha(first)),
        inspected=report)
