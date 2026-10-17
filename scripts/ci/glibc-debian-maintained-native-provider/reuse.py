# SPDX-License-Identifier: MIT
"""Counted adaptations of pinned cleanup/retention; no old admission entrypoint."""
import ast,hashlib,importlib.util
LABEL='org.cachy-asahi.glibc-debian-maintained-provider.job'
PACKAGE='cachy-asahi-glibc-gnu-provider-2.43.caa3-1-aarch64.pkg.tar.xz'
OWNER_SHA='81fdb4a33e77ba6ad4fdf0358107603dfc9f583b8fa47dfd571ce717665202e3'
CHANGES=(
 ('def retain(workspace,base,runtime,bundle,proof,cleanup_path,output):','def retain(workspace,base,runtime,bundle,proof,cleanup_path,output,harness):'),
 ("    harness=workspace/'scripts/ci/glibc-gnu-provider'\n",''),
 ("name=='glibc-2.43.tar.gz'","name in ('glibc_2.43.orig.tar.xz','sid-Sources.xz')"),
 ('PASS_UNSELECTED_GNU_PROVIDER_NATIVE_PAIR_EVIDENCE','PASS_UNSELECTED_MAINTAINED_DEBIAN_PROVIDER_NATIVE_PAIR_EVIDENCE'))
def load(root):
 path=root/'scripts/ci/glibc-gnu-provider/job.py';raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=OWNER_SHA:raise ValueError('exact original cleanup/retention owner required')
 spec=importlib.util.spec_from_file_location('debian_original_cleanup_owner',path);j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
 j.LABEL=LABEL;j.PACKAGE=PACKAGE
 tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='retain')
 text=ast.get_source_segment(raw.decode(),node)+'\n'
 for before,after in CHANGES:
  if text.count(before)!=1:raise ValueError('exact single retention adaptation anchor required')
  text=text.replace(before,after)
 exec(compile(text,str(path)+':counted-retain','exec'),j.__dict__)
 return j
