# SPDX-License-Identifier: MIT
"""Finite dependency admission/qualification additions; exact parent substitutions."""
PATCHES={
'hosted/bootstrap.py':[
("    root,work=Path(root),Path(work);own=owner(binding);out=work/'normal-image';out.mkdir(mode=0o700)","    root,work=Path(root),Path(work);own=owner(binding);out=work/'normal-image';out.mkdir(mode=0o700)\n    dependencies=load('rust_bootstrap_build_dependencies',root/'hosted/build_dependencies.py');dependency_policy=dependencies.policy(root)"),
("        dockerfile=normal_dockerfile(own['base_tag'],fingerprint_expected);(context/'Dockerfile').write_bytes(dockerfile)","        dependency_audit=dependencies.prepare_context(root,context,out,Path(os.environ['RUNNER_TEMP'])/'alarm-cache',dependency_policy,call,tick)\n        dockerfile=dependencies.extend_dockerfile(normal_dockerfile(own['base_tag'],fingerprint_expected),dependency_policy);(context/'Dockerfile').write_bytes(dockerfile)"),
("        report.update(status='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA'", "        dependency_observation=dependencies.observe(rootfs,root,dependency_policy,tick);dependencies.validate_observation(dependency_observation,root,dependency_policy,native=False)\n        need(dependency_observation['inventory']==dict(bytes=len(qualified_raw),sha256=hashlib.sha256(qualified_raw).hexdigest()),'same exact actual qualified dependency inventory')\n        report['build_dependencies']=dict(policy=dependencies.POLICY_PIN,audit=dict(bytes=len(encode(dependency_audit)),sha256=hashlib.sha256(encode(dependency_audit)).hexdigest()),observation=dependency_observation)\n        report.update(status='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA'"),
("    for name in ('inputs.lock.json','acquisition.json','signatures.json'", "    files['signed_build_dependencies']=filepin(out/'build-dependency-audit.json')\n    for name in ('inputs.lock.json','acquisition.json','signatures.json'")],
'hosted/qualification.py':[
("    P=load('qualification_owned_bind_replay',Path(__file__).with_name('producer.py'));owner=", "    dependencies=load('qualification_build_dependency_checks',Path(__file__).with_name('build_dependencies.py'));source_root=Path(__file__).parent.parent;dependency_policy=dependencies.policy(source_root)\n    dependencies.validate_observation(value['build_dependencies'],source_root,dependency_policy,boot['build_dependencies']['observation'])\n    for phase in ('data','probe'):\n        filename='build-dependencies-'+phase+'.json'\n        if directory is not None:path=Path(directory)/filename\n        else:path=Path(value['files']['qualification_'+filename]['local_path'])\n        raw=dependencies.read(path,1024**2)\n        if directory is None:\n            row=value['files']['qualification_'+filename];need(dependencies.pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole retained native dependency observation')\n        dependencies.validate_observation(dependencies.decode(raw),source_root,dependency_policy,boot['build_dependencies']['observation'])\n    P=load('qualification_owned_bind_replay',Path(__file__).with_name('producer.py'));owner="),
("    q=dict(schema=4,status='ROOT_PREGRANTED_NATIVE_SOURCE_QUALIFICATION_ONLY'", "    q=dict(build_dependencies=boot['build_dependencies']['observation'],schema=4,status='ROOT_PREGRANTED_NATIVE_SOURCE_QUALIFICATION_ONLY'")],
'actor/qualify.py':[
("        if phase=='data':\n            (WORK/'stage0-unpack').mkdir();", "        dependencies=load('native_qualification_build_dependencies',ROOT/'hosted/build_dependencies.py');dependency_policy=dependencies.policy(ROOT)\n        dependency_observation=dependencies.observe(Path('/'),ROOT,dependency_policy,tick,native=True);dependencies.validate_observation(dependency_observation,ROOT,dependency_policy,p['build_dependencies'])\n        with (OUT/('build-dependencies-'+phase+'.json')).open('xb')as stream:stream.write(encode(dependency_observation))\n        if phase=='data':\n            (WORK/'stage0-unpack').mkdir();"),
("            row=dict(data_commands=", "            row=dict(build_dependencies=dependency_observation,data_commands="),
("        result=dict(data_commands=", "        result=dict(build_dependencies=dependency_observation,data_commands=")]
}
def render_leaves(before):
 result={}
 for name,changes in PATCHES.items():
  raw,mode=before[name]
  for old,new in changes:
   old,new=old.encode(),new.encode()
   if raw.count(old)!=1:raise ValueError('one exact dependency insertion site: '+name)
   raw=raw.replace(old,new)
  result[name]=(raw,mode)
 return result
