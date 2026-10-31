#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert closed SQLite overlay/ELF controls; no loader, CDLL, GPG or ALPM."""
import copy,hashlib,importlib.util,json,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
spec=importlib.util.spec_from_file_location('coherent_profile',HERE/'profile.py');p=importlib.util.module_from_spec(spec);sys.modules[spec.name]=p;spec.loader.exec_module(p)
HELD=p.constants(ROOT/'scripts/virtual/common.py',{'TRANSACTION_PROFILE_BYTES'})['TRANSACTION_PROFILE_BYTES']
BASE={row['name']:row['version'] for row in p.decode((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']}


def selection():
    manifest=dict(packages=[dict(p.SQLITE_ARCHIVE)])
    payload=dict(nodes={p.NEW_SQLITE['path'].lstrip('/'):dict(type='file',mode=0o755,uid=0,gid=0,bytes=p.NEW_SQLITE['size'],sha256=p.NEW_SQLITE['sha256'])})
    for name in ('usr/lib/libsqlite3.so','usr/lib/libsqlite3.so.0'):
        payload['nodes'][name]=dict(type='symlink',mode=0o777,uid=0,gid=0,target='libsqlite3.so.3.54.0')
    return manifest,payload,dict(BASE)


def synthetic_elf(**changes):
    values=dict(soname='libsqlite3.so.0',needed=['ld-linux-aarch64.so.1','libc.so.6','libm.so.6'],runpath='/usr/lib');values.update(changes)
    strings=bytearray(b'\0');rows=[]
    def string(text):
        offset=len(strings);strings.extend(text.encode()+b'\0');return offset
    for name in values['needed']:rows.append((1,string(name)))
    rows.extend([(14,string(values['soname'])),(29,string(values['runpath'])),(5,512),(10,len(strings)),(0,0)])
    raw=bytearray(768);raw[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HH',raw,16,3,183)
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,2)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,len(raw),len(raw),4096)
    struct.pack_into('<IIQQQQQQ',raw,120,2,6,256,256,256,len(rows)*16,len(rows)*16,8)
    for index,row in enumerate(rows):struct.pack_into('<qQ',raw,256+index*16,*row)
    raw[512:512+len(strings)]=strings;return bytes(raw)


class CoherentProfileControls(unittest.TestCase):
    def test_exact_one_replacement_all135_other_files_and_seven_roles_unchanged(self):
        old=p.decode(HELD);new=p.coherent_tools(HELD)
        self.assertEqual(len(new['files']),136);self.assertEqual(new['roots'],old['roots'])
        before={row['path']:row for row in old['files']};after={row['path']:row for row in new['files']}
        self.assertEqual({k:v for k,v in before.items() if k!=p.OLD_SQLITE['path']},{k:v for k,v in after.items() if k!=p.NEW_SQLITE['path']})
        self.assertEqual(after[p.NEW_SQLITE['path']],p.NEW_SQLITE);self.assertNotIn(p.OLD_SQLITE['path'],after)
        self.assertEqual(sum(row['size'] for row in new['files']),85444968)
        self.assertEqual(hashlib.sha256((json.dumps(new,sort_keys=True,indent=2)+'\n').encode()).hexdigest(),p.COHERENT_TOOL_PROFILE_SHA)
    def test_only_two_soname_aliases_are_added_and_existing_aliases_preserved(self):
        old=p.decode(HELD);new=p.coherent_tools(HELD);aliases=dict(old['aliases']);aliases.pop(p.OLD_SQLITE['path'])
        for name,target in aliases.items():self.assertEqual(new['aliases'][name],target)
        for name in ('/usr/lib/libsqlite3.so','/usr/lib/libsqlite3.so.0',p.NEW_SQLITE['path']):self.assertEqual(new['aliases'][name],p.NEW_SQLITE['path'])
        self.assertEqual(len(new['aliases']),len(old['aliases'])+2)
        self.assertTrue({'/usr/lib/'+name for name in p.SQLITE_ELF['needed']}<={row['path'] for row in new['files']})
    def test_mutated_historical_profile_cannot_authorize_any_change(self):
        old=p.decode(HELD);old['files'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'historical'):p.coherent_tools(json.dumps(old).encode())
    def test_signed_archive_version_hash_signature_size_or_duplicate_drift_refuses(self):
        for key,value in (('version','3.53.4-1'),('sha256','0'*64),('signature_sha256','0'*64),('size',1849949),('signature_size',567)):
            manifest,payload,base=selection();manifest['packages'][0][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'source tuple'):p.tool_selection(manifest,payload,base)
        manifest,payload,base=selection();manifest['packages']*=2
        with self.assertRaisesRegex(ValueError,'source tuple'):p.tool_selection(manifest,payload,base)
    def test_payload_hash_mode_uid_gid_or_flattened_alias_refuses(self):
        for field,value in (('sha256','0'*64),('mode',0o644),('uid',1),('gid',1)):
            manifest,payload,base=selection();payload['nodes'][p.NEW_SQLITE['path'].lstrip('/')][field]=value
            with self.assertRaisesRegex(ValueError,'payload differs'):p.tool_selection(manifest,payload,base)
        manifest,payload,base=selection();payload['nodes']['usr/lib/libsqlite3.so.0']['target']='other'
        with self.assertRaisesRegex(ValueError,'alias differs'):p.tool_selection(manifest,payload,base)
    def test_old_sqlite_member_or_other_builder_inventory_is_never_authorized(self):
        manifest,payload,base=selection();payload['nodes'][p.OLD_SQLITE['path'].lstrip('/')]=dict(payload['nodes'][p.NEW_SQLITE['path'].lstrip('/')])
        with self.assertRaisesRegex(ValueError,'payload differs'):p.tool_selection(manifest,payload,base)
        for changed in (dict(BASE,sqlite='3.53.4-1'),dict(BASE,sqlite='3.55.0-1'),{k:v for k,v in BASE.items() if k!='sqlite'}):
            manifest,payload,_=selection()
            with self.assertRaisesRegex(ValueError,'preserved574'):p.tool_selection(manifest,payload,changed)
    def test_profile_declared_source_and_generated_bytes_must_join(self):
        manifest,payload,base=selection();profile=dict(tools=p.coherent_tools(HELD),base_tool_profile_sha256=p.BASE_TOOL_PROFILE_SHA,
            tool_profile_sha256=p.COHERENT_TOOL_PROFILE_SHA,tool_profile_binding=p.tool_selection(manifest,payload,base))
        p.validate_tools(profile,manifest,payload,base,HELD)
        for field,value in (('tool_profile_sha256',p.BASE_TOOL_PROFILE_SHA),('base_tool_profile_sha256','0'*64),('tool_profile_binding',{})):
            with self.assertRaises(ValueError):p.validate_tools(dict(profile,**{field:value}),manifest,payload,base,HELD)
    def test_build_emits_both_profile_pins_and_archive_binding_from_real_builder_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ready=root/'ready';ready.mkdir();code=root/'code';code.mkdir();output=root/'out';output.mkdir()
            config=code/'scripts/ci/full-root-upgrade-caller/upgrade-config.json';config.parent.mkdir(parents=True)
            config.write_text('{"code_pins":{}}')
            for name in ('scripts/virtual/common.py','scripts/virtual/tooling.lock.json','scripts/virtual/audit_tooling.py'):
                path=code/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'{}')
            for name in ('scripts/platform/elf_audit.py','scripts/update/root_path.py'):
                path=code/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/name).read_bytes())
            builder=ready/'builder-packages.lock';builder.write_text(''.join(n+' '+v+'\n' for n,v in sorted(BASE.items())))
            manifest,payload,base=selection();manifest['builder_lock']=dict(path=builder.name,size=builder.stat().st_size,sha256=p.BUILDER_LOCK)
            for gid in (0,5,11,50,81,102):payload['nodes']['inert-'+str(gid)]=dict(type='directory',uid=0,gid=gid,mode=0o755)
            expected=dict(line.split() for line in (ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_text().splitlines())
            def constants(path,names):
                return {'NATIVE_PROFILE_SHA':p.BASE_TOOL_PROFILE_SHA} if names=={'NATIVE_PROFILE_SHA'} else dict(TRANSACTION_PROFILE_BYTES=HELD,TRANSACTION_LAUNCHER={})
            with patch.object(p,'manifest',return_value=(manifest,{},expected)),patch.object(p,'payload',return_value=payload),patch.object(p,'constants',side_effect=constants),\
                 patch.object(p,'project_sonames',return_value={'outputs':{}}),patch.object(p,'soname_selection',return_value={'purpose':'inert-separate-SONAME-control'}):
                profile=p.build(ready,code,output)
            self.assertEqual(profile['derived_output_binding'],{'purpose':'inert-separate-SONAME-control'})
            self.assertEqual(profile['tool_profile_sha256'],p.COHERENT_TOOL_PROFILE_SHA)
            self.assertEqual(profile['base_tool_profile_sha256'],p.BASE_TOOL_PROFILE_SHA)
            self.assertEqual(profile['tool_profile_binding']['archive'],p.SQLITE_ARCHIVE)
            self.assertEqual(p.decode((output/'installer-profile.json').read_bytes()),profile)
    def test_input_maps_are_not_mutated(self):
        inputs=selection();before=copy.deepcopy(inputs);p.tool_selection(*inputs);self.assertEqual(inputs,before)


class ELFControls(unittest.TestCase):
    def inspect(self,raw):
        # Only synthetic unit data changes the fixture byte pin. Production pins
        # above are exact and the passive readout checks the actual retained DSO.
        with patch.object(p,'NEW_SQLITE',dict(p.NEW_SQLITE,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())):return p.sqlite_elf(raw)
    def test_exact_dso_soname_three_needed_members_and_runpath(self):self.assertEqual(self.inspect(synthetic_elf()),p.SQLITE_ELF)
    def test_changed_soname_needed_or_runpath_refuses(self):
        for change in (dict(soname='libsqlite3.so.1'),dict(needed=['missing.so']),dict(runpath='/tmp'),dict(needed=p.SQLITE_ELF['needed']+['libc.so.6'])):
            with self.assertRaisesRegex(ValueError,'dynamic closure'):self.inspect(synthetic_elf(**change))
    def test_wrong_architecture_or_truncated_segments_refuse(self):
        wrong=bytearray(synthetic_elf());struct.pack_into('<H',wrong,18,62)
        with self.assertRaisesRegex(ValueError,'AArch64'):self.inspect(bytes(wrong))
        wrong=bytearray(synthetic_elf());struct.pack_into('<Q',wrong,96,100000)
        with self.assertRaises(ValueError):self.inspect(bytes(wrong))
    def test_unpinned_production_bytes_refuse_before_elf_interpretation(self):
        with self.assertRaisesRegex(ValueError,'ELF bytes'):p.sqlite_elf(synthetic_elf())


if __name__=='__main__':unittest.main()
