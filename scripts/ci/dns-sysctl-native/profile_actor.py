# SPDX-License-Identifier: MIT
"""One finite seventh zero-cap actor; native574 preservation, staged exact DNS script."""
import hashlib,json,os,shutil,stat
from pathlib import Path

def need(ok,message):
 if not ok:raise ValueError(message)

def network_state():
 root=Path('/sys/class/net');need({p.name for p in root.iterdir()}=={'lo'},'only private loopback allowed')
 paths=['/sys/class/net/lo/flags','/sys/class/net/lo/mtu','/proc/net/if_inet6','/proc/sys/net/ipv6/conf/lo/temp_valid_lft','/proc/sys/net/ipv6/conf/lo/temp_prefered_lft']
 result={name:Path(name).read_text()for name in paths}
 # Exclude only read-side kernel use/reference counters, not route identity/flags/metrics.
 result['ipv4_routes']=[row[:4]+row[6:]for row in(line.split()for line in Path('/proc/net/route').read_text().splitlines()[1:])]
 result['ipv6_routes']=[row[:6]+row[8:]for row in(line.split()for line in Path('/proc/net/ipv6_route').read_text().splitlines())]
 return result

def launch(C,source,out,image,products,docker,command,containers):
 inputs=out/'profile-inputs';inputs.mkdir();runner=inputs/'runner';runner.mkdir();accepted=runner/'accepted';accepted.mkdir()
 for target,path in [('profile_actor.py',C.HERE/'profile_actor.py'),('private_profile.py',C.HERE/'private_profile.py'),('installed.py',source/'scripts/ci/apps-cache-native/installed.py'),('accepted/lifecycle.py',source/'scripts/ci/welcome-native/lifecycle.py'),('accepted/root_upgrade.py',source/'scripts/ci/full-root-upgrade/root_upgrade.py')]:shutil.copyfile(path,runner/target)
 base=dict(line.split()for line in(out/'base-inventory.log').read_text().splitlines())
 (inputs/'base.json').write_text(json.dumps(base))
 product=products['cachy-asahi-dns'];program=source/'packages/tools/cachy-asahi-dns/cachy-asahi-dns';payload=product['payload']['usr/bin/cachy-asahi-dns']
 C.need(C.digest(program)==payload['sha256']and payload['mode']==0o755,'validated build-A/source program byte join required')
 (inputs/'control.json').write_text(json.dumps(dict(source_program_sha256=payload['sha256'],native_archive_sha256=product['sha256'],version=product['version'])))
 for path in(inputs,*inputs.rglob('*')):path.chmod(0o755 if path.is_dir()else 0o644)
 staged=inputs/'dns-command';shutil.copyfile(program,staged);staged.chmod(0o755);C.need(C.digest(staged)==payload['sha256'],'staged native-payload bytes differ')
 output=out/'private-profile-actor';output.mkdir(mode=0o700);actor='cachy-asahi-product-'+os.urandom(16).hex();containers.append(actor)
 argv=docker(image,actor,output,root=True);caps=['--cap-add='+c for c in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
 C.need([a for a in argv if a.startswith('--cap-add=')]==caps,'original ALPM root capset changed; no silent privilege adaptation')
 argv=[a for a in argv if a not in caps]
 command(argv+['--env=CACHY_ASAHI_DNS_PRIVATE_PROFILE=1','--env=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket','--mount',f'type=bind,src={inputs},dst=/inputs,readonly','--mount',f'type=bind,src={runner},dst=/runner,readonly','--mount',f'type=bind,src={staged},dst=/usr/bin/cachy-asahi-dns,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/profile_actor.py'],out/'private-profile.log',600)
 receipt=output/'private-profile/receipt.json';C.need(receipt.is_file()and not receipt.is_symlink()and receipt.stat().st_size<=1024**2,'bounded private NM receipt required')
 value=json.loads(receipt.read_bytes())
 from rules import validate_profile
 validate_profile(value,payload['sha256']);return value

def inside():
 import installed as I
 import private_profile as F
 L,driver=I.apis()
 L.need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64','dedicated native ARM PID1 required')
 base=json.loads(Path('/inputs/base.json').read_bytes());control=json.loads(Path('/inputs/control.json').read_bytes())
 L.need(len(base)==574 and L.inventory()==base and L.sha(F.PROGRAM)==control['source_program_sha256']and stat.S_IMODE(F.PROGRAM.stat().st_mode)==0o755 and control['version']=='0.1.0-1','exact574/native-build source program required')
 state=I.base_state(L,driver);before=I.preserve_base(L,state);network=network_state();result=F.run(Path('/out/private-profile'))
 receipt=Path('/out/private-profile/receipt.json');value=json.loads(receipt.read_bytes())
 try:
  L.need(I.preserve_base(L,state)==before,'original574 payload/raw DB changed during real private NM integration')
  after=network_state();L.need(after==network,'private namespace loopback/routes/lifetimes changed')
  value.update(base574_preserved=True,base_manifest_sha256=before,base_count=574,network_before=network,network_after=after,network_state_preserved=True,program_delivery='SOURCE_BYTES_EQUAL_VERIFIED_NATIVE_BUILD_A_PAYLOAD_READONLY_MOUNT',native_archive_sha256=control['native_archive_sha256'])
 except BaseException as error:value.update(status='FAIL_PRIVATE_PROFILE_INTEGRATION',preservation_error=str(error)[:1024]);result=1
 receipt.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');return result

if __name__=='__main__':raise SystemExit(inside())
