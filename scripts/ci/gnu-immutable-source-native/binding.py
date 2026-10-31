"""Private runtime selection from exact source-bound prior decisions; no actors."""
import argparse,os,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D,kernel_input as K

def boot(root):
 p=D.obj(D.read(root/D.LANE/'input-policy.json'));raw=D.read(root/D.LANE/'Root-boot-decision.json');projection=D.read(root/D.LANE/'boot-projection.json')
 D.need(p['boot_decision']is not None and p['boot_projection']is not None,'NULL genuine boot availability authority; refuse BEFORE output, API, secrets or actors');D.need(D.pin(raw)==p['boot_decision']and D.pin(projection)==p['boot_projection'],'whole source-selected Root boot decision/projection')
 v=D.obj(raw);b=D.obj(projection);k,_=K.known();import boot_binding;D.need(b==boot_binding.projection(raw,D.read(root/D.LANE/'Root-boot-strict.json'),k),'exact source-derived finite boot projection');D.need(v.get('scope')=='BOOT_AND_DM_TARGET_AVAILABILITY_ONLY'and type(v.get('status'))is str and v['status'].startswith('ROOT_ACCEPTED_')and str(v.get('run'))==str(b['run'])and v.get('source')==b['source']and v.get('hardware')=='NOT_RUN','finite genuine Root boot availability record, not mapping/lifecycle acceptance')
 path=root/'runtime/immutable';sys.path.insert(0,str(path));P=D.load('_immutable_boot_scope',path/'prerequisites.py');P.boot(b,k['kernel_decision']);return raw,projection

def runtime(root):
 path=root/'runtime/immutable';sys.path.insert(0,str(path));I=D.load('inputs',path/'inputs.py');return I

def build(root,output,env=os.environ):
 root=root.absolute();D.source(root);raw_boot,projection=boot(root);identity=D.environment(env);I=runtime(root);k,v=K.known()
 C=I.current_module('_immutable_current_phase_contract',root/D.VM/D.INST/'contract.py');phases=C.gate(root/D.VM/D.INST/'prerequisites');native_path=C.ref(root/D.VM/D.INST/'prerequisites',C.decode(C.read(C.HERE/'input-policy.json'))['binding']['native_lifecycle'],128*1024);native=D.read(native_path,128*1024)
 out=D.private(output);selected=out/'selected-runtime';shutil.copytree(root/'runtime',selected);private=out/'private-inputs';private.mkdir(mode=0o700);a=private/'immutable-inputs';b=private/'broker-authorities';a.mkdir(mode=0o700);b.mkdir(mode=0o700)
 docs=dict(kernel_build_decision=D.read(D.HERE/'kernel-provenance/Root-acceptance.json'),kernel_boot_decision=projection,source_decision=native,producer_retirement=native)
 for n,raw in docs.items():D.write(a/(n+'.json'),raw)
 authorities=dict(source_authority=native,kernel_authority=docs['kernel_build_decision'],producer_retirement=native,native_readback=native)
 for n,raw in authorities.items():D.write(b/(n+'.json'),raw)
 # Historical Root native cleanup qualifies that prior input only. The fresh
 # native owner must independently prove all new writers retired before consume.
 value=D.obj(D.read(selected/'immutable/policy.json'));value.update(actual_source=identity['source'],actual_ref=identity['ref'],actual_run=identity['run'],**{n:D.pin(raw)for n,raw in docs.items()})
 strict=D.obj(D.read(D.HERE/'kernel-provenance/Root-strict-result.json'));profile=strict['checked']['profile'];nonce=os.urandom(16).hex()
 value['bootstrap']=dict(status='ROOT_BOUND_GNU_VERITY_BOOTSTRAP',source='7d7ccbcb7b5a170999716ed640285806b7cab9bb',kernel=dict(profile=profile['profile'],boot_page_size=16384,release=profile['release'],configured_symbols=['MD','BLK_DEV_DM','DM_VERITY','CRYPTO_SHA256']),nonce=nonce,image=None,tree=None,snapshot=None,producer_retirement=None)
 value['broker']=dict(purpose='GNU_PID1_VERITY_SOURCE_BROKER_V1',nonce=nonce,verity=None,**{n:D.pin(raw)for n,raw in authorities.items()})
 descriptor=dict(purpose='EXISTING_ACTIONS_KERNEL_ARTIFACT_INPUT_ONLY',source=k['source'],run=k['run'],artifact_id=k['artifact']['id'],artifact_name=k['artifact']['name'],archive=k['transport']['artifact'],Image=k['Image'],config=k['config'],kernel_build_decision=k['kernel_decision'],scope='BUILD_ONLY_NOT_BOOT_OR_MAPPING_OR_LIFECYCLE')
 qualifiers=D.obj(D.read(selected/'immutable/qualification-pins.json'));qualifiers.update(actual_source=identity['source'],actual_ref=identity['ref'],actual_run=identity['run'],**{n:D.pin(raw)for n,raw in docs.items()},broker_authorities={n:D.pin(raw)for n,raw in authorities.items()},kernel_artifact=dict(source=k['source'],run=k['run'],artifact_id=k['artifact']['id'],artifact_name=k['artifact']['name'],archive=k['transport']['artifact'],Image=k['Image'],config=k['config'],descriptor=D.pin(D.encoded(descriptor))))
 # Public template remains unchanged. Only these TWO private selector leaves
 # and the exact matching manifest rows change; no executable body is rebound.
 for n,data in(('policy.json',value),('qualification-pins.json',qualifiers)):(selected/'immutable'/n).write_bytes(D.encoded(data))
 manifest=D.obj(D.read(selected/'runtime-source.json',2*1024**2))
 for n in('policy.json','qualification-pins.json'):manifest['files']['immutable/'+n]=D.pin(D.read(selected/'immutable'/n))
 (selected/'runtime-source.json').write_bytes(D.encoded(manifest));D.write(private/'policy.json',D.encoded(value));proof=dict(status='PRIVATE_SOURCE_BOUND_INPUT_SELECTION_NO_ACTORS',identity=identity,private_changes=['immutable/policy.json','immutable/qualification-pins.json','runtime-source.json'],prior_kernel=k['source'],Root_boot_input_only=True,new_native_acceptance=False);D.write(out/'binding-proof.json',D.encoded(proof));return proof
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=D.ROOT);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(D.encoded(build(a.source,a.output)).decode(),end='')
