# SPDX-License-Identifier: MIT
"""Two finite future Root decisions; expected schema is not an accepted record."""
import re
KINDS=('native_interruption','normal_installed16k')
def need(ok,why):
 if not ok:raise ValueError(why)

def fields(value,kind,expected,provider):
 need(kind in KINDS and type(value)is dict,'finite maintained prerequisite role')
 static=dict(schema_version=1,**expected[kind],provider=provider['name'],version=provider['version'],provider_archive_sha256=provider['archive_sha256'],source_authority_sha256=provider['source_authority_sha256'],ALPM_installation='PASS',ordered_cleanup='PASS',hardware='NOT_RUN',release_admission=False,cases=['pristine','modified'],source_preservation='PASS',configuration_preservation='PASS',capabilities='PASS_EXACT_SOURCE_MAP_PRESERVED')
 if kind=='native_interruption':static.update(interruption='REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED',recovery='PASS_EXACT_LOCK_AND_EXTERNAL_HELD_REINSTALL',power_loss='NOT_TESTED')
 else:static.update(scope='FULL574_ALPM_NORMAL_INSTALLED16K')
 need(set(value)==set(static)|{'run_id','attempt'},'exact finite Root decision schema; no old provider or staged substitution')
 for key,wanted in static.items():need(type(value[key])is type(wanted)and value[key]==wanted,'same maintained actual source/MF/provider/completeness required: '+kind+' '+key)
 need(type(value['run_id'])is int and value['run_id']>0 and type(value['attempt'])is int and value['attempt']==1,'real first-attempt actual run identity required')
 return value

def validate(C,acceptances):
 policy=C.decode(C.read(C.HERE/'input-policy.json',65536))
 C.need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT'and type(policy['binding'])is dict and set(policy['binding'])==set(KINDS)and all(type(policy['binding'][k])is dict for k in KINDS),'UNBOUND maintained interrupted16K: BOTH genuine exact-source decisions required before output/actors')
 result={}
 for kind in KINDS:
  value=C.decode(C.read(C.ref(acceptances,policy['binding'][kind],128*1024),128*1024));result[kind]=fields(value,kind,EXPECTED,PROVIDER)
 return result

EXPECTED={'native_interruption': {'committed_transactions': 8, 'complete574_maps': 20, 'integration_manifest': {'bytes': 26324, 'path': 'scripts/ci/glibc-debian-maintained-public-provider-interruption-owner/integration-manifest.json', 'sha256': '980181310c94a60eaa2734304e7678b29d58e882301da1f620088825c7735469'}, 'normal_runtime_observations': 10, 'page_size': 4096, 'source_manifest': {'bytes': 1721, 'path': 'scripts/ci/glibc-debian-maintained-public-provider-interruption/source-manifest.json', 'sha256': 'e6b11bfc2f92aacabef814248b9a6505f14694400e727e4176ca036285f3f8e1'}, 'source_sha': '73da7728469c7c11b5877ba47645bf812ac6dbdc', 'status': 'ROOT_ACCEPTED_CAA3_PUBLIC_COMPILE_NATIVE_INTERRUPTION_RECOVERY', 'zero_commit_refusals': 2}, 'normal_installed16k': {'committed_transactions': 6, 'complete574_maps': 16, 'integration_manifest': {'bytes': 54805, 'path': 'scripts/ci/glibc-debian-maintained-public-installed16k/source-pins.json', 'sha256': 'ff276f4e19e0204b65bb9045383dd8941b977b74b259495849745debb7acd8bd'}, 'normal_runtime_observations': 8, 'page_size': 16384, 'source_manifest': {'bytes': 4088, 'path': 'scripts/ci/glibc-debian-maintained-installed16k/source-manifest.json', 'sha256': 'a4e9a88e89b5c6dadd6229d7472b9ba646cfcc67cc3482f04882ff8c607f79ac'}, 'source_sha': '34548c30fa5b0d65172eba2302ddcb4a07840488', 'status': 'ROOT_ACCEPTED_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY', 'zero_commit_refusals': 2}}
PROVIDER={'archive_sha256': 'a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9', 'name': 'cachy-asahi-glibc-gnu-provider', 'source_authority_sha256': '88643eabd61a39df63ecaeb50bb20041d17cf4fd3adee55d82d43d3c1ca08707', 'version': '2.43.caa3-1'}
