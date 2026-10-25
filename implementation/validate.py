# SPDX-License-Identifier: MIT
"""New607 scope AND the original complete VM positive/failure protocol parser."""
import common as C

def completion(vm,events,nonce,common,profile_sha256=None):
 result=vm.validate_completion(events,nonce,common,profile_sha256) # Complete original parser body held.
 C.need(result['status']=='PASS_PUBLIC_PAIRS_APPS6_CURRENT607_INSTALLER'and result['package_count']==607 and result['expected_lock_sha256']==C.profile()['target']['sha256'],'exact607 positive target, not old604 success')
 return result

def owner(value):
 C.need(type(value)is dict and value.get('status')=='PASS'and all(value.get(k)=='PASS'for k in('container_cleanup','private_cleanup','source_cache_preservation'))and value.get('image_cleanup')in('PASS','NOT CREATED'),'complete original owned VM retirement/preservation')
 return value

def failure(vm,data,nonce):
 events=vm.parse_protocol(data,nonce,complete=True)
 C.need(not(events and len(events)==3 and events[1].get('status')=='PASS_PUBLIC_PAIRS_APPS6_CURRENT607_INSTALLER'),'positive protocol cannot become a failure acceptance')
 return dict(status='OBSERVED_FAILURE_DATA_ONLY',events=events,acceptance='NOT_GRANTED',fresh607='NOT_ACCEPTED',hardware='NOT_RUN')
