"""Exact normal-v2 persistent API contract, embedded in standalone trial sources.

The helper validates source selection only. It performs no observation, download,
process launch, package operation, native admission or performance measurement.
"""
import hashlib
_NORMAL_PERSISTENT_API_PROFILE = ('NORMAL_I16K_STATX_HASH_SPLIT_V2_PERSISTENT_API_V1', (69933, 'eb2503068499399d4de60a08f82fb21f179a2a173d1d789d57a28de73eaf609f'), (36200, '1a8a788572325ca68d29abfe34008fd5227d8fb6ff5abccdc12624e110837f8f'))

def normal_persistent_profile(observation_profile, selected):
    if type(observation_profile)is not tuple or observation_profile!=_NORMAL_PERSISTENT_API_PROFILE:
        raise ValueError('exact normal-v2 persistent observation profile')
    if (len(selected),hashlib.sha256(selected).hexdigest())!=observation_profile[1]:
        raise ValueError('whole selected normal-v2 persistent observation source')
    return observation_profile[2]

def disk_observation_profile(config):
    if config['purpose']=='actual-apps6-current604-persistent-root-test':
        if config['code_pins']['scripts/update/full_root.py']!=_NORMAL_PERSISTENT_API_PROFILE[1][1]:
            raise ValueError('normal-v2 disk configuration/root source binding')
        return _NORMAL_PERSISTENT_API_PROFILE
    faults={'actual-apps6-current604-precommit-failure-disposal-test':'precommit-exit86',
            'actual-apps6-current604-postcommit-failure-disposal-test':'postcommit-exit87'}
    if (config['purpose']not in faults or config.get('failure',{}).get('case')!=faults[config['purpose']]
            or config['code_pins']['scripts/update/full_root.py']!='3d8972efeb577750382c62d6801b8c507dbf612ed96e29ebde450a102c5c568e'):
        raise ValueError('exact frozen fault-v1 disk observation selection')
    return None
