"""Fixed source bindings and bounded metadata for the opt-in native trial."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

PINS = {
    'maintained574_active_owner.py':'5cceb8bc88442e9990ac263b7fc1d64999b0b991f4baeb33200755005854408e',
    'test_maintained574_active_owner.py':'1251c25ccdba68aa64fc8e3c059924b2ecf08a40efddcf12cdf6409c714612c7',
    'maintained_desktop574.py':'27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760',
    'maintained-desktop574-inputs.json':'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9',
    'old_four_seed.py':'a14e0318549d24a9bc91ceeb03ec2c1fa2d12f2b3a4f9b0a4cccfb64be34b2b7',
    'log_evidence.py':'a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5',
}
PUBLIC_COMMIT = '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd'
PUBLIC_PINS = {'seed.py':'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3',
               'index.json':'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'}
ENV = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
IMAGE = re.compile('sha256:[0-9a-f]{64}')
CID = re.compile('[0-9a-f]{64}')
TOKEN = re.compile('[0-9a-f]{16}')


class Refused(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=128*1024):
    need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)), 'regular_metadata_required')
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    need(len(raw)<=limit, 'metadata_bound')
    def pairs(items):
        result = {}
        for k,v in items:
            need(k not in result,'duplicate_JSON_key'); result[k]=v
        return result
    def nonfinite(_):
        raise Refused('nonfinite_JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite),{'bytes':len(raw),'sha256':sha(raw)}


def save(path, value):
    raw = (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(len(raw)<=128*1024,'public_metadata_bound')
    temporary = path.with_suffix('.partial')
    with temporary.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)


def pinned(path, pin):
    need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)), 'regular_source_required')
    with path.open('rb') as stream:
        need(hashlib.file_digest(stream,'sha256').hexdigest()==pin,'source_pin_differs')
    return path


def load(ci, name):
    path = pinned(ci/name,PINS[name])
    spec = importlib.util.spec_from_file_location('active_trial_'+name.replace('.','_'),path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def error(error):
    # Never retain arbitrary exception text (acquisition errors may contain URLs).
    value = {'kind':type(error).__name__[:64]}
    if isinstance(error,Refused):
        need(re.fullmatch('[A-Za-z0-9_]{1,80}',str(error)), 'invalid_public_error_code')
        value['code']=str(error)
    return value


def images(docker):
    rows = docker.run('image','ls','-a','--no-trunc','-q').splitlines()
    need(all(IMAGE.fullmatch(v) for v in rows),'invalid_image_list')
    return sorted(set(rows))
