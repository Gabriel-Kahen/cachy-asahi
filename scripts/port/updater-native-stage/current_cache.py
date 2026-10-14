"""Seed four owned old public inputs under the original updater native endpoint."""
import hashlib
import math
import os
from pathlib import Path
import stat
import time

PREFIX = 'scripts/port/updater-native-stage/'
INTAKE_SHA = '07ada8534f4fd21def79ab98c62334e4e0e6a7f5b15a9da8c7eacf44376c334d'
BUFFERS = {
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    PREFIX+'donor/current-controller.py': 'bbe279edb9743f98e8feed8365859abc221b2665924658e600775c902e18299e',
    PREFIX+'donor/current-packet.json': '9d5a7dc25fd44e127c457c72addb28272b1eb1f5391c4c5b8d5b0a226a3be048',
    'scripts/ci/inputs.lock.json': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
}
SEEDS = (
 ('jbigkit-2.1-8-aarch64.pkg.tar.xz',48816,'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db'),
 ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig',566,'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f'),
 ('libtiff-4.7.2-1-aarch64.pkg.tar.xz',354480,'02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd'),
 ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig',566,'8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa'))
PRIVATE_PREFIX = 'CACHY_OLD_FOUR_'


def need(value, code):
    if not value: raise ValueError(code)


def seed(snapshot, private, contract, end, check, holder, module, regular, verify_snapshot):
    """Source-owned intake is retained before construction; no acquire or native actor."""
    first = intake = last = None
    errors = []
    observation = dict(status='FAIL',objects=0,bytes=0,resource_uncertain=True,cancelled=False,
                       signature_authentication='NOT RUN',native_build='NOT RUN',secondary_errors=0)
    def live():
        nonlocal last
        check()
        now=time.monotonic()
        need(type(end) in (int,float) and math.isfinite(end) and type(now) in (int,float)
             and math.isfinite(now) and (last is None or now>=last) and now<end,
             'updater-cache-original-end')
        last=now
    def remember(error):
        nonlocal first
        if first is None:first=error
        errors.append(error)
        observation.update(cancelled=observation['cancelled'] or isinstance(error,(KeyboardInterrupt,SystemExit))
                           or type(error) is ValueError and error.args==('stage-cancelled',),
                           secondary_errors=len(errors)-1)
    try:
        need(type(holder) is dict and not holder,'updater-cache-replay')
        holder.update(observation=observation,errors=errors,intake=None,end=end)
        live()
        need(type(snapshot) is type(private) is type(Path('/')) and snapshot==private/'source',
             'updater-cache-fixed-root')
        verify_snapshot(snapshot,contract);live()
        path=snapshot/(PREFIX+'cache_intake.py')
        need(contract['files'][PREFIX+'cache_intake.py']['sha256']==INTAKE_SHA,
             'updater-cache-intake-source')
        raw=regular(path,2*1024**2);live()
        need(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==INTAKE_SHA,'updater-cache-intake-pin')
        inputs=[]
        for name,pin in BUFFERS.items():
            need(contract['files'][name]['sha256']==pin,'updater-cache-buffer-source')
            raw=regular(snapshot/name,2*1024**2);live()
            need(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==pin,'updater-cache-buffer-pin')
            inputs.append(raw)
        loaded=module(path,INTAKE_SHA);live()
        cls=loaded.CacheIntake
        need(type(cls) is type and cls.__module__==loaded.__name__,'updater-cache-class')
        intake=cls.__new__(cls);holder['intake']=intake;live()
        intake.__init__(*inputs,work_end=end,check=live);live()
        cache=private/'archives';cache.mkdir(mode=0o700);live()
        intake.seed(cache);live()
        guard=intake.guard
        need(intake.state=='SEEDED' and type(guard.resources) is dict and not guard.resources,
             'updater-cache-seed-resources')
        names=guard.invoke(os.listdir,cache)
        need(type(names) is list and len(names)==4 and set(names)=={r[0] for r in SEEDS},
             'updater-cache-seed-membership')
        uid,gid=guard.invoke(os.getuid),guard.invoke(os.getgid)
        for name,size,pin in SEEDS:
            path=cache/name;before=guard.invoke(path.lstat)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600
                 and before.st_nlink==1 and before.st_uid==uid and before.st_gid==gid
                 and before.st_size==size,'updater-cache-seed-owner')
            value=intake.file_hash(path);after=guard.invoke(path.lstat)
            need(value==pin and intake.identity(before)==intake.identity(after),'updater-cache-seed-pin')
        after=guard.invoke(os.listdir,cache)
        need(type(after) is list and len(after)==4 and set(after)==set(names)
             and intake.identity(guard.invoke(cache.lstat))[:6]==intake.cache_identity
             and not guard.resources,'updater-cache-final-custody')
        verify_snapshot(snapshot,contract);live()
    except BaseException as error:remember(error)
    finally:
        try:
            for name in tuple(os.environ):
                if name.startswith(PRIVATE_PREFIX):
                    try:del os.environ[name]
                    except BaseException as error:remember(error)
        except BaseException as error:remember(error)
        try:live()
        except BaseException as error:remember(error)
    if first is not None:
        first.retained_cache_intake=intake
        first.retained_cache_errors=tuple(errors)
        raise first
    observation.update(status='SEEDED_TRANSPORT_ONLY',objects=4,bytes=404428,resource_uncertain=False)
    return dict(observation)
