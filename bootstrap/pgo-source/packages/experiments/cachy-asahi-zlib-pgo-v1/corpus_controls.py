# SPDX-License-Identifier: MIT
"""Fixed, separate PGO training and validation data; passive byte/policy checks."""
import hashlib
import json
from pathlib import Path
import stat

SOURCE_SHA256='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
VALIDATION_SHA256='e178d56b3a6d0af1900f8e3a1b668549793b48d0ae35c24e730b9a39992604bf'
ORDER=['baseline','candidate','candidate','baseline','candidate','baseline','baseline','candidate','baseline','candidate','candidate','baseline']
TEXT=b'cachy-asahi original PGO v1 training records; generic ARM gzip roundtrips; no heldout inputs.\n'
SEED=b'cachy-asahi-zlib-pgo-v1-training-counter:'
SECTIONS=[
 {'name':'public-zlib-source','offset':0,'bytes':1048576,'sha256':'7ec5549498d34ca0a27b05a5045e474c561d09942b5af1f665ca60eb527f5dca'},
 {'name':'structured-records','offset':1048576,'bytes':1048576,'sha256':'48dc12d1dfcc06a6a1535b25eddedf7cdd61cec010d253e4be388fef75567ae7'},
 {'name':'binary-ramp','offset':2097152,'bytes':1048576,'sha256':'d0d5ce74c58ce0e93a8ea778171f293bed4c1b7b47701afd6bd8263fab1df3cf'},
 {'name':'seeded-high-entropy','offset':3145728,'bytes':1048576,'sha256':'88aac3cba4d1c80deb950a516cb697e730df9a80fffaf187350142b700e4816c'}]


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def training_bytes():
    """Original synthetic bytes; no validation input is read to generate them."""
    text=(TEXT*((131072+len(TEXT)-1)//len(TEXT)))[:131072]
    records=b''.join((json.dumps({'batch':i,'kind':'pgo-training-only','status':'recorded','value':i%17},sort_keys=True,separators=(',',':'))+'\n').encode()for i in range(1024))
    structured=(records*((65536+len(records)-1)//len(records)))[:65536]
    entropy=b''.join(hashlib.sha256(SEED+i.to_bytes(4,'big')).digest()for i in range(2048))
    return text+structured+entropy


def expected_policy():
    raw=training_bytes()
    return dict(schema=1,purpose='ZLIB_PGO_V1_FIXED_TRAINING_AND_INDEPENDENT_VALIDATION',source_zlib_sha256=SOURCE_SHA256,
        training=dict(path='training.bin',bytes=len(raw),sha256=sha(raw),role='training-only',license='MIT',
            recipe=dict(version=1,text_prefix_bytes=131072,structured_prefix_bytes=65536,sha256_counter_blocks=2048,counter_encoding='uint32-big-endian',counter_seed_hex=SEED.hex()),
            upstream_fixed_literal_programs={'test/example.c':'be1b050aad808cdb016c01f42568d3a62ee37dd7b2b56bef0ade21be8d9fee0d'},
            prohibited_inputs=['validation.bin','heldout-source.bin','mixed.bin']),
        validation=dict(path='validation.bin',bytes=4194304,sha256=VALIDATION_SHA256,role='independent-validation-and-measurement-only',
            origin='c01-paired-runtime source fc45bef5493afc1fbc5ee0a1fc0537275a4e90d6 fixed mixed4MiB corpus; unchanged bytes',
            license='Public zlib source/doc sections retain upstream Zlib notices; synthetic sections MIT project',sections=SECTIONS),
        separation=dict(construction='Training generator uses only original text, fixed records and an independent SHA256 counter seed; no heldout bytes, hashes or sections influence generated training bytes',
            training_input_allowlist=['training.bin','pinned test/example.c fixed literals'],validation_during_instrumentation='FORBIDDEN',
            meaning='Independent construction and role isolation; not a claim that arbitrary byte values or short substrings never overlap'),
        measurement=dict(execution_context='virtual',measurement_scope='GENERIC_HOSTED_ARM_ZLIB_PGO_V1',payload_bytes=16777216,payload_definition='Repeat unchanged validation.bin four times',
            iterations=4,compression_level=6,correctness_slots=2,excluded_warmup_slots=4,measured_slots=12,total_slots=18,minimum_trials=6,order=ORDER,
            trial_seconds=45,session_seconds=900,sample_seconds=0.1,thresholds=dict(minimum_elapsed_improvement_pct=5,maximum_elapsed_range_pct=25,maximum_regression={}),
            current_source=None,current_run=None,current_image=None),
        hardware='NOT RUN',optimization_acceptance='NOT RUN',performance_acceptance='NOT GRANTED',release='NOT_ADMITTED')


def read(path,cap):
    path=Path(path)
    need(not any(p.is_symlink()for p in(path,*path.parents)),'corpus alias refused')
    info=path.stat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary single-link corpus file required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'corpus size changed while reading');return raw


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate corpus policy key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in()).throw(ValueError('nonfinite corpus policy')))


def validate(root):
    """Read-only whole policy, both byte blobs, and frozen section/role/gate check."""
    root=Path(root);policy=decode(read(root/'corpus-policy.json',65536));expected=expected_policy()
    need(json.dumps(policy,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False),'whole corpus policy differs from fixed roles, recipes or gates')
    training=read(root/'training.bin',1048576);validation=read(root/'validation.bin',4194304)
    need(training==training_bytes()and len(training)==policy['training']['bytes']and sha(training)==policy['training']['sha256'],'deterministic training bytes differ')
    need(len(validation)==policy['validation']['bytes']and sha(validation)==policy['validation']['sha256'],'independent validation bytes differ')
    need(training!=validation and sha(training)!=sha(validation),'training and validation must differ')
    for row in SECTIONS:
        section=validation[row['offset']:row['offset']+row['bytes']]
        need(len(section)==row['bytes']and sha(section)==row['sha256'],'frozen validation section differs')
        need(sha(training)!=sha(section),'training equals a full validation section')
    return policy
