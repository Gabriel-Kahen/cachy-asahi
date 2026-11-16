#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete modeled image-lifecycle Reader seam; no actors or Reader invocation."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
MAP = 'a' * 64
BINDING = dict(source='b'*40,ref='refs/heads/codex/MODELED',run='123',attempt=1,token='c'*24)
DOCKER = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
LABEL = 'org.cachy-asahi.native-developer'


def fence(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')):
        raise AssertionError('actor denied by image DATA controls: '+event)
sys.addaudithook(fence)


def need(value,message):
    if not value: raise ValueError(message)


def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def reader_function():
    raw = (HERE/'payload/native/build_tools_reader_v2.py').read_text()
    node = next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='retained_image_lifecycle')
    scope = dict(need=need,pin=pin,Path=Path,re=re,json=json)
    exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated retained-image DATA function','exec'),scope)
    return scope[node.name]


class Model:
    def __init__(self):
        self.values = {}; self.files = {}; self.actors = {'owner':[],'retirement':[]}
        self.aliases = {role:'native-developer-'+role+':'+BINDING['token'] for role in ('base','tools')}
        self.ids = dict(base='sha256:'+'1'*64,tools='sha256:'+'2'*64)
        self.ledger = dict(schema=1,binding=BINDING,source_map_sha256=MAP,status='PASS_FRESH_LOCAL_ALIAS_BASELINE',actor_scope='owner',
                           aliases=self.aliases,baseline=dict(aliases=dict(base=[],tools=[]),owned_image_ids=[]),created={},query_checks=[])
        self.retirement = dict(schema=1,binding=BINDING,source_map_sha256=MAP,status='PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED',
                               actor_scope='retirement',ledger=self.ledger,final=dict(aliases=dict(base=[],tools=[]),owned_image_ids=[]),
                               codes=[],removed_aliases=[self.aliases['tools'],self.aliases['base']],query_checks=[],removals=[])
        self.ledger['baseline_query_indexes'] = [self.query(self.ledger,['image','ls','--no-trunc','-q','--filter',selector],b'')
            for selector in ('reference='+self.aliases['base'],'reference='+self.aliases['tools'],'label='+LABEL+'='+BINDING['token'])]
        self.builds = {}
        self.build('base')
        before = self.proof(self.ledger,'base'); before.update(phase='before_overlay',status='PASS')
        self.build('tools')
        after = self.proof(self.ledger,'base'); after.update(phase='after_overlay',status='PASS')
        self.ledger['base_checks'] = [before,after]
        self.ledger['created']['tools']['registration'] = self.proof(self.ledger,'tools')
        self.consumer = '3'*64
        create = DOCKER+['create','--name','developer-'+BINDING['token'],'--pull=never','--network=none',self.ids['tools']]
        self.actor('owner',create,self.consumer.encode())
        self.retirement['preflight'] = dict(aliases={r:[self.ids[r]] for r in ('base','tools')},owned_image_ids=sorted(self.ids.values()))
        self.retirement['preflight_query_indexes'] = [self.query(self.retirement,['image','ls','--no-trunc','-q','--filter',selector],raw)
            for selector,raw in [('reference='+self.aliases[r],self.ids[r].encode()) for r in ('base','tools')] +
                                [('label='+LABEL+'='+BINDING['token'],' '.join(sorted(self.ids.values())).encode())]]
        inspection = dict(Id=self.consumer,Name='/developer-'+BINDING['token'],Image=self.ids['tools'],
                          Config=dict(Labels={LABEL:BINDING['token'],LABEL+'.source':BINDING['source']}),State=dict(Running=False))
        inspect_actor = self.actor('retirement',DOCKER+['inspect',self.consumer],encoded([inspection]))
        remove_actor = self.actor('retirement',DOCKER+['rm',self.consumer],self.consumer.encode())
        containers = [dict(container=self.consumer,before=inspection,name=inspection['Name'],creation=dict(kind='developer-id',proof=self.consumer),
                           inspect_actor=inspect_actor,remove_actor=remove_actor)]
        for role in ('tools','base'):
            observed = self.proof(self.retirement,role)
            observed['removal_query_index'] = self.query(self.retirement,['image','rm',self.aliases[role]],self.aliases[role].encode())
            self.retirement['removals'].append(observed)
        self.retirement['final_query_indexes'] = {role:self.query(self.retirement,['image','ls','--no-trunc','-q','--filter','reference='+self.aliases[role]],b'') for role in ('base','tools')}
        self.retirement['final_query_indexes']['owned_image_ids'] = self.query(self.retirement,['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+BINDING['token']],b'')
        absence = {key:dict(output='',actor=self.actor('retirement',DOCKER+args,b'')) for key,args in
                   [('containers',['ps','-aq','--no-trunc','--filter','label='+LABEL+'='+BINDING['token']]),
                    ('images',['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+BINDING['token']])]}
        self.receipt = dict(image_ledger=self.ledger,actors=self.actors['owner'],bootstrap=dict(image=self.ids['base']),
                            consumer=dict(container=self.consumer,image=self.ids['tools']))
        self.cleanup = dict(image_retirement=self.retirement,actors=self.actors['retirement'],
                            build_operations=[dict(role=role,terminal=True,actor=self.builds[role]) for role in ('base','tools')],
                            container_retirement=containers,daemon_absence=absence)
        self.put('bootstrap-proof/overlay-Dockerfile',('FROM '+self.aliases['base']+'\n').encode())
        self.refresh()

    def put(self,name,raw):
        self.values[name] = raw; self.files[name] = dict(kind='file',**pin(raw))

    def refresh(self):
        self.put('image-ledger.json',encoded(self.ledger));self.put('image-retirement.json',encoded(self.retirement))

    def read(self,name): return self.values[name]
    def load(self,name): return json.loads(self.read(name))

    def actor(self,scope,argv,raw,log=None):
        number = len(self.actors[scope]); name = 'actor-logs/'+scope+'-%03d.log'%number
        row = dict(argv=argv,log=log or '/MODELED/'+scope+'/%03d.log'%number,status='PASS',exit=0,natural_exit=True,
                   group_absent=True,exit_observed_via_waitpid=True,leader_held_until_group_inspection=True,
                   ownership_lost=False,forced_cleanup=False,retirement='REAPED',public_log=name,log_pin=pin(raw))
        self.actors[scope].append(row);self.put(name,raw)
        return row

    def query(self,context,args,raw):
        scope = context['actor_scope']; row = self.actor(scope,DOCKER+args,raw)
        check = dict(actor_scope=scope,argv=row['argv'],status='PASS',code='EXACT_RETIRED_ACTOR_STDOUT',
                     actor_index=len(self.actors[scope])-1,log=row['log'],stdout_bytes=len(raw),stdout_sha256=pin(raw)['sha256'])
        context['query_checks'].append(check)
        return len(context['query_checks'])-1

    def proof(self,context,role):
        alias,ident = self.aliases[role],self.ids[role]
        image = dict(Id=ident,Architecture='arm64',Os='linux',RepoTags=[alias],Config=dict(Labels={LABEL:BINDING['token'],LABEL+'.source':BINDING['source']}))
        indexes = [self.query(context,['image','ls','--no-trunc','-q','--filter','reference='+alias],ident.encode()),
                   self.query(context,['image','inspect',alias],encoded([image])),
                   self.query(context,['image','inspect',ident],encoded([image]))]
        return dict(query_indexes=indexes,alias=alias,image_id=ident,repo_tags=[alias],token=BINDING['token'],source=BINDING['source'])

    def build(self,role):
        alias = self.aliases[role];directory = 'bootstrap' if role=='base' else 'overlay'
        prefix = (DOCKER+['build','--no-cache','--tag',alias,'--label',LABEL+'='+BINDING['token'],'--label',LABEL+'.source='+BINDING['source'],
                          '--network=none','--pull=false','--platform=linux/arm64'] if role=='base' else
                  DOCKER+['build','--quiet','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--tag',alias,
                          '--label',LABEL+'='+BINDING['token'],'--label',LABEL+'.source='+BINDING['source']])
        argv = prefix+['--iidfile','/MODELED/'+directory+'/image-id','/MODELED/'+directory+'/context']
        row = self.actor('owner',argv,self.ids[role].encode(),log='/MODELED/bootstrap/bootstrap.log' if role=='base' else None)
        self.builds[role] = row
        keys = ('argv','log','status','exit','natural_exit','group_absent','exit_observed_via_waitpid','leader_held_until_group_inspection',
                'ownership_lost','forced_cleanup','retirement')
        value = dict(alias=alias,image_id=self.ids[role],build_actor_index=len(self.actors['owner'])-1,build={k:row[k] for k in keys})
        self.ledger['created'][role] = value
        if role=='base': value['registration'] = self.proof(self.ledger,role)


class ImageLifecycleDataTests(unittest.TestCase):
    def test_complete_source36_base16_tools17_lifecycle_passes(self):
        model = Model()
        self.assertEqual([len(model.builds[r]['argv']) for r in ('base','tools')],[16,17])
        reader_function()(model,model.files,model.receipt,model.cleanup,BINDING,MAP)

    def test_stale_tools16_and_unexpected_base17_are_refused(self):
        for role in ('base','tools'):
            model = Model();argv = model.builds[role]['argv']
            if role=='tools': argv.remove('--quiet')
            else: argv.insert(3,'--quiet')
            model.refresh()
            with self.assertRaisesRegex(ValueError,'image build argv'):
                reader_function()(model,model.files,model.receipt,model.cleanup,BINDING,MAP)

    def test_correct_length_wrong_quiet_position_or_option_is_refused(self):
        for value in ('--progress=plain','--security-opt=seccomp=unconfined'):
            model = Model();model.builds['tools']['argv'][3] = value;model.refresh()
            with self.assertRaisesRegex(ValueError,'image build command'):
                reader_function()(model,model.files,model.receipt,model.cleanup,BINDING,MAP)

    def test_missing_actual_log_or_retirement_cannot_pass(self):
        model = Model();model.values[model.builds['tools']['public_log']] += b'tampered'
        with self.assertRaisesRegex(ValueError,'retained actor log'):
            reader_function()(model,model.files,model.receipt,model.cleanup,BINDING,MAP)
        model = Model();model.cleanup['daemon_absence']['images']['actor']['group_absent'] = False
        with self.assertRaisesRegex(ValueError,'naturally retired actor'):
            reader_function()(model,model.files,model.receipt,model.cleanup,BINDING,MAP)


if __name__ == '__main__': unittest.main()
